/*
	Copyright 2023 Loophole Labs

	Licensed under the Apache License, Version 2.0 (the "License");
	you may not use this file except in compliance with the License.
	You may obtain a copy of the License at

		   http://www.apache.org/licenses/LICENSE-2.0

	Unless required by applicable law or agreed to in writing, software
	distributed under the License is distributed on an "AS IS" BASIS,
	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
	See the License for the specific language governing permissions and
	limitations under the License.
*/

package userkey

import (
	"errors"
	"fmt"
	"github.com/gofiber/fiber/v2"
	"github.com/loopholelabs/endkey/internal/database"
	"github.com/loopholelabs/endkey/internal/metrics"
	"github.com/loopholelabs/endkey/internal/utils"
	"github.com/loopholelabs/endkey/pkg/api/authorization"
	"github.com/loopholelabs/endkey/pkg/api/v1/models"
	"github.com/loopholelabs/endkey/pkg/api/v1/options"
	"github.com/rs/zerolog"
	"time"
)

var (
	createMetric = metrics.NewStatusMetric("v1_userkey_create", "The total number of user key create requests")
	rotateMetric = metrics.NewStatusMetric("v1_userkey_rotate", "The total number of user key rotate requests")
	listMetric   = metrics.NewStatusMetric("v1_userkey_list", "The total number of user key list requests")
	deleteMetric = metrics.NewStatusMetric("v1_userkey_delete", "The total number of user key delete requests")
)

type UserKey struct {
	logger  *zerolog.Logger
	app     *fiber.App
	options *options.Options
}

func New(options *options.Options, logger *zerolog.Logger) *UserKey {
	l := logger.With().Str("COMPONENT", "USERKEY").Logger()
	i := &UserKey{
		logger:  &l,
		app:     utils.DefaultFiberApp(),
		options: options,
	}

	i.init()

	return i
}

func (a *UserKey) init() {
	a.logger.Debug().Msg("initializing")

	a.app.Use(a.options.Auth().RootKeyValidate)
	a.app.Post("/:name", createMetric.Middleware(), a.CreateUserKey)
	a.app.Post("/rotate/:name", rotateMetric.Middleware(), a.RotateUserKey)
	a.app.Get("/", listMetric.Middleware(), a.ListUserKeys)
	a.app.Delete("/:name", deleteMetric.Middleware(), a.DeleteUserKey)
}

// CreateUserKey godoc
// @Description  Create a new User Key
// @Tags         userkey
// @Accept       json
// @Produce      json
// @Param 	     name  path  string  true  "User Key Name"
// @Success      200  {object} models.UserKeyResponse
// @Failure      400  {string} string
// @Failure      401  {string} string
// @Failure      404  {string} string
// @Failure      409  {string} string
// @Failure      412  {string} string
// @Failure      500  {string} string
// @Router       /userkey/{name} [post]
func (a *UserKey) CreateUserKey(ctx *fiber.Ctx) error {
	a.logger.Debug().Msgf("received CreateUserKey request from %s", ctx.IP())

	rk, err := authorization.GetRootKey(ctx)
	if err != nil {
		a.logger.Error().Err(err).Msg("failed to get root key from context")
		return fiber.NewError(fiber.StatusInternalServerError, "failed to get root key from request context")
	}

	name := ctx.Params("name")

	if name == "" {
		return fiber.NewError(fiber.StatusBadRequest, "name is required")
	}

	if !utils.ValidString(name) {
		return fiber.NewError(fiber.StatusBadRequest, "name is invalid")
	}

	a.logger.Info().Msgf("creating user key '%s' for root key %s", name, rk.Name)

	uk, secret, err := a.options.Database().CreateUserKey(ctx.Context(), name, rk)
	if err != nil {
		if errors.Is(err, database.ErrAlreadyExists) {
			return fiber.NewError(fiber.StatusConflict, "user key already exists")
		}

		a.logger.Error().Err(err).Msg("failed to create user key")
		return fiber.NewError(fiber.StatusInternalServerError, "failed to create user key")
	}

	return ctx.JSON(&models.UserKeyResponse{
		CreatedAt: uk.CreatedAt.Format(time.RFC3339),
		ID:        uk.ID,
		Name:      uk.Name,
		Secret:    string(secret),
	})
}

// RotateUserKey godoc
// @Description  Rotates a given User Key
// @Tags         userkey
// @Accept       json
// @Produce      json
// @Param 	     name  path  string  true  "User Key Name"
// @Success      200  {object} models.UserKeyResponse
// @Failure      400  {string} string
// @Failure      401  {string} string
// @Failure      404  {string} string
// @Failure      409  {string} string
// @Failure      412  {string} string
// @Failure      500  {string} string
// @Router       /userkey/rotate/{name} [post]
func (a *UserKey) RotateUserKey(ctx *fiber.Ctx) error {
	a.logger.Debug().Msgf("received RotateUserKey request from %s", ctx.IP())

	rk, err := authorization.GetRootKey(ctx)
	if err != nil {
		a.logger.Error().Err(err).Msg("failed to get root key from context")
		return fiber.NewError(fiber.StatusInternalServerError, "failed to get root key from request context")
	}

	name := ctx.Params("name")

	if name == "" {
		return fiber.NewError(fiber.StatusBadRequest, "name is required")
	}

	if !utils.ValidString(name) {
		return fiber.NewError(fiber.StatusBadRequest, "name is invalid")
	}

	a.logger.Info().Msgf("rotating user key '%s' for root key %s", name, rk.Name)

	uk, secret, err := a.options.Database().RotateUserKeyByName(ctx.Context(), name)
	if err != nil {
		if errors.Is(err, database.ErrAlreadyExists) {
			return fiber.NewError(fiber.StatusConflict, "user key already exists")
		}

		a.logger.Error().Err(err).Msg("failed to rotate user key")
		return fiber.NewError(fiber.StatusInternalServerError, "failed to rotate user key")
	}

	return ctx.JSON(&models.UserKeyResponse{
		CreatedAt: uk.CreatedAt.Format(time.RFC3339),
		ID:        uk.ID,
		Name:      uk.Name,
		Secret:    string(secret),
	})
}

// ListUserKeys godoc
// @Description  Lists all the User Keys
// @Tags         userkey
// @Accept       json
// @Produce      json
// @Success      200  {array} models.UserKeyResponse
// @Failure      400  {string} string
// @Failure      401  {string} string
// @Failure      404  {string} string
// @Failure      409  {string} string
// @Failure      412  {string} string
// @Failure      500  {string} string
// @Router       /userkey [get]
func (a *UserKey) ListUserKeys(ctx *fiber.Ctx) error {
	a.logger.Debug().Msgf("received ListUserKeys request from %s", ctx.IP())

	rk, err := authorization.GetRootKey(ctx)
	if err != nil {
		a.logger.Error().Err(err).Msg("failed to get root key from context")
		return fiber.NewError(fiber.StatusInternalServerError, "failed to get root key from request context")
	}

	a.logger.Info().Msgf("listing user keys for root key %s", rk.Name)

	uks, err := a.options.Database().ListUserKeys(ctx.Context())
	if err != nil {
		if errors.Is(err, database.ErrNotFound) {
			return fiber.NewError(fiber.StatusNotFound, "no user keys found")
		}

		a.logger.Error().Err(err).Msg("failed to list user keys")
		return fiber.NewError(fiber.StatusInternalServerError, "failed to list user keys")
	}

	ret := make([]*models.UserKeyResponse, 0, len(uks))
	for _, uk := range uks {
		ret = append(ret, &models.UserKeyResponse{
			CreatedAt: uk.CreatedAt.Format(time.RFC3339),
			ID:        uk.ID,
			Name:      uk.Name,
		})
	}

	return ctx.JSON(ret)
}

// DeleteUserKey godoc
// @Description  Delete a User Key
// @Tags         userkey
// @Accept       json
// @Produce      json
// @Param 	     name  path  string  true  "User Key Name"
// @Success      200  {string} string
// @Failure      400  {string} string
// @Failure      401  {string} string
// @Failure      404  {string} string
// @Failure      409  {string} string
// @Failure      412  {string} string
// @Failure      500  {string} string
// @Router       /userkey/{name} [delete]
func (a *UserKey) DeleteUserKey(ctx *fiber.Ctx) error {
	a.logger.Debug().Msgf("received DeleteUserKey request from %s", ctx.IP())

	rk, err := authorization.GetUserKey(ctx)
	if err != nil {
		a.logger.Error().Err(err).Msg("failed to get root key from context")
		return fiber.NewError(fiber.StatusInternalServerError, "failed to get root key from request context")
	}

	name := ctx.Params("name")

	if name == "" {
		return fiber.NewError(fiber.StatusBadRequest, "name is required")
	}

	if !utils.ValidString(name) {
		return fiber.NewError(fiber.StatusBadRequest, "name is invalid")
	}

	a.logger.Info().Msgf("deleting user key '%s' for root key %s", name, rk.Name)

	err = a.options.Database().DeleteUserKeyByName(ctx.Context(), name)
	if err != nil {
		if errors.Is(err, database.ErrNotFound) {
			return fiber.NewError(fiber.StatusNotFound, "user key not found")
		}

		if errors.Is(err, database.ErrAlreadyExists) {
			return fiber.NewError(fiber.StatusConflict, "cannot delete user key because resources are still associated with it")
		}

		a.logger.Error().Err(err).Msg("failed to delete user key")
		return fiber.NewError(fiber.StatusInternalServerError, "failed to delete user key")
	}

	return ctx.SendString(fmt.Sprintf("user key '%s' deleted", name))
}

func (a *UserKey) App() *fiber.App {
	return a.app
}
