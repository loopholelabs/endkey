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

package rootkey

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
	createMetric = metrics.NewStatusMetric("v1_rootkey_create", "The total number of root key create requests")
	rotateMetric = metrics.NewStatusMetric("v1_rootkey_rotate", "The total number of root key rotate requests")
	listMetric   = metrics.NewStatusMetric("v1_rootkey_list", "The total number of root key list requests")
	deleteMetric = metrics.NewStatusMetric("v1_rootkey_delete", "The total number of root key delete requests")
)

type RootKey struct {
	logger  *zerolog.Logger
	app     *fiber.App
	options *options.Options
}

func New(options *options.Options, logger *zerolog.Logger) *RootKey {
	l := logger.With().Str("COMPONENT", "ROOTKEY").Logger()
	i := &RootKey{
		logger:  &l,
		app:     utils.DefaultFiberApp(),
		options: options,
	}

	i.init()

	return i
}

func (a *RootKey) init() {
	a.logger.Debug().Msg("initializing")

	a.app.Use(a.options.Auth().RootKeyValidate)
	a.app.Post("/:name", createMetric.Middleware(), a.CreateRootKey)
	a.app.Post("/rotate/:name", rotateMetric.Middleware(), a.RotateRootKey)
	a.app.Get("/", listMetric.Middleware(), a.ListRootKeys)
	a.app.Delete("/:name", deleteMetric.Middleware(), a.DeleteRootKey)

}

// CreateRootKey godoc
// @Description  Create a new Root Key
// @Tags         rootkey
// @Accept       json
// @Produce      json
// @Param 	     name  path  string  true  "Root Key Name"
// @Success      200  {object} models.RootKeyResponse
// @Failure      400  {string} string
// @Failure      401  {string} string
// @Failure      404  {string} string
// @Failure      409  {string} string
// @Failure      412  {string} string
// @Failure      500  {string} string
// @Router       /rootkey/{name} [post]
func (a *RootKey) CreateRootKey(ctx *fiber.Ctx) error {
	a.logger.Debug().Msgf("received CreateRootKey request from %s", ctx.IP())

	rk, err := authorization.GetRootKey(ctx)
	if err != nil {
		a.logger.Error().Err(err).Msg("failed to get root key from context")
		return fiber.NewError(fiber.StatusInternalServerError, "failed to get root key from request context")
	}

	name := ctx.Params("name")

	if name == "" {
		return fiber.NewError(fiber.StatusBadRequest, "name is required")
	}

	if !utils.ValidString(name) || name == "bootstrap" {
		return fiber.NewError(fiber.StatusBadRequest, "name is invalid")
	}

	a.logger.Info().Msgf("creating root key '%s' for root key with ID %s", name, rk.Identifier)

	rk, secret, err := a.options.Database().CreateRootKey(ctx.Context(), name)
	if err != nil {
		if errors.Is(err, database.ErrAlreadyExists) {
			return fiber.NewError(fiber.StatusConflict, "root key already exists")
		}

		a.logger.Error().Err(err).Msg("failed to create root key")
		return fiber.NewError(fiber.StatusInternalServerError, "failed to create root key")
	}

	return ctx.JSON(&models.RootKeyResponse{
		CreatedAt:  rk.CreatedAt.Format(time.RFC3339),
		Identifier: rk.Identifier,
		Name:       rk.Name,
		Secret:     string(secret),
	})
}

// RotateRootKey godoc
// @Description  Rotates a given Root Key
// @Tags         rootkey
// @Accept       json
// @Produce      json
// @Param 	     name  path  string  true  "Root Key Name"
// @Success      200  {object} models.RootKeyResponse
// @Failure      400  {string} string
// @Failure      401  {string} string
// @Failure      404  {string} string
// @Failure      409  {string} string
// @Failure      412  {string} string
// @Failure      500  {string} string
// @Router       /rootkey/rotate/{name} [post]
func (a *RootKey) RotateRootKey(ctx *fiber.Ctx) error {
	a.logger.Debug().Msgf("received RotateRootKey request from %s", ctx.IP())

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

	a.logger.Info().Msgf("rotating root key '%s' for root key with ID %s", name, rk.Identifier)

	rk, secret, err := a.options.Database().RotateRootKey(ctx.Context(), name)
	if err != nil {
		if errors.Is(err, database.ErrAlreadyExists) {
			return fiber.NewError(fiber.StatusConflict, "root key already exists")
		}

		a.logger.Error().Err(err).Msg("failed to rotate root key")
		return fiber.NewError(fiber.StatusInternalServerError, "failed to rotate root key")
	}

	return ctx.JSON(&models.RootKeyResponse{
		CreatedAt:  rk.CreatedAt.Format(time.RFC3339),
		Identifier: rk.Identifier,
		Name:       rk.Name,
		Secret:     string(secret),
	})
}

// ListRootKeys godoc
// @Description  Lists all the root keys
// @Tags         rootkey
// @Accept       json
// @Produce      json
// @Success      200  {array} models.RootKeyResponse
// @Failure      400  {string} string
// @Failure      401  {string} string
// @Failure      404  {string} string
// @Failure      409  {string} string
// @Failure      412  {string} string
// @Failure      500  {string} string
// @Router       /rootkey [get]
func (a *RootKey) ListRootKeys(ctx *fiber.Ctx) error {
	a.logger.Debug().Msgf("received ListRootKeys request from %s", ctx.IP())

	rk, err := authorization.GetRootKey(ctx)
	if err != nil {
		a.logger.Error().Err(err).Msg("failed to get root key from context")
		return fiber.NewError(fiber.StatusInternalServerError, "failed to get root key from request context")
	}

	a.logger.Info().Msgf("listing root keys for root key with ID %s", rk.Identifier)

	rks, err := a.options.Database().ListRootKeys(ctx.Context())
	if err != nil {
		if errors.Is(err, database.ErrNotFound) {
			return fiber.NewError(fiber.StatusNotFound, "no root keys found")
		}

		a.logger.Error().Err(err).Msg("failed to list root keys")
		return fiber.NewError(fiber.StatusInternalServerError, "failed to list root keys")
	}

	ret := make([]*models.RootKeyResponse, 0, len(rks))
	for _, rk := range rks {
		ret = append(ret, &models.RootKeyResponse{
			CreatedAt:  rk.CreatedAt.Format(time.RFC3339),
			Identifier: rk.Identifier,
			Name:       rk.Name,
		})
	}

	return ctx.JSON(ret)
}

// DeleteRootKey godoc
// @Description  Delete a Root Key
// @Tags         rootkey
// @Accept       json
// @Produce      json
// @Param 	     name  path  string  true  "Root Key Name"
// @Success      200  {string} string
// @Failure      400  {string} string
// @Failure      401  {string} string
// @Failure      404  {string} string
// @Failure      409  {string} string
// @Failure      412  {string} string
// @Failure      500  {string} string
// @Router       /rootkey/{name} [delete]
func (a *RootKey) DeleteRootKey(ctx *fiber.Ctx) error {
	a.logger.Debug().Msgf("received DeleteRootKey request from %s", ctx.IP())

	rk, err := authorization.GetRootKey(ctx)
	if err != nil {
		a.logger.Error().Err(err).Msg("failed to get root key from context")
		return fiber.NewError(fiber.StatusInternalServerError, "failed to get root key from request context")
	}

	name := ctx.Params("name")

	if name == "" {
		return fiber.NewError(fiber.StatusBadRequest, "name is required")
	}

	if !utils.ValidString(name) || name == "bootstrap" {
		return fiber.NewError(fiber.StatusBadRequest, "name is invalid")
	}

	a.logger.Info().Msgf("deleting root key '%s' for root key with ID %s", name, rk.Identifier)

	err = a.options.Database().DeleteRootKey(ctx.Context(), name)
	if err != nil {
		if errors.Is(err, database.ErrNotFound) {
			return fiber.NewError(fiber.StatusNotFound, "root key not found")
		}

		if errors.Is(err, database.ErrAlreadyExists) {
			return fiber.NewError(fiber.StatusConflict, "cannot delete root key because resources are still associated with it")
		}

		a.logger.Error().Err(err).Msg("failed to delete root key")
		return fiber.NewError(fiber.StatusInternalServerError, "failed to delete root key")
	}

	return ctx.SendString(fmt.Sprintf("root key '%s' deleted", name))
}

func (a *RootKey) App() *fiber.App {
	return a.app
}
