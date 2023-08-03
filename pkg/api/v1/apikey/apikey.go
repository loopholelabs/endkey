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

package apikey

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
	createMetric = metrics.NewStatusMetric("v1_apikey_create", "The total number of api key create requests")
	listMetric   = metrics.NewStatusMetric("v1_apikey_list", "The total number of api key list requests")
	deleteMetric = metrics.NewStatusMetric("v1_apikey_delete", "The total number of api key delete requests")
)

type APIKey struct {
	logger  *zerolog.Logger
	app     *fiber.App
	options *options.Options
}

func New(options *options.Options, logger *zerolog.Logger) *APIKey {
	l := logger.With().Str("COMPONENT", "APIKEY").Logger()
	i := &APIKey{
		logger:  &l,
		app:     utils.DefaultFiberApp(),
		options: options,
	}

	i.init()

	return i
}

func (a *APIKey) init() {
	a.logger.Debug().Msg("initializing")

	a.app.Use(a.options.Auth().UserKeyValidate)
	a.app.Post("/", createMetric.Middleware(), a.CreateAPIKey)
	a.app.Get("/:authority_name", listMetric.Middleware(), a.ListAPIKeys)
	a.app.Delete("/", deleteMetric.Middleware(), a.DeleteAPIKey)
}

// CreateAPIKey godoc
// @Description  Create a new API Key for a given Authority
// @Tags         apikey
// @Accept       json
// @Produce      json
// @Param        request  body models.CreateAPIKeyRequest  true  "Create API Key Request"
// @Success      200  {object} models.APIKeyResponse
// @Failure      400  {string} string
// @Failure      401  {string} string
// @Failure      404  {string} string
// @Failure      409  {string} string
// @Failure      412  {string} string
// @Failure      500  {string} string
// @Router       /apikey [post]
func (a *APIKey) CreateAPIKey(ctx *fiber.Ctx) error {
	a.logger.Debug().Msgf("received CreateAPIKey request from %s", ctx.IP())

	uk, err := authorization.GetUserKey(ctx)
	if err != nil {
		a.logger.Error().Err(err).Msg("failed to get user key from context")
		return fiber.NewError(fiber.StatusInternalServerError, "failed to get user key from request context")
	}

	body := new(models.CreateAPIKeyRequest)
	err = ctx.BodyParser(body)
	if err != nil {
		a.logger.Error().Err(err).Msg("failed to parse body")
		return fiber.NewError(fiber.StatusBadRequest, "failed to parse body")
	}

	if body.Name == "" {
		return fiber.NewError(fiber.StatusBadRequest, "name is required")
	}

	if !utils.ValidString(body.Name) {
		return fiber.NewError(fiber.StatusBadRequest, "name is invalid")
	}

	if body.AuthorityName == "" {
		return fiber.NewError(fiber.StatusBadRequest, "authority name is required")
	}

	if !utils.ValidString(body.AuthorityName) {
		return fiber.NewError(fiber.StatusBadRequest, "authority name is invalid")
	}

	if body.ServerTemplateName != "" && !utils.ValidString(body.ServerTemplateName) {
		return fiber.NewError(fiber.StatusBadRequest, "server template name is invalid")
	}

	if body.ClientTemplateName != "" && !utils.ValidString(body.ClientTemplateName) {
		return fiber.NewError(fiber.StatusBadRequest, "client template is name invalid")
	}

	if body.ServerTemplateName == "" && body.ClientTemplateName == "" {
		return fiber.NewError(fiber.StatusBadRequest, "server template name or client template name is required")
	}

	a.logger.Info().Msgf("creating api key '%s' for authority '%s' (with server template '%s' and client template '%s') for user key %s", body.Name, body.AuthorityName, body.ServerTemplateName, body.ClientTemplateName, uk.Name)

	ak, secret, err := a.options.Database().CreateAPIKey(ctx.Context(), body.Name, body.AuthorityName, uk, body.ServerTemplateName, body.ClientTemplateName)
	if err != nil {
		if errors.Is(err, database.ErrAlreadyExists) {
			return fiber.NewError(fiber.StatusConflict, "api key already exists for this authority")
		}

		a.logger.Error().Err(err).Msg("failed to create api key")
		return fiber.NewError(fiber.StatusInternalServerError, "failed to create api key")
	}

	return ctx.JSON(&models.APIKeyResponse{
		ID:                 ak.ID,
		Name:               ak.Name,
		AuthorityName:      body.AuthorityName,
		ServerTemplateName: body.ServerTemplateName,
		ClientTemplateName: body.ClientTemplateName,
		Secret:             string(secret),
	})
}

// ListAPIKeys godoc
// @Description  Lists all the api keys
// @Tags         apikey
// @Accept       json
// @Produce      json
// @Param 	     authority_name  path  string  true  "Authority Name"
// @Success      200  {array} models.APIKeyResponse
// @Failure      400  {string} string
// @Failure      401  {string} string
// @Failure      404  {string} string
// @Failure      409  {string} string
// @Failure      412  {string} string
// @Failure      500  {string} string
// @Router       /apikey/{authority_name} [get]
func (a *APIKey) ListAPIKeys(ctx *fiber.Ctx) error {
	a.logger.Debug().Msgf("received ListAPIKeys request from %s", ctx.IP())

	uk, err := authorization.GetUserKey(ctx)
	if err != nil {
		a.logger.Error().Err(err).Msg("failed to get user key from context")
		return fiber.NewError(fiber.StatusInternalServerError, "failed to get user key from request context")
	}

	authorityName := ctx.Params("authority_name")

	if authorityName == "" {
		return fiber.NewError(fiber.StatusBadRequest, "authority name is required")
	}

	if !utils.ValidString(authorityName) {
		return fiber.NewError(fiber.StatusBadRequest, "authority name is invalid")
	}

	a.logger.Info().Msgf("listing api keys for authority '%s' for user key %s", authorityName, uk.Name)

	aks, err := a.options.Database().ListAPIKeys(ctx.Context(), authorityName, uk)
	if err != nil {
		if errors.Is(err, database.ErrNotFound) {
			return fiber.NewError(fiber.StatusNotFound, "no api keys found")
		}

		a.logger.Error().Err(err).Msg("failed to list api keys")
		return fiber.NewError(fiber.StatusInternalServerError, "failed to list api keys")
	}

	ret := make([]*models.APIKeyResponse, 0, len(aks))
	for _, ak := range aks {
		r := &models.APIKeyResponse{
			CreatedAt:     ak.CreatedAt.Format(time.RFC3339),
			ID:            ak.ID,
			Name:          ak.Name,
			AuthorityName: authorityName,
		}
		serverTempl, err := ak.Edges.ServerTemplateOrErr()
		if err == nil {
			r.ServerTemplateName = serverTempl.Name
		}

		clientTempl, err := ak.Edges.ClientTemplateOrErr()
		if err == nil {
			r.ClientTemplateName = clientTempl.Name
		}

		ret = append(ret, r)
	}

	return ctx.JSON(ret)
}

// DeleteAPIKey godoc
// @Description  Delete an API Key
// @Tags         apikey
// @Accept       json
// @Produce      json
// @Param        request  body models.DeleteAPIKeyRequest  true  "Delete API Key Request"
// @Success      200  {string} string
// @Failure      400  {string} string
// @Failure      401  {string} string
// @Failure      404  {string} string
// @Failure      409  {string} string
// @Failure      412  {string} string
// @Failure      500  {string} string
// @Router       /apikey [delete]
func (a *APIKey) DeleteAPIKey(ctx *fiber.Ctx) error {
	a.logger.Debug().Msgf("received DeleteAPIKey request from %s", ctx.IP())

	uk, err := authorization.GetUserKey(ctx)
	if err != nil {
		a.logger.Error().Err(err).Msg("failed to get user key from context")
		return fiber.NewError(fiber.StatusInternalServerError, "failed to get user key from request context")
	}

	body := new(models.DeleteAPIKeyRequest)
	err = ctx.BodyParser(body)
	if err != nil {
		a.logger.Error().Err(err).Msg("failed to parse body")
		return fiber.NewError(fiber.StatusBadRequest, "failed to parse body")
	}

	if body.Name == "" {
		return fiber.NewError(fiber.StatusBadRequest, "name is required")
	}

	if !utils.ValidString(body.Name) || body.Name == "bootstrap" {
		return fiber.NewError(fiber.StatusBadRequest, "name is invalid")
	}

	if body.AuthorityName == "" {
		return fiber.NewError(fiber.StatusBadRequest, "authority name is required")
	}

	if !utils.ValidString(body.AuthorityName) {
		return fiber.NewError(fiber.StatusBadRequest, "authority name is invalid")
	}

	a.logger.Info().Msgf("deleting api key '%s' for authority '%s' for user key %s", body.Name, body.AuthorityName, uk.Name)

	err = a.options.Database().DeleteAPIKeyByName(ctx.Context(), body.Name, body.AuthorityName, uk)
	if err != nil {
		if errors.Is(err, database.ErrNotFound) {
			return fiber.NewError(fiber.StatusNotFound, "api key not found")
		}

		if errors.Is(err, database.ErrAlreadyExists) {
			return fiber.NewError(fiber.StatusConflict, "cannot delete api key because resources are still associated with it")
		}

		a.logger.Error().Err(err).Msg("failed to delete api key")
		return fiber.NewError(fiber.StatusInternalServerError, "failed to delete api key")
	}

	return ctx.SendString(fmt.Sprintf("api key '%s' for authority '%s' deleted", body.Name, body.AuthorityName))
}

func (a *APIKey) App() *fiber.App {
	return a.app
}
