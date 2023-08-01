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
	"github.com/gofiber/fiber/v2"
	"github.com/loopholelabs/endkey/internal/database"
	"github.com/loopholelabs/endkey/internal/metrics"
	"github.com/loopholelabs/endkey/internal/utils"
	"github.com/loopholelabs/endkey/pkg/api/authorization"
	"github.com/loopholelabs/endkey/pkg/api/v1/models"
	"github.com/loopholelabs/endkey/pkg/api/v1/options"
	"github.com/rs/zerolog"
)

var (
	createMetric = metrics.NewStatusMetric("v1_apikey_create", "The total number of api key create requests")
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

	a.app.Use(a.options.Auth().RootKeyValidate)
	a.app.Post("/", createMetric.Middleware(), a.CreateAPIKey)
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

	rk, err := authorization.GetRootKey(ctx)
	if err != nil {
		a.logger.Error().Err(err).Msg("failed to get root key from context")
		return fiber.NewError(fiber.StatusInternalServerError, "failed to get root key from request context")
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

	if body.Authority == "" {
		return fiber.NewError(fiber.StatusBadRequest, "authority is required")
	}

	if !utils.ValidString(body.Authority) {
		return fiber.NewError(fiber.StatusBadRequest, "authority is invalid")
	}

	if body.ServerTemplate != "" && !utils.ValidString(body.ServerTemplate) {
		return fiber.NewError(fiber.StatusBadRequest, "server template is invalid")
	}

	if body.ClientTemplate != "" && !utils.ValidString(body.ClientTemplate) {
		return fiber.NewError(fiber.StatusBadRequest, "client template is invalid")
	}

	a.logger.Info().Msgf("creating API Key '%s' for Authority '%s' (with Server Template '%s' and Client Template '%') for root key with ID %s", body.Name, body.Authority, body.ServerTemplate, body.ClientTemplate, rk.Identifier)

	ak, secret, err := a.options.Database().CreateAPIKey(ctx.Context(), body.Name, body.Authority, body.ServerTemplate, body.ClientTemplate)
	if err != nil {
		if errors.Is(err, database.ErrAlreadyExists) {
			return fiber.NewError(fiber.StatusConflict, "api key already exists for this authority")
		}

		a.logger.Error().Err(err).Msg("failed to create api key")
		return fiber.NewError(fiber.StatusInternalServerError, "failed to create api key")
	}

	return ctx.JSON(&models.APIKeyResponse{
		Identifier:     ak.Identifier,
		Name:           ak.Name,
		Authority:      body.Authority,
		ServerTemplate: body.ServerTemplate,
		ClientTemplate: body.ClientTemplate,
		Secret:         string(secret),
	})
}

func (a *APIKey) App() *fiber.App {
	return a.app
}
