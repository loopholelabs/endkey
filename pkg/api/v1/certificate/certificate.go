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

package certificate

import (
	"encoding/base64"
	"github.com/gofiber/fiber/v2"
	"github.com/loopholelabs/endkey/internal/metrics"
	"github.com/loopholelabs/endkey/internal/utils"
	"github.com/loopholelabs/endkey/pkg/api/authorization"
	"github.com/loopholelabs/endkey/pkg/api/v1/models"
	"github.com/loopholelabs/endkey/pkg/api/v1/options"
	"github.com/rs/zerolog"
)

var (
	createServerMetric = metrics.NewStatusMetric("v1_certificate_server_create", "The total number of certificate server create requests")
	createClientMetric = metrics.NewStatusMetric("v1_certificate_client_create", "The total number of certificate client create requests")
	getCAMetric        = metrics.NewStatusMetric("v1_certificate_ca_get", "The total number of certificate ca get requests")
)

type Certificate struct {
	logger  *zerolog.Logger
	app     *fiber.App
	options *options.Options
}

func New(options *options.Options, logger *zerolog.Logger) *Certificate {
	l := logger.With().Str("COMPONENT", "CERTIFICATE").Logger()
	i := &Certificate{
		logger:  &l,
		app:     utils.DefaultFiberApp(),
		options: options,
	}

	i.init()

	return i
}

func (a *Certificate) init() {
	a.logger.Debug().Msg("initializing")

	a.app.Use(a.options.Auth().APIKeyValidate)
	a.app.Post("/server", createServerMetric.Middleware(), a.CreateServer)
	a.app.Post("/client", createClientMetric.Middleware(), a.CreateClient)
	a.app.Get("/ca", getCAMetric.Middleware(), a.GetCA)
}

// GetCA godoc
// @Description  Retrieves the CA Certificate
// @Tags         certificate
// @Accept       json
// @Produce      json
// @Success      200  {object} models.CAResponse
// @Failure      400  {string} string
// @Failure      401  {string} string
// @Failure      404  {string} string
// @Failure      409  {string} string
// @Failure      412  {string} string
// @Failure      500  {string} string
// @Router       /certificate/ca [get]
func (a *Certificate) GetCA(ctx *fiber.Ctx) error {
	a.logger.Debug().Msgf("received GetCA request from %s", ctx.IP())

	ak, err := authorization.GetAPIKey(ctx)
	if err != nil {
		a.logger.Error().Err(err).Msg("failed to get api key from context")
		return fiber.NewError(fiber.StatusInternalServerError, "failed to get api key from request context")
	}

	auth, err := ak.Edges.AuthorityOrErr()
	if err != nil {
		a.logger.Error().Err(err).Msg("failed to get authority edge from api key")
		return fiber.NewError(fiber.StatusInternalServerError, "failed to get authority from api key")
	}

	return ctx.JSON(&models.CAResponse{
		AuthorityName: auth.Name,
		CACertificate: base64.StdEncoding.EncodeToString(auth.CaCertificatePem),
	})
}

func (a *Certificate) App() *fiber.App {
	return a.app
}
