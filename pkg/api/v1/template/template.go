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

package template

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
	"net"
	"time"
)

var (
	createServerMetric = metrics.NewStatusMetric("v1_template_server_create", "The total number of server template create requests")
	createClientMetric = metrics.NewStatusMetric("v1_template_client_create", "The total number of client template create requests")
)

type Template struct {
	logger  *zerolog.Logger
	app     *fiber.App
	options *options.Options
}

func New(options *options.Options, logger *zerolog.Logger) *Template {
	l := logger.With().Str("COMPONENT", "TEMPLATE").Logger()
	i := &Template{
		logger:  &l,
		app:     utils.DefaultFiberApp(),
		options: options,
	}

	i.init()

	return i
}

func (a *Template) init() {
	a.logger.Debug().Msg("initializing")

	a.app.Use(a.options.Auth().RootKeyValidate)
	a.app.Post("/server", createServerMetric.Middleware(), a.CreateServer)
	a.app.Post("/client", createClientMetric.Middleware(), a.CreateClient)
}

// CreateServer godoc
// @Description  Create a new Server Template
// @Tags         template
// @Accept       json
// @Produce      json
// @Param        request  body models.CreateServerTemplateRequest  true  "Create Server Template Request"
// @Success      200  {object} models.ServerTemplateResponse
// @Failure      400  {string} string
// @Failure      401  {string} string
// @Failure      404  {string} string
// @Failure      409  {string} string
// @Failure      412  {string} string
// @Failure      500  {string} string
// @Router       /template/server [post]
func (a *Template) CreateServer(ctx *fiber.Ctx) error {
	a.logger.Debug().Msgf("received CreateServer request from %s", ctx.IP())

	rk, err := authorization.GetRootKey(ctx)
	if err != nil {
		a.logger.Error().Err(err).Msg("failed to get root key from context")
		return fiber.NewError(fiber.StatusInternalServerError, "failed to get root key from request context")
	}

	body := new(models.CreateServerTemplateRequest)
	err = ctx.BodyParser(body)
	if err != nil {
		a.logger.Error().Err(err).Msg("failed to parse body")
		return fiber.NewError(fiber.StatusBadRequest, "failed to parse body")
	}

	if body.Identifier == "" {
		return fiber.NewError(fiber.StatusBadRequest, "identifier is required")
	}

	if !utils.ValidString(body.Identifier) {
		return fiber.NewError(fiber.StatusBadRequest, "invalid identifier")
	}

	if body.Authority == "" {
		return fiber.NewError(fiber.StatusBadRequest, "authority is required")
	}

	if !utils.ValidString(body.Authority) {
		return fiber.NewError(fiber.StatusBadRequest, "invalid authority")
	}

	if body.CommonName == "" {
		return fiber.NewError(fiber.StatusBadRequest, "common name is required")
	}

	if !utils.ValidString(body.CommonName) {
		return fiber.NewError(fiber.StatusBadRequest, "invalid common name")
	}

	if body.Tag == "" {
		return fiber.NewError(fiber.StatusBadRequest, "tag is required")
	}

	if !utils.ValidString(body.Tag) {
		return fiber.NewError(fiber.StatusBadRequest, "invalid tag")
	}

	for _, dnsName := range body.DNSNames {
		if !utils.ValidDNS(dnsName) {
			return fiber.NewError(fiber.StatusBadRequest, "invalid dns name")
		}
	}

	for _, ip := range body.IPAddresses {
		if net.ParseIP(ip) == nil {
			return fiber.NewError(fiber.StatusBadRequest, "invalid ip address")
		}
	}

	if body.Validity == "" {
		return fiber.NewError(fiber.StatusBadRequest, "validity is required")
	}

	validity, err := time.ParseDuration(body.Validity)
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid validity")
	}

	a.logger.Info().Msgf("creating server template '%s' with authority '%s', common name '%s', DNS names '%v', and a validity of %s for root key with ID %s", body.Identifier, body.Authority, body.CommonName, body.DNSNames, validity.String(), rk.Identifier)

	templ, err := a.options.Database().CreateServerTemplate(ctx.Context(), body.Identifier, body.Authority, body.CommonName, body.Tag, body.DNSNames, body.AllowAdditionalDNSNames, body.IPAddresses, body.AllowAdditionalIPs, body.Validity)
	if err != nil {
		if errors.Is(err, database.ErrAlreadyExists) {
			return fiber.NewError(fiber.StatusConflict, "server template already exists")
		}

		a.logger.Error().Err(err).Msg("failed to create server template")
		return fiber.NewError(fiber.StatusInternalServerError, "failed to create server template")
	}

	return ctx.JSON(&models.ServerTemplateResponse{
		Identifier:              templ.Identifier,
		Authority:               body.Authority,
		CommonName:              templ.CommonName,
		Tag:                     templ.Tag,
		DNSNames:                templ.DNSNames,
		AllowAdditionalDNSNames: templ.AllowAdditionalDNSNames,
		IPAddresses:             templ.IPAddresses,
		AllowAdditionalIPs:      templ.AllowAdditionalIps,
		Validity:                validity.String(),
	})
}

// CreateClient godoc
// @Description  Create a new Client Template
// @Tags         template
// @Accept       json
// @Produce      json
// @Param        request  body models.CreateClientTemplateRequest  true  "Create Client Template Request"
// @Success      200  {object} models.ClientTemplateResponse
// @Failure      400  {string} string
// @Failure      401  {string} string
// @Failure      404  {string} string
// @Failure      409  {string} string
// @Failure      412  {string} string
// @Failure      500  {string} string
// @Router       /template/client [post]
func (a *Template) CreateClient(ctx *fiber.Ctx) error {
	a.logger.Debug().Msgf("received CreateClient request from %s", ctx.IP())

	rk, err := authorization.GetRootKey(ctx)
	if err != nil {
		a.logger.Error().Err(err).Msg("failed to get root key from context")
		return fiber.NewError(fiber.StatusInternalServerError, "failed to get root key from request context")
	}

	body := new(models.CreateClientTemplateRequest)
	err = ctx.BodyParser(body)
	if err != nil {
		a.logger.Error().Err(err).Msg("failed to parse body")
		return fiber.NewError(fiber.StatusBadRequest, "failed to parse body")
	}

	if body.Identifier == "" {
		return fiber.NewError(fiber.StatusBadRequest, "identifier is required")
	}

	if !utils.ValidString(body.Identifier) {
		return fiber.NewError(fiber.StatusBadRequest, "invalid identifier")
	}

	if body.Authority == "" {
		return fiber.NewError(fiber.StatusBadRequest, "authority is required")
	}

	if !utils.ValidString(body.Authority) {
		return fiber.NewError(fiber.StatusBadRequest, "invalid authority")
	}

	if body.CommonName == "" {
		return fiber.NewError(fiber.StatusBadRequest, "common name is required")
	}

	if !utils.ValidString(body.CommonName) {
		return fiber.NewError(fiber.StatusBadRequest, "invalid common name")
	}

	if body.Tag == "" {
		return fiber.NewError(fiber.StatusBadRequest, "tag is required")
	}

	if !utils.ValidString(body.Tag) {
		return fiber.NewError(fiber.StatusBadRequest, "invalid tag")
	}

	for _, dnsName := range body.DNSNames {
		if !utils.ValidDNS(dnsName) {
			return fiber.NewError(fiber.StatusBadRequest, "invalid dns name")
		}
	}

	for _, ip := range body.IPAddresses {
		if net.ParseIP(ip) == nil {
			return fiber.NewError(fiber.StatusBadRequest, "invalid ip address")
		}
	}

	if body.Validity == "" {
		return fiber.NewError(fiber.StatusBadRequest, "validity is required")
	}

	validity, err := time.ParseDuration(body.Validity)
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid validity")
	}

	a.logger.Info().Msgf("creating client template '%s' with authority '%s', common name '%s', DNS names '%v', and a validity of %s for root key with ID %s", body.Identifier, body.Authority, body.CommonName, body.DNSNames, validity.String(), rk.Identifier)

	templ, err := a.options.Database().CreateClientTemplate(ctx.Context(), body.Identifier, body.Authority, body.CommonName, body.Tag, body.DNSNames, body.AllowAdditionalDNSNames, body.IPAddresses, body.AllowAdditionalIPs, body.Validity)
	if err != nil {
		if errors.Is(err, database.ErrAlreadyExists) {
			return fiber.NewError(fiber.StatusConflict, "client template already exists")
		}

		a.logger.Error().Err(err).Msg("failed to create client template")
		return fiber.NewError(fiber.StatusInternalServerError, "failed to create client template")
	}

	return ctx.JSON(&models.ClientTemplateResponse{
		Identifier:              templ.Identifier,
		Authority:               body.Authority,
		CommonName:              templ.CommonName,
		Tag:                     templ.Tag,
		DNSNames:                templ.DNSNames,
		AllowAdditionalDNSNames: templ.AllowAdditionalDNSNames,
		IPAddresses:             templ.IPAddresses,
		AllowAdditionalIPs:      templ.AllowAdditionalIps,
		Validity:                validity.String(),
	})
}

func (a *Template) App() *fiber.App {
	return a.app
}
