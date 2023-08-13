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
	"fmt"
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
	createMetric = metrics.NewStatusMetric("v1_template_create", "The total number of template create requests")
	listMetric   = metrics.NewStatusMetric("v1_template_list", "The total number of template list requests")
	deleteMetric = metrics.NewStatusMetric("v1_template_delete", "The total number of template delete requests")
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

	a.app.Use(a.options.Auth().UserKeyValidate)

	a.app.Post("/", createMetric.Middleware(), a.Create)
	a.app.Get("/:authority_name", listMetric.Middleware(), a.List)
	a.app.Delete("/", deleteMetric.Middleware(), a.Delete)
}

// Create godoc
// @Description  Create a new Template
// @Tags         template
// @Accept       json
// @Produce      json
// @Param        request  body models.CreateTemplateRequest  true  "Create Template Request"
// @Success      200  {object} models.TemplateResponse
// @Failure      400  {string} string
// @Failure      401  {string} string
// @Failure      404  {string} string
// @Failure      409  {string} string
// @Failure      412  {string} string
// @Failure      500  {string} string
// @Router       /template [post]
func (a *Template) Create(ctx *fiber.Ctx) error {
	a.logger.Debug().Msgf("received Create request from %s", ctx.IP())

	uk, err := authorization.GetUserKey(ctx)
	if err != nil {
		a.logger.Error().Err(err).Msg("failed to get user key from context")
		return fiber.NewError(fiber.StatusInternalServerError, "failed to get user key from request context")
	}

	body := new(models.CreateTemplateRequest)
	err = ctx.BodyParser(body)
	if err != nil {
		a.logger.Error().Err(err).Msg("failed to parse body")
		return fiber.NewError(fiber.StatusBadRequest, "failed to parse body")
	}

	if body.Name == "" {
		return fiber.NewError(fiber.StatusBadRequest, "name is required")
	}

	if !utils.ValidString(body.Name) {
		return fiber.NewError(fiber.StatusBadRequest, "invalid name")
	}

	if body.AuthorityName == "" {
		return fiber.NewError(fiber.StatusBadRequest, "authority name is required")
	}

	if !utils.ValidString(body.AuthorityName) {
		return fiber.NewError(fiber.StatusBadRequest, "invalid authority name")
	}

	if body.CommonName == "" {
		return fiber.NewError(fiber.StatusBadRequest, "common name is required")
	}

	if !utils.ValidDNS(body.CommonName) {
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

	a.logger.Info().Msgf("creating template '%s' with authority '%s', common name '%s', dns names '%v', validity %s, client %t, and server %t for user key %s", body.Name, body.AuthorityName, body.CommonName, body.DNSNames, validity.String(), body.Client, body.Server, uk.Name)

	templ, err := a.options.Database().CreateTemplate(ctx.Context(), body.Name, body.AuthorityName, uk, body.CommonName, body.AllowOverrideCommonName, body.Tag, body.DNSNames, body.AllowAdditionalDNSNames, body.IPAddresses, body.AllowAdditionalIPs, validity.String(), body.Client, body.Server)
	if err != nil {
		if errors.Is(err, database.ErrAlreadyExists) {
			return fiber.NewError(fiber.StatusConflict, "template already exists")
		}

		a.logger.Error().Err(err).Msg("failed to create template")
		return fiber.NewError(fiber.StatusInternalServerError, "failed to create template")
	}

	return ctx.JSON(&models.TemplateResponse{
		CreatedAt:               templ.CreatedAt.Format(time.RFC3339),
		ID:                      templ.ID,
		Name:                    templ.Name,
		AuthorityName:           body.AuthorityName,
		CommonName:              templ.CommonName,
		AllowOverrideCommonName: templ.AllowOverrideCommonName,
		Tag:                     templ.Tag,
		DNSNames:                templ.DNSNames,
		AllowAdditionalDNSNames: templ.AllowAdditionalDNSNames,
		IPAddresses:             templ.IPAddresses,
		AllowAdditionalIPs:      templ.AllowAdditionalIps,
		Validity:                templ.Validity,
		Client:                  templ.Client,
		Server:                  templ.Server,
	})
}

// List godoc
// @Description  List all Templates
// @Tags         template
// @Accept       json
// @Produce      json
// @Param 	     authority_name  path  string  true  "Authority Name"
// @Success      200  {array} models.TemplateResponse
// @Failure      400  {string} string
// @Failure      401  {string} string
// @Failure      404  {string} string
// @Failure      409  {string} string
// @Failure      412  {string} string
// @Failure      500  {string} string
// @Router       /template/{authority_name} [get]
func (a *Template) List(ctx *fiber.Ctx) error {
	a.logger.Debug().Msgf("received List request from %s", ctx.IP())

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

	a.logger.Info().Msgf("listing templates for authority '%s' for user key %s", authorityName, uk.Name)

	templs, err := a.options.Database().ListTemplates(ctx.Context(), authorityName, uk)
	if err != nil {
		if errors.Is(err, database.ErrNotFound) {
			return fiber.NewError(fiber.StatusNotFound, "no templates found")
		}

		a.logger.Error().Err(err).Msg("failed to list templates")
		return fiber.NewError(fiber.StatusInternalServerError, "failed to list templates")
	}

	ret := make([]*models.TemplateResponse, 0, len(templs))
	for _, templ := range templs {
		ret = append(ret, &models.TemplateResponse{
			CreatedAt:               templ.CreatedAt.Format(time.RFC3339),
			ID:                      templ.ID,
			Name:                    templ.Name,
			AuthorityName:           authorityName,
			CommonName:              templ.CommonName,
			AllowOverrideCommonName: templ.AllowOverrideCommonName,
			Tag:                     templ.Tag,
			DNSNames:                templ.DNSNames,
			AllowAdditionalDNSNames: templ.AllowAdditionalDNSNames,
			IPAddresses:             templ.IPAddresses,
			AllowAdditionalIPs:      templ.AllowAdditionalIps,
			Validity:                templ.Validity,
			Client:                  templ.Client,
			Server:                  templ.Server,
		})
	}

	return ctx.JSON(ret)
}

// Delete godoc
// @Description  Delete a Template
// @Tags         template
// @Accept       json
// @Produce      json
// @Param        request  body models.DeleteTemplateRequest  true  "Delete Template Request"
// @Success      200  {string} string
// @Failure      400  {string} string
// @Failure      401  {string} string
// @Failure      404  {string} string
// @Failure      409  {string} string
// @Failure      412  {string} string
// @Failure      500  {string} string
// @Router       /template [delete]
func (a *Template) Delete(ctx *fiber.Ctx) error {
	a.logger.Debug().Msgf("received Delete request from %s", ctx.IP())

	uk, err := authorization.GetUserKey(ctx)
	if err != nil {
		a.logger.Error().Err(err).Msg("failed to get user key from context")
		return fiber.NewError(fiber.StatusInternalServerError, "failed to get user key from request context")
	}

	body := new(models.DeleteTemplateRequest)
	err = ctx.BodyParser(body)
	if err != nil {
		a.logger.Error().Err(err).Msg("failed to parse body")
		return fiber.NewError(fiber.StatusBadRequest, "failed to parse body")
	}

	if body.Name == "" {
		return fiber.NewError(fiber.StatusBadRequest, "name is required")
	}

	if !utils.ValidString(body.Name) {
		return fiber.NewError(fiber.StatusBadRequest, "invalid name")
	}

	if body.AuthorityName == "" {
		return fiber.NewError(fiber.StatusBadRequest, "authority name is required")
	}

	if !utils.ValidString(body.AuthorityName) {
		return fiber.NewError(fiber.StatusBadRequest, "invalid authority name")
	}

	a.logger.Info().Msgf("deleting template '%s' with authority '%s' for user key %s", body.Name, body.AuthorityName, uk.Name)

	err = a.options.Database().DeleteTemplateByName(ctx.Context(), body.Name, body.AuthorityName, uk)
	if err != nil {
		if errors.Is(err, database.ErrNotFound) {
			return fiber.NewError(fiber.StatusNotFound, "template not found")
		}

		if errors.Is(err, database.ErrAlreadyExists) {
			return fiber.NewError(fiber.StatusConflict, "cannot delete template because resources are still associated with it")
		}

		a.logger.Error().Err(err).Msg("failed to delete template")
		return fiber.NewError(fiber.StatusInternalServerError, "failed to delete template")
	}

	return ctx.SendString(fmt.Sprintf("template '%s' for authority '%s' deleted", body.Name, body.AuthorityName))
}

func (a *Template) App() *fiber.App {
	return a.app
}
