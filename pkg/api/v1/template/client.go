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
	"github.com/loopholelabs/endkey/internal/utils"
	"github.com/loopholelabs/endkey/pkg/api/authorization"
	"github.com/loopholelabs/endkey/pkg/api/v1/models"
	"net"
	"time"
)

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

	templ, err := a.options.Database().CreateClientTemplate(ctx.Context(), body.Identifier, body.Authority, body.CommonName, body.Tag, body.DNSNames, body.AllowAdditionalDNSNames, body.IPAddresses, body.AllowAdditionalIPs, validity.String())
	if err != nil {
		if errors.Is(err, database.ErrAlreadyExists) {
			return fiber.NewError(fiber.StatusConflict, "client template already exists")
		}

		a.logger.Error().Err(err).Msg("failed to create client template")
		return fiber.NewError(fiber.StatusInternalServerError, "failed to create client template")
	}

	return ctx.JSON(&models.ClientTemplateResponse{
		CreatedAt:               templ.CreatedAt.Format(time.RFC3339),
		Identifier:              templ.Identifier,
		Authority:               body.Authority,
		CommonName:              templ.CommonName,
		Tag:                     templ.Tag,
		DNSNames:                templ.DNSNames,
		AllowAdditionalDNSNames: templ.AllowAdditionalDNSNames,
		IPAddresses:             templ.IPAddresses,
		AllowAdditionalIPs:      templ.AllowAdditionalIps,
		Validity:                templ.Validity,
	})
}

// ListClient godoc
// @Description  List all Client Templates
// @Tags         template
// @Accept       json
// @Produce      json
// @Param 	     authority  path  string  true  "Authority Identifier"
// @Success      200  {array} models.ClientTemplateResponse
// @Failure      400  {string} string
// @Failure      401  {string} string
// @Failure      404  {string} string
// @Failure      409  {string} string
// @Failure      412  {string} string
// @Failure      500  {string} string
// @Router       /template/client/{authority} [get]
func (a *Template) ListClient(ctx *fiber.Ctx) error {
	a.logger.Debug().Msgf("received ListClient request from %s", ctx.IP())

	rk, err := authorization.GetRootKey(ctx)
	if err != nil {
		a.logger.Error().Err(err).Msg("failed to get root key from context")
		return fiber.NewError(fiber.StatusInternalServerError, "failed to get root key from request context")
	}

	authority := ctx.Params("authority")

	if authority == "" {
		return fiber.NewError(fiber.StatusBadRequest, "authority is required")
	}

	if !utils.ValidString(authority) {
		return fiber.NewError(fiber.StatusBadRequest, "authority is invalid")
	}

	a.logger.Info().Msgf("listing Client Templates for Authority '%s' for root key with ID %s", authority, rk.Identifier)

	templs, err := a.options.Database().ListClientTemplates(ctx.Context(), authority)
	if err != nil {
		if errors.Is(err, database.ErrNotFound) {
			return fiber.NewError(fiber.StatusNotFound, "no client templates found")
		}

		a.logger.Error().Err(err).Msg("failed to list client templates")
		return fiber.NewError(fiber.StatusInternalServerError, "failed to list client templates")
	}

	ret := make([]*models.ClientTemplateResponse, 0, len(templs))
	for _, templ := range templs {
		ret = append(ret, &models.ClientTemplateResponse{
			CreatedAt:               templ.CreatedAt.Format(time.RFC3339),
			Identifier:              templ.Identifier,
			Authority:               authority,
			CommonName:              templ.CommonName,
			Tag:                     templ.Tag,
			DNSNames:                templ.DNSNames,
			AllowAdditionalDNSNames: templ.AllowAdditionalDNSNames,
			IPAddresses:             templ.IPAddresses,
			AllowAdditionalIPs:      templ.AllowAdditionalIps,
			Validity:                templ.Validity,
		})
	}

	return ctx.JSON(ret)
}

// DeleteClient godoc
// @Description  Delete a Client Template
// @Tags         template
// @Accept       json
// @Produce      json
// @Param        request  body models.DeleteClientTemplateRequest  true  "Delete Server Client Request"
// @Success      200  {string} string
// @Failure      400  {string} string
// @Failure      401  {string} string
// @Failure      404  {string} string
// @Failure      409  {string} string
// @Failure      412  {string} string
// @Failure      500  {string} string
// @Router       /template/client [delete]
func (a *Template) DeleteClient(ctx *fiber.Ctx) error {
	a.logger.Debug().Msgf("received DeleteClient request from %s", ctx.IP())

	rk, err := authorization.GetRootKey(ctx)
	if err != nil {
		a.logger.Error().Err(err).Msg("failed to get root key from context")
		return fiber.NewError(fiber.StatusInternalServerError, "failed to get root key from request context")
	}

	body := new(models.DeleteClientTemplateRequest)
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

	a.logger.Info().Msgf("deleting client template '%s' with authority '%s' for root key with ID %s", body.Identifier, body.Authority, rk.Identifier)

	err = a.options.Database().DeleteClientTemplate(ctx.Context(), body.Identifier, body.Authority)
	if err != nil {
		if errors.Is(err, database.ErrNotFound) {
			return fiber.NewError(fiber.StatusNotFound, "client template not found")
		}

		if errors.Is(err, database.ErrAlreadyExists) {
			return fiber.NewError(fiber.StatusConflict, "cannot delete client template because resources are still associated with it")
		}

		a.logger.Error().Err(err).Msg("failed to delete client template")
		return fiber.NewError(fiber.StatusInternalServerError, "failed to delete client template")
	}

	return ctx.SendString(fmt.Sprintf("client template '%s' for authority '%s' deleted", body.Identifier, body.Authority))
}
