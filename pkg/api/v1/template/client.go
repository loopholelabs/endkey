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

	uk, err := authorization.GetUserKey(ctx)
	if err != nil {
		a.logger.Error().Err(err).Msg("failed to get user key from context")
		return fiber.NewError(fiber.StatusInternalServerError, "failed to get user key from request context")
	}

	body := new(models.CreateClientTemplateRequest)
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

	a.logger.Info().Msgf("creating client template '%s' with authority '%s', common name '%s', dns names '%v', and a validity of %s for user key %s", body.Name, body.AuthorityName, body.CommonName, body.DNSNames, validity.String(), uk.Name)

	templ, err := a.options.Database().CreateClientTemplate(ctx.Context(), body.Name, body.AuthorityName, uk, body.CommonName, body.Tag, body.DNSNames, body.AllowAdditionalDNSNames, body.IPAddresses, body.AllowAdditionalIPs, validity.String())
	if err != nil {
		if errors.Is(err, database.ErrAlreadyExists) {
			return fiber.NewError(fiber.StatusConflict, "client template already exists")
		}

		a.logger.Error().Err(err).Msg("failed to create client template")
		return fiber.NewError(fiber.StatusInternalServerError, "failed to create client template")
	}

	return ctx.JSON(&models.ClientTemplateResponse{
		CreatedAt:               templ.CreatedAt.Format(time.RFC3339),
		ID:                      templ.ID,
		Name:                    templ.Name,
		AuthorityName:           body.AuthorityName,
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
// @Param 	     authority_name  path  string  true  "Authority Name"
// @Success      200  {array} models.ClientTemplateResponse
// @Failure      400  {string} string
// @Failure      401  {string} string
// @Failure      404  {string} string
// @Failure      409  {string} string
// @Failure      412  {string} string
// @Failure      500  {string} string
// @Router       /template/client/{authority_name} [get]
func (a *Template) ListClient(ctx *fiber.Ctx) error {
	a.logger.Debug().Msgf("received ListClient request from %s", ctx.IP())

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

	a.logger.Info().Msgf("listing client templates for authority '%s' for user key %s", authorityName, uk.Name)

	templs, err := a.options.Database().ListClientTemplates(ctx.Context(), authorityName, uk)
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
			ID:                      templ.ID,
			Name:                    templ.Name,
			AuthorityName:           authorityName,
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
// @Param        request  body models.DeleteClientTemplateRequest  true  "Delete Client Template Request"
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

	uk, err := authorization.GetUserKey(ctx)
	if err != nil {
		a.logger.Error().Err(err).Msg("failed to get user key from context")
		return fiber.NewError(fiber.StatusInternalServerError, "failed to get user key from request context")
	}

	body := new(models.DeleteClientTemplateRequest)
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

	a.logger.Info().Msgf("deleting client template '%s' with authority '%s' for user key %s", body.Name, body.AuthorityName, uk.Name)

	err = a.options.Database().DeleteClientTemplateByName(ctx.Context(), body.Name, body.AuthorityName, uk)
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

	return ctx.SendString(fmt.Sprintf("client template '%s' for authority '%s' deleted", body.Name, body.AuthorityName))
}
