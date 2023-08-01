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

package authority

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"github.com/gofiber/fiber/v2"
	"github.com/loopholelabs/endkey/internal/database"
	"github.com/loopholelabs/endkey/internal/metrics"
	"github.com/loopholelabs/endkey/internal/utils"
	"github.com/loopholelabs/endkey/pkg/api/authorization"
	"github.com/loopholelabs/endkey/pkg/api/v1/models"
	"github.com/loopholelabs/endkey/pkg/api/v1/options"
	"github.com/rs/zerolog"
	"math/big"
	"time"
)

var (
	createMetric = metrics.NewStatusMetric("v1_authority_create", "The total number of authority create requests")
)

type Authority struct {
	logger  *zerolog.Logger
	app     *fiber.App
	options *options.Options
}

func New(options *options.Options, logger *zerolog.Logger) *Authority {
	l := logger.With().Str("COMPONENT", "AUTHORITY").Logger()
	i := &Authority{
		logger:  &l,
		app:     utils.DefaultFiberApp(),
		options: options,
	}

	i.init()

	return i
}

func (a *Authority) init() {
	a.logger.Debug().Msg("initializing")

	a.app.Use(a.options.Auth().RootKeyValidate)
	a.app.Post("/", createMetric.Middleware(), a.CreateAuthority)
}

// CreateAuthority godoc
// @Description  Create a new Authority
// @Tags         authority
// @Accept       json
// @Produce      json
// @Param        request  body models.CreateAuthorityRequest  true  "Create Authority Request"
// @Success      200  {object} models.AuthorityResponse
// @Failure      400  {string} string
// @Failure      401  {string} string
// @Failure      404  {string} string
// @Failure      409  {string} string
// @Failure      412  {string} string
// @Failure      500  {string} string
// @Router       /authority [post]
func (a *Authority) CreateAuthority(ctx *fiber.Ctx) error {
	a.logger.Debug().Msgf("received CreateAuthority request from %s", ctx.IP())

	rk, err := authorization.GetRootKey(ctx)
	if err != nil {
		a.logger.Error().Err(err).Msg("failed to get root key from context")
		return fiber.NewError(fiber.StatusInternalServerError, "failed to get root key from request context")
	}

	body := new(models.CreateAuthorityRequest)
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

	if body.Validity == "" {
		return fiber.NewError(fiber.StatusBadRequest, "validity is required")
	}

	validity, err := time.ParseDuration(body.Validity)
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid validity")

	}

	ca := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:         body.CommonName,
			Organization:       []string{a.options.Identifier()},
			Country:            []string{"-"},
			Province:           []string{"-"},
			Locality:           []string{"-"},
			OrganizationalUnit: []string{body.Tag},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(validity),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		a.logger.Error().Err(err).Msg("failed to generate private key")
		return fiber.NewError(fiber.StatusInternalServerError, "failed to generate private key")
	}

	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, &privateKey.PublicKey, privateKey)
	if err != nil {
		a.logger.Error().Err(err).Msg("failed to create certificate")
		return fiber.NewError(fiber.StatusInternalServerError, "failed to create ca certificate")
	}

	caPEM, err := utils.EncodeX509Certificate(caBytes)
	if err != nil {
		a.logger.Error().Err(err).Msg("failed to encode ca certificate")
		return fiber.NewError(fiber.StatusInternalServerError, "failed to encode ca certificate")
	}

	privateKeyPEM := utils.EncodeECDSAPrivateKey(privateKey)

	a.logger.Info().Msgf("creating authority '%s' with common name '%s' for root key with ID %s", body.Identifier, body.CommonName, rk.Identifier)

	authority, err := a.options.Database().CreateAuthority(ctx.Context(), body.Identifier, caPEM, privateKeyPEM)
	if err != nil {
		if errors.Is(err, database.ErrAlreadyExists) {
			return fiber.NewError(fiber.StatusConflict, "authority already exists")
		}

		a.logger.Error().Err(err).Msg("failed to create authority")
		return fiber.NewError(fiber.StatusInternalServerError, "failed to create authority")
	}

	return ctx.JSON(&models.AuthorityResponse{
		Identifier:    authority.Identifier,
		CommonName:    body.CommonName,
		Tag:           body.Tag,
		Expiry:        ca.NotAfter.Format(time.RFC3339),
		CACertificate: base64.StdEncoding.EncodeToString(caPEM),
	})
}

func (a *Authority) App() *fiber.App {
	return a.app
}
