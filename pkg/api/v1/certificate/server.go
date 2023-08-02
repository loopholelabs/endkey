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
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"github.com/gofiber/fiber/v2"
	"github.com/loopholelabs/endkey/internal/database"
	"github.com/loopholelabs/endkey/internal/utils"
	"github.com/loopholelabs/endkey/pkg/api/authorization"
	"github.com/loopholelabs/endkey/pkg/api/v1/models"
	"math/big"
	"net"
	"time"
)

// CreateServer godoc
// @Description  Create a new Server Certificate
// @Tags         certificate
// @Accept       json
// @Produce      json
// @Param        request  body models.CreateServerCertificateRequest  true  "Create Server Certificate Request"
// @Success      200  {object} models.ServerCertificateResponse
// @Failure      400  {string} string
// @Failure      401  {string} string
// @Failure      404  {string} string
// @Failure      409  {string} string
// @Failure      412  {string} string
// @Failure      500  {string} string
// @Router       /certificate/server [post]
func (a *Certificate) CreateServer(ctx *fiber.Ctx) error {
	a.logger.Debug().Msgf("received CreateServer request from %s", ctx.IP())

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

	body := new(models.CreateServerCertificateRequest)
	err = ctx.BodyParser(body)
	if err != nil {
		a.logger.Error().Err(err).Msg("failed to parse body")
		return fiber.NewError(fiber.StatusBadRequest, "failed to parse body")
	}

	for _, dnsName := range body.AdditionalDNSNames {
		if !utils.ValidDNS(dnsName) {
			return fiber.NewError(fiber.StatusBadRequest, "invalid additional dns name")
		}
	}

	for _, ip := range body.AdditionalIPAddresses {
		if net.ParseIP(ip) == nil {
			return fiber.NewError(fiber.StatusBadRequest, "invalid additional ip address")
		}
	}

	if body.CSR == "" {
		return fiber.NewError(fiber.StatusBadRequest, "csr is required")
	}

	csrBytes, err := base64.StdEncoding.DecodeString(body.CSR)
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "failed to decode csr")
	}

	csr, err := utils.DecodeX509CSR(csrBytes)
	if err != nil {
		a.logger.Error().Err(err).Msg("failed to parse csr")
		return fiber.NewError(fiber.StatusBadRequest, "failed to parse csr")
	}

	if csr.SignatureAlgorithm != x509.ECDSAWithSHA256 {
		return fiber.NewError(fiber.StatusBadRequest, "invalid signature algorithm")
	}

	if csr.PublicKeyAlgorithm != x509.ECDSA {
		return fiber.NewError(fiber.StatusBadRequest, "invalid public key algorithm")
	}

	templ, err := ak.Edges.ServerTemplateOrErr()
	if err != nil {
		_, err = ak.Edges.ClientTemplateOrErr()
		if err == nil {
			return fiber.NewError(fiber.StatusBadRequest, "template not valid for this api key")
		}

		if body.Template == "" {
			return fiber.NewError(fiber.StatusBadRequest, "template is required")
		}

		if !utils.ValidString(body.Template) {
			return fiber.NewError(fiber.StatusBadRequest, "template is invalid")
		}

		templ, err = a.options.Database().GetServerTemplate(ctx.Context(), body.Template, auth.Identifier)
		if err != nil {
			if errors.Is(err, database.ErrNotFound) {
				return fiber.NewError(fiber.StatusNotFound, "template not found")
			}

			a.logger.Error().Err(err).Msg("failed to get template")
			return fiber.NewError(fiber.StatusInternalServerError, "failed to get template")
		}
	} else {
		if body.Template != "" && body.Template != templ.Identifier {
			return fiber.NewError(fiber.StatusUnauthorized, "template not valid for this api key")
		}
	}

	ca, err := utils.DecodeX509Certificate(auth.CaCertificatePem)
	if err != nil {
		a.logger.Error().Err(err).Msg("failed to decode ca certificate")
		return fiber.NewError(fiber.StatusInternalServerError, "failed to decode ca certificate")
	}

	privateKeyPEM, err := a.options.Database().DecryptAuthorityPrivateKey(auth)
	if err != nil {
		a.logger.Error().Err(err).Msg("failed to decrypt authority private key")
		return fiber.NewError(fiber.StatusInternalServerError, "failed to decrypt authority private key")
	}

	privateKey, err := utils.DecodeECDSAPrivateKey(privateKeyPEM)
	if err != nil {
		a.logger.Error().Err(err).Msg("failed to decode authority private key")
		return fiber.NewError(fiber.StatusInternalServerError, "failed to decode authority private key")
	}

	dnsNames := make([]string, 0, len(templ.DNSNames)+len(body.AdditionalDNSNames))
	for _, dnsName := range templ.DNSNames {
		if !utils.ValidDNS(dnsName) {
			a.logger.Error().Msg("invalid dns name in template")
			return fiber.NewError(fiber.StatusInternalServerError, "invalid dns name in template")
		}
		dnsNames = append(dnsNames, dnsName)
	}

	for _, dnsName := range body.AdditionalDNSNames {
		dnsNames = append(dnsNames, dnsName)
	}

	ipAddress := make([]net.IP, 0, len(templ.IPAddresses)+len(body.AdditionalIPAddresses))
	for _, ip := range templ.IPAddresses {
		parsedIP := net.ParseIP(ip)
		if parsedIP == nil {
			a.logger.Error().Msg("invalid ip address in template")
			return fiber.NewError(fiber.StatusInternalServerError, "invalid ip address in template")
		}
		ipAddress = append(ipAddress, parsedIP)
	}

	for _, ip := range body.AdditionalIPAddresses {
		ipAddress = append(ipAddress, net.ParseIP(ip))
	}

	validity, err := time.ParseDuration(templ.Validity)
	if err != nil {
		a.logger.Error().Err(err).Msg("failed to parse validity")
		return fiber.NewError(fiber.StatusInternalServerError, "failed to parse validity")
	}

	template := &x509.Certificate{
		SerialNumber:       big.NewInt(1),
		Signature:          csr.Signature,
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		PublicKeyAlgorithm: x509.ECDSA,
		PublicKey:          csr.PublicKey,
		Issuer:             ca.Subject,
		Subject: pkix.Name{
			CommonName:         templ.CommonName,
			Organization:       []string{a.options.Identifier()},
			Country:            []string{"-"},
			Province:           []string{"-"},
			Locality:           []string{"-"},
			OrganizationalUnit: []string{templ.Tag},
		},
		DNSNames:    dnsNames,
		IPAddresses: ipAddress,
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(validity),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	a.logger.Info().Msgf("creating server certificate for template '%s' with authority '%s', for api key with ID %s", body.Template, auth.Identifier, ak.Identifier)

	certBytes, err := x509.CreateCertificate(rand.Reader, template, ca, csr.PublicKey, privateKey)
	if err != nil {
		a.logger.Error().Err(err).Msg("failed to create certificate")
		return fiber.NewError(fiber.StatusInternalServerError, "failed to create certificate")
	}

	certPEM, err := utils.EncodeX509Certificate(certBytes)
	if err != nil {
		a.logger.Error().Err(err).Msg("failed to encode certificate")
		return fiber.NewError(fiber.StatusInternalServerError, "failed to encode certificate")
	}

	return ctx.JSON(&models.ServerCertificateResponse{
		Authority:             auth.Identifier,
		Template:              templ.Identifier,
		AdditionalDNSNames:    body.AdditionalDNSNames,
		AdditionalIPAddresses: body.AdditionalIPAddresses,
		Expiry:                template.NotAfter.Format(time.RFC3339),
		CACertificate:         base64.StdEncoding.EncodeToString(auth.CaCertificatePem),
		PublicCertificate:     base64.StdEncoding.EncodeToString(certPEM),
	})
}
