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
	"github.com/gofiber/fiber/v2"
	"github.com/loopholelabs/endkey/internal/metrics"
	"github.com/loopholelabs/endkey/internal/utils"
	"github.com/loopholelabs/endkey/pkg/api/authorization"
	"github.com/loopholelabs/endkey/pkg/api/v1/models"
	"github.com/loopholelabs/endkey/pkg/api/v1/options"
	"github.com/loopholelabs/endkey/pkg/template"
	"github.com/rs/zerolog"
	"math/big"
	"net"
	"time"
)

var (
	createCertificateMetric = metrics.NewStatusMetric("v1_certificate_create", "The total number of certificate create requests")
	getCAMetric             = metrics.NewStatusMetric("v1_certificate_ca", "The total number of certificate ca get requests")
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
	a.app.Post("/", createCertificateMetric.Middleware(), a.CreateCertificate)
	a.app.Get("/", getCAMetric.Middleware(), a.GetCA)
}

// CreateCertificate godoc
// @Description  Create a new Certificate
// @Tags         certificate
// @Accept       json
// @Produce      json
// @Param        request  body models.CreateCertificateRequest  true  "Create Certificate Request"
// @Success      200  {object} models.CertificateResponse
// @Failure      400  {string} string
// @Failure      401  {string} string
// @Failure      404  {string} string
// @Failure      409  {string} string
// @Failure      412  {string} string
// @Failure      500  {string} string
// @Router       /certificate [post]
func (a *Certificate) CreateCertificate(ctx *fiber.Ctx) error {
	a.logger.Debug().Msgf("received CreateCertificate request from %s", ctx.IP())

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

	body := new(models.CreateCertificateRequest)
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

	var kind template.Kind
	var name string
	var commonName string
	var tag string
	var templateDNSNames []string
	var templateIPAddresses []string
	var validity string
	clientTemplate, err := ak.Edges.ClientTemplateOrErr()
	if err == nil {
		kind = template.Client
		name = clientTemplate.Name
		commonName = clientTemplate.CommonName
		tag = clientTemplate.Tag
		templateDNSNames = clientTemplate.DNSNames
		templateIPAddresses = clientTemplate.IPAddresses
		validity = clientTemplate.Validity
	} else {
		serverTemplate, err := ak.Edges.ServerTemplateOrErr()
		if err == nil {
			kind = template.Server
			name = serverTemplate.Name
			commonName = serverTemplate.CommonName
			tag = serverTemplate.Tag
			templateDNSNames = serverTemplate.DNSNames
			templateIPAddresses = serverTemplate.IPAddresses
			validity = serverTemplate.Validity
		} else {
			a.logger.Error().Msg("failed to get template from api key")
			return fiber.NewError(fiber.StatusInternalServerError, "error finding template for api key")
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

	dnsNames := make([]string, 0, len(templateDNSNames)+len(body.AdditionalDNSNames))
	for _, dnsName := range templateDNSNames {
		if !utils.ValidDNS(dnsName) {
			a.logger.Error().Msg("invalid dns name in template")
			return fiber.NewError(fiber.StatusInternalServerError, "invalid dns name in template")
		}
		dnsNames = append(dnsNames, dnsName)
	}

	for _, dnsName := range body.AdditionalDNSNames {
		dnsNames = append(dnsNames, dnsName)
	}

	ipAddress := make([]net.IP, 0, len(templateIPAddresses)+len(body.AdditionalIPAddresses))
	for _, ip := range templateIPAddresses {
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

	parsedValidity, err := time.ParseDuration(validity)
	if err != nil {
		a.logger.Error().Err(err).Msg("failed to parse validity")
		return fiber.NewError(fiber.StatusInternalServerError, "failed to parse validity")
	}

	templ := &x509.Certificate{
		SerialNumber:       big.NewInt(1),
		Signature:          csr.Signature,
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		PublicKeyAlgorithm: x509.ECDSA,
		PublicKey:          csr.PublicKey,
		Issuer:             ca.Subject,
		Subject: pkix.Name{
			CommonName:         commonName,
			Organization:       []string{a.options.Identifier(), name},
			Country:            []string{"-"},
			Province:           []string{"-"},
			Locality:           []string{"-"},
			OrganizationalUnit: []string{tag},
		},
		DNSNames:    dnsNames,
		IPAddresses: ipAddress,
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(parsedValidity),
		KeyUsage:    x509.KeyUsageDigitalSignature,
	}

	switch kind {
	case template.Server:
		templ.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	case template.Client:
		templ.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	default:
		a.logger.Error().Msg("invalid template kind")
		return fiber.NewError(fiber.StatusInternalServerError, "invalid template kind")
	}

	a.logger.Info().Msgf("creating %s certificate for template '%s' with authority '%s' for api key %s", string(kind), name, auth.Name, ak.Name)

	certBytes, err := x509.CreateCertificate(rand.Reader, templ, ca, csr.PublicKey, privateKey)
	if err != nil {
		a.logger.Error().Err(err).Msg("failed to create certificate")
		return fiber.NewError(fiber.StatusInternalServerError, "failed to create certificate")
	}

	certPEM, err := utils.EncodeX509Certificate(certBytes)
	if err != nil {
		a.logger.Error().Err(err).Msg("failed to encode certificate")
		return fiber.NewError(fiber.StatusInternalServerError, "failed to encode certificate")
	}

	return ctx.JSON(&models.CertificateResponse{
		AuthorityName:         auth.Name,
		TemplateName:          name,
		TemplateKind:          string(kind),
		AdditionalDNSNames:    body.AdditionalDNSNames,
		AdditionalIPAddresses: body.AdditionalIPAddresses,
		Expiry:                templ.NotAfter.Format(time.RFC3339),
		CACertificate:         base64.StdEncoding.EncodeToString(auth.CaCertificatePem),
		PublicCertificate:     base64.StdEncoding.EncodeToString(certPEM),
	})
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
// @Router       /certificate [get]
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
