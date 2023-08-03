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

package loader

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	httptransport "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"
	"github.com/loopholelabs/endkey/internal/utils"
	"github.com/loopholelabs/endkey/pkg/api/authorization"
	"github.com/loopholelabs/endkey/pkg/client"
	"github.com/loopholelabs/endkey/pkg/client/certificate"
	"github.com/loopholelabs/endkey/pkg/client/models"
	"github.com/loopholelabs/tls/pkg/loader"
)

var _ loader.Loader = (*Loader)(nil)

var (
	ErrInvalidEndpoint = errors.New("invalid endpoint")
	ErrInvalidAPIKey   = errors.New("invalid api key")
)

type Options struct {
	Endpoint              string
	TLS                   bool
	APIKey                string
	AdditionalDNSNames    []string
	AdditionalIPAddresses []string
}

type Loader struct {
	options *Options
	client  *client.EndKeyAPIV1
}

func New(options *Options) (*Loader, error) {
	if options.Endpoint == "" {
		return nil, ErrInvalidEndpoint
	}

	if options.APIKey == "" {
		return nil, ErrInvalidAPIKey
	}

	scheme := "http"
	if options.TLS {
		scheme = "https"
	}
	r := httptransport.New(options.Endpoint, client.DefaultBasePath, []string{scheme})
	r.DefaultAuthentication = httptransport.APIKeyAuth(authorization.HeaderString, "header", authorization.BearerString+options.APIKey)

	c := client.New(r, strfmt.Default)

	return &Loader{
		options: options,
		client:  c,
	}, nil
}

func (l *Loader) RootCA(ctx context.Context) (*x509.CertPool, error) {
	result, err := l.client.Certificate.GetCertificate(certificate.NewGetCertificateParamsWithContext(ctx))
	if err != nil {
		return nil, err
	}

	caPEM, err := base64.StdEncoding.DecodeString(result.GetPayload().CaCertificate)
	if err != nil {
		return nil, err
	}

	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(caPEM)

	return caPool, nil
}

func (l *Loader) Certificate(ctx context.Context) (*tls.Certificate, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	template := &x509.CertificateRequest{
		SignatureAlgorithm: x509.ECDSAWithSHA256,
	}

	csrPEM, err := x509.CreateCertificateRequest(rand.Reader, template, privateKey)
	if err != nil {
		return nil, err
	}

	req := &models.ModelsCreateCertificateRequest{
		AdditionalDNSNames:    l.options.AdditionalDNSNames,
		AdditionalIPAddresses: l.options.AdditionalIPAddresses,
		Csr:                   base64.StdEncoding.EncodeToString(csrPEM),
	}

	result, err := l.client.Certificate.PostCertificate(certificate.NewPostCertificateParamsWithContext(ctx).WithRequest(req))
	if err != nil {
		return nil, err
	}

	certPEM, err := base64.StdEncoding.DecodeString(result.GetPayload().PublicCertificate)
	if err != nil {
		return nil, err
	}

	cert, err := utils.DecodeX509Certificate(certPEM)
	if err != nil {
		return nil, err
	}

	return &tls.Certificate{
		Certificate: [][]byte{cert.Raw},
		Leaf:        cert,
		PrivateKey:  privateKey,
	}, nil
}