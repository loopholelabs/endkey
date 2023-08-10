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

package models

type CreateCertificateRequest struct {
	AdditionalDNSNames    []string `json:"additional_dns_names"`
	AdditionalIPAddresses []string `json:"additional_ip_addresses"`
	CSR                   string   `json:"csr" format:"base64"`
}

type CertificateResponse struct {
	AuthorityName         string   `json:"authority_name"`
	TemplateName          string   `json:"template_name"`
	Client                bool     `json:"client"`
	Server                bool     `json:"server"`
	AdditionalDNSNames    []string `json:"additional_dns_names"`
	AdditionalIPAddresses []string `json:"additional_ip_addresses"`
	Expiry                string   `json:"expiry"`
	CACertificate         string   `json:"ca_certificate" format:"base64"`
	PublicCertificate     string   `json:"public_certificate" format:"base64"`
}

type CAResponse struct {
	AuthorityName string `json:"authority_name"`
	CACertificate string `json:"ca_certificate" format:"base64"`
}
