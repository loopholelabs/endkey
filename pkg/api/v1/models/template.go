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

type CreateServerTemplateRequest struct {
	Identifier              string   `json:"identifier"`
	Authority               string   `json:"authority"`
	CommonName              string   `json:"common_name"`
	Tag                     string   `json:"tag"`
	DNSNames                []string `json:"dns_names"`
	AllowAdditionalDNSNames bool     `json:"allow_additional_dns_names"`
	IPAddresses             []string `json:"ip_addresses"`
	AllowAdditionalIPs      bool     `json:"allow_additional_ips"`
	Validity                string   `json:"validity"`
}

type ServerTemplateResponse struct {
	Identifier              string   `json:"identifier"`
	Authority               string   `json:"authority"`
	CommonName              string   `json:"common_name"`
	Tag                     string   `json:"tag"`
	DNSNames                []string `json:"dns_names"`
	AllowAdditionalDNSNames bool     `json:"allow_additional_dns_names"`
	IPAddresses             []string `json:"ip_addresses"`
	AllowAdditionalIPs      bool     `json:"allow_additional_ips"`
	Validity                string   `json:"validity"`
}

type CreateClientTemplateRequest struct {
	Identifier              string   `json:"identifier"`
	Authority               string   `json:"authority"`
	CommonName              string   `json:"common_name"`
	Tag                     string   `json:"tag"`
	DNSNames                []string `json:"dns_names"`
	AllowAdditionalDNSNames bool     `json:"allow_additional_dns_names"`
	IPAddresses             []string `json:"ip_addresses"`
	AllowAdditionalIPs      bool     `json:"allow_additional_ips"`
	Validity                string   `json:"validity"`
}

type ClientTemplateResponse struct {
	Identifier              string   `json:"identifier"`
	Authority               string   `json:"authority"`
	CommonName              string   `json:"common_name"`
	Tag                     string   `json:"tag"`
	DNSNames                []string `json:"dns_names"`
	AllowAdditionalDNSNames bool     `json:"allow_additional_dns_names"`
	IPAddresses             []string `json:"ip_addresses"`
	AllowAdditionalIPs      bool     `json:"allow_additional_ips"`
	Validity                string   `json:"validity"`
}
