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

type CreateTemplateRequest struct {
	Name                    string   `json:"name"`
	AuthorityName           string   `json:"authority_name"`
	CommonName              string   `json:"common_name"`
	AllowOverrideCommonName bool     `json:"allow_override_common_name"`
	Tag                     string   `json:"tag"`
	DNSNames                []string `json:"dns_names"`
	AllowAdditionalDNSNames bool     `json:"allow_additional_dns_names"`
	IPAddresses             []string `json:"ip_addresses"`
	AllowAdditionalIPs      bool     `json:"allow_additional_ips"`
	Validity                string   `json:"validity"`
	Client                  bool     `json:"client"`
	Server                  bool     `json:"server"`
}

type DeleteTemplateRequest struct {
	Name          string `json:"name"`
	AuthorityName string `json:"authority_name"`
}

type TemplateResponse struct {
	CreatedAt               string   `json:"created_at"`
	ID                      string   `json:"id"`
	Name                    string   `json:"name"`
	AuthorityName           string   `json:"authority_name"`
	CommonName              string   `json:"common_name"`
	AllowOverrideCommonName bool     `json:"allow_override_common_name"`
	Tag                     string   `json:"tag"`
	DNSNames                []string `json:"dns_names"`
	AllowAdditionalDNSNames bool     `json:"allow_additional_dns_names"`
	IPAddresses             []string `json:"ip_addresses"`
	AllowAdditionalIPs      bool     `json:"allow_additional_ips"`
	Validity                string   `json:"validity"`
	Client                  bool     `json:"client"`
	Server                  bool     `json:"server"`
}
