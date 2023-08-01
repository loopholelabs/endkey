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

type CreateAPIKeyRequest struct {
	Name           string `json:"name"`
	Authority      string `json:"authority"`
	ServerTemplate string `json:"server_template"`
	ClientTemplate string `json:"client_template"`
}

type APIKeyResponse struct {
	Identifier     string `json:"identifier"`
	Name           string `json:"name"`
	Authority      string `json:"authority"`
	ServerTemplate string `json:"server_template"`
	ClientTemplate string `json:"client_template"`
	Secret         string `json:"secret"`
}
