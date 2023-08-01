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

package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"time"
)

// Authority holds the schema definition for the Authority entity.
//
// An Authority is the Certificate Authority is responsible for signing server-side and client-side certificates
// for the purpose of establishing an mTLS connection between two services.
type Authority struct {
	ent.Schema
}

// Fields of the CertificateAuthority.
func (Authority) Fields() []ent.Field {
	return []ent.Field{
		// When the Authority was created, immutable
		field.Time("created_at").Immutable().Default(time.Now),

		// A unique identifier for the Authority, immutable, globally unique
		//
		// This identifier will be used to address the Authority in the API
		field.String("identifier").NotEmpty().Unique().Immutable(),

		// The CA Public Key encoded in the PEM format
		field.Bytes("ca_certificate_pem").NotEmpty(),

		// The Encrypted Private Key for the CA Certificate
		field.String("encrypted_private_key").NotEmpty(),
	}
}

// Edges of the CertificateAuthority.
func (Authority) Edges() []ent.Edge {
	return []ent.Edge{
		// The API Keys that are scoped to this Authority
		//
		// This is a one-to-many relationship, as an API Key can only be scoped to one Authority
		// but an Authority can have multiple API Keys scoped to it
		edge.To("api_keys", APIKey.Type),

		// The Server Templates that are scoped to this Authority
		//
		// This is a one-to-many relationship, as a Server Template can only be scoped to one Authority
		// but an Authority can have multiple Server Templates scoped to it
		edge.To("server_templates", ServerTemplate.Type),

		// The Client Templates that are scoped to this Authority
		//
		// This is a one-to-many relationship, as a Client Template can only be scoped to one Authority
		// but an Authority can have multiple Client Templates scoped to it
		edge.To("client_templates", ClientTemplate.Type),
	}
}
