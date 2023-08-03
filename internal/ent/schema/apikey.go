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
	"entgo.io/ent/schema/index"
	"time"
)

// APIKey holds the schema definition for the APIKey entity.
//
// An APIKey is an API Key used to authenticate with the API for the purpose of
// issuing server or client certificates using a given Authority.
type APIKey struct {
	ent.Schema
}

// Fields of the APIKey.
func (APIKey) Fields() []ent.Field {
	return []ent.Field{
		// When the API Key was created, immutable
		field.Time("created_at").Immutable().Default(time.Now),

		// A unique identifier for the API Key, immutable, globally unique
		field.String("id").NotEmpty().Unique().Immutable().StorageKey("id"),

		// An easily recognizable name for the API Key, immutable
		//
		// Its uniqueness is guaranteed within the Authority that it is scoped to
		field.String("name").NotEmpty().Immutable(),

		// A randomly generated salt for the API Key, immutable
		field.Bytes("salt").NotEmpty().Immutable(),

		// The hashed API Key, generated from the API Key's secret and salt
		//
		// The secret is never stored, and the salt is immutable
		field.Bytes("hash").NotEmpty().Immutable(),
	}
}

// Edges of the APIKey.
func (APIKey) Edges() []ent.Edge {
	return []ent.Edge{
		// The Authority that this API Key is scoped to
		//
		// This is a many-to-one relationship, as an Authority can have multiple API Keys scoped to it
		// but an API Key can only be scoped to one Authority
		//
		// This edge is unique, required and immutable
		edge.From("authority", Authority.Type).Ref("api_keys").Unique().Required().Immutable(),

		// An optional Server Template that this API Key is scoped to
		//
		// This is a many-to-one relationship, as a Server Template can have multiple API Keys scoped to it
		// but an API Key can only be scoped to one Server Template at a time
		//
		// This edge is unique and immutable
		edge.From("server_template", ServerTemplate.Type).Ref("api_keys").Unique().Immutable(),

		// An optional Client Template that this API Key is scoped to
		//
		// This is a many-to-one relationship, as a Client Template can have multiple API Keys scoped to it
		// but an API Key can only be scoped to one Client Template at a time
		//
		// This edge is unique and immutable
		edge.From("client_template", ClientTemplate.Type).Ref("api_keys").Unique().Immutable(),
	}
}

// Indexes of the APIKey.
func (APIKey) Indexes() []ent.Index {
	return []ent.Index{
		// Guarantee uniqueness of the API Key's name per Authority
		index.Fields("name").Edges("authority").Unique(),
	}
}
