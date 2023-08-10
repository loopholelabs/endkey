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

// Template holds the schema definition for the Template entity.
//
// A Template is a Certificate Template for use with a Client or Server.
type Template struct {
	ent.Schema
}

// Fields of the Template.
func (Template) Fields() []ent.Field {
	return []ent.Field{
		// When the Template was created, immutable
		field.Time("created_at").Immutable().Default(time.Now),

		// A unique identifier for the Template, immutable, globally unique
		field.String("id").NotEmpty().Unique().Immutable().StorageKey("id"),

		// An easily recognizable name for the Template, immutable
		//
		// Its uniqueness is guaranteed within the Authority that it is scoped to
		field.String("name").NotEmpty().Immutable(),

		// The Common Name for the Template, immutable
		field.String("common_name").NotEmpty().Immutable(),

		// The Tag for the Template, immutable
		field.String("tag").NotEmpty().Immutable(),

		// The Validity for the Template, immutable
		field.String("validity").NotEmpty().Immutable(),

		// The DNS Names for the Template, immutable
		field.Strings("dns_names").Immutable().Optional(),

		// Whether to allow additional DNS Names for the Template, immutable
		field.Bool("allow_additional_dns_names").Immutable().Default(false),

		// The IP Addresses for the Template, immutable
		field.Strings("ip_addresses").Immutable().Optional(),

		// Whether to allow additional IP Addresses for the Template, immutable
		field.Bool("allow_additional_ips").Immutable().Default(false),

		// Whether this is a client Template, immutable
		field.Bool("client").Immutable().Default(false),

		// Whether this is a server Template, immutable
		field.Bool("server").Immutable().Default(false),
	}
}

// Edges of the Template.
func (Template) Edges() []ent.Edge {
	return []ent.Edge{
		// The Authority that this Template is associated with
		//
		// This edge is a many-to-one relationship, as an Authority can have many Templates scoped to it
		// but a Template can only be scoped to one Template at a time
		//
		// This edge is unique, required, and immutable
		edge.From("authority", Authority.Type).Ref("templates").Unique().Required().Immutable(),

		// The API Keys that are scoped to this Template
		//
		// This is a one-to-many relationship, as an API Key can only be scoped to one Template
		// but a Template can have multiple API Keys scoped to it
		edge.To("api_keys", APIKey.Type),
	}
}

// Indexes of the Template.
func (Template) Indexes() []ent.Index {
	return []ent.Index{
		// Guarantee uniqueness of the Template's name per Authority
		index.Fields("name").Edges("authority").Unique(),
	}
}
