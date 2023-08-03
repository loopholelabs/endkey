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

// UserKey holds the schema definition for the UserKey entity.
//
// A UserKey is a User Key used to authenticate with the API for the purpose of
// creating and managing Authorities and their associated Client Templates, Server Templates, and API Keys.
type UserKey struct {
	ent.Schema
}

// Fields of the UserKey.
func (UserKey) Fields() []ent.Field {
	return []ent.Field{
		// When the User Key was created, immutable
		field.Time("created_at").Immutable().Default(time.Now),

		// A unique identifier for the User Key, immutable, globally unique
		field.String("id").NotEmpty().Unique().Immutable().StorageKey("id"),

		// An easily recognizable name for the User Key, immutable, globally unique
		field.String("name").NotEmpty().Unique().Immutable(),

		// A randomly generated salt for the User Key, immutable
		field.Bytes("salt").NotEmpty().Immutable(),

		// The hashed User Key, generated from the User Key's secret and salt
		//
		// The secret is never stored, and the salt is immutable
		field.Bytes("hash").NotEmpty().Immutable(),
	}
}

// Edges of the UserKey.
func (UserKey) Edges() []ent.Edge {
	return []ent.Edge{
		// The Root Key that created this User Key
		//
		// This is a many-to-one relationship, as a Root Key can create multiple User Keys
		// but a User Key can only be created by one Root Key
		//
		// This edge is unique but not immutable or required as it is possible to
		// change the Root Key that created a User Key (generally when rotating Root Keys)
		edge.From("root_key", RootKey.Type).Ref("user_keys").Unique(),

		// The Authorities that were created using this User Key
		//
		// This is a one-to-many relationship, as a User Key can create multiple Authorities
		// but an Authority can only be created by one User Key
		edge.To("authorities", Authority.Type),
	}
}
