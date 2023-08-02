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
	"entgo.io/ent/schema/field"
	"time"
)

// RootKey holds the schema definition for the RootKey entity.
//
// A RootKey is a Root Key used to authenticate with the API for the purposes of
// creating new Authority entities and issuing API Keys scoped to them.
type RootKey struct {
	ent.Schema
}

// Fields of the RootKey.
func (RootKey) Fields() []ent.Field {
	return []ent.Field{
		// When the Root Key was created, immutable
		field.Time("created_at").Immutable().Default(time.Now),

		// A unique identifier for the Root Key, immutable, globally unique
		field.String("identifier").NotEmpty().Unique().Immutable(),

		// An easily recognizable name for the Root Key, immutable
		//
		// If this is the Bootstrap Root Key, it's name will be set to "bootstrap"
		// and it will not be possible to delete or change it. This is to ensure
		// that there is always at least one Root Key in the system.
		field.String("name").NotEmpty().Immutable().Unique(),

		// A randomly generated salt for the Root Key, immutable
		field.Bytes("salt").NotEmpty().Immutable(),

		// The hashed RootKey secret and salt
		//
		// The secret is never stored, and the salt is immutable
		field.Bytes("hash").NotEmpty().Immutable(),
	}
}

// Edges of the RootKey.
func (RootKey) Edges() []ent.Edge {
	return []ent.Edge{}
}
