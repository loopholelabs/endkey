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

package database

import (
	"context"
	"github.com/google/uuid"
	"github.com/loopholelabs/endkey/internal/ent"
	"github.com/loopholelabs/endkey/internal/ent/rootkey"
	"golang.org/x/crypto/bcrypt"
)

func (d *Database) GetRootKey(ctx context.Context, identifier string) (*ent.RootKey, error) {
	rk, err := d.sql.RootKey.Query().Where(rootkey.Identifier(identifier)).Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, ErrNotFound
		}
		return nil, err
	}

	return rk, nil
}

func (d *Database) CreateRootKey(ctx context.Context, bootstrap bool) (*ent.RootKey, []byte, error) {
	identifier := uuid.New().String()
	secret := []byte(uuid.New().String())
	salt := []byte(uuid.New().String())
	hash, err := bcrypt.GenerateFromPassword(append(salt, secret...), bcrypt.DefaultCost)
	if err != nil {
		return nil, nil, err
	}

	rkBuilder := d.sql.RootKey.Create().SetIdentifier(identifier).SetHash(hash).SetSalt(salt)
	if bootstrap {
		rkBuilder = rkBuilder.SetBootstrap("bootstrap")
	}

	rk, err := rkBuilder.Save(ctx)
	if err != nil {
		if ent.IsConstraintError(err) {
			return nil, nil, ErrAlreadyExists
		}
		return nil, nil, err
	}

	return rk, secret, nil
}
