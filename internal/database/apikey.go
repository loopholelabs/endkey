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
	"github.com/loopholelabs/endkey/internal/ent/apikey"
	"github.com/loopholelabs/endkey/internal/ent/authority"
	"github.com/loopholelabs/endkey/internal/ent/template"
	"github.com/loopholelabs/endkey/internal/ent/userkey"
	"golang.org/x/crypto/bcrypt"
)

func (d *Database) CreateAPIKey(ctx context.Context, name string, authorityName string, uk *ent.UserKey, templateName string) (*ent.APIKey, []byte, error) {
	id := uuid.New().String()
	secret := []byte(uuid.New().String())
	salt := []byte(uuid.New().String())
	hash, err := bcrypt.GenerateFromPassword(append(salt, secret...), bcrypt.DefaultCost)
	if err != nil {
		return nil, nil, err
	}

	auth, err := d.sql.Authority.Query().Where(authority.Name(authorityName), authority.HasUserKeyWith(userkey.ID(uk.ID))).Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, nil, ErrNotFound
		}
		return nil, nil, err
	}

	templ, err := d.sql.Template.Query().Where(template.Name(templateName)).Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, nil, ErrNotFound
		}
		return nil, nil, err
	}

	ak, err := d.sql.APIKey.Create().SetID(id).SetName(name).SetHash(hash).SetSalt(salt).SetAuthority(auth).SetTemplate(templ).Save(ctx)
	if err != nil {
		if ent.IsConstraintError(err) {
			return nil, nil, ErrAlreadyExists
		}
		return nil, nil, err
	}

	return ak, secret, nil
}

func (d *Database) GetAPIKeyByID(ctx context.Context, id string) (*ent.APIKey, error) {
	ak, err := d.sql.APIKey.Query().Where(apikey.ID(id)).WithAuthority().WithTemplate().Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, ErrNotFound
		}
		return nil, err
	}

	return ak, nil
}

func (d *Database) ListAPIKeys(ctx context.Context, authorityName string, uk *ent.UserKey) (ent.APIKeys, error) {
	aks, err := d.sql.APIKey.Query().Where(apikey.HasAuthorityWith(authority.Name(authorityName), authority.HasUserKeyWith(userkey.ID(uk.ID)))).WithTemplate().All(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, ErrNotFound
		}
		return nil, err
	}

	return aks, nil
}

func (d *Database) DeleteAPIKeyByName(ctx context.Context, name string, authorityName string, uk *ent.UserKey) error {
	n, err := d.sql.APIKey.Delete().Where(apikey.Name(name), apikey.HasAuthorityWith(authority.Name(authorityName), authority.HasUserKeyWith(userkey.ID(uk.ID)))).Exec(ctx)
	if err != nil {
		if ent.IsNotFound(err) || n == 0 {
			return ErrNotFound
		}

		if ent.IsConstraintError(err) {
			return ErrAlreadyExists
		}

		return err
	}

	return nil
}
