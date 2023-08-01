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
	"github.com/loopholelabs/endkey/internal/ent/clienttemplate"
	"github.com/loopholelabs/endkey/internal/ent/servertemplate"
	"golang.org/x/crypto/bcrypt"
)

func (d *Database) GetAPIKey(ctx context.Context, identifier string) (*ent.APIKey, error) {
	ak, err := d.sql.APIKey.Query().Where(apikey.Identifier(identifier)).WithAuthority().WithClientTemplate().WithServerTemplate().Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, ErrNotFound
		}
		return nil, err
	}

	return ak, nil
}

func (d *Database) CreateAPIKey(ctx context.Context, name string, authorityID string, serverTemplateID string, clientTemplateID string) (*ent.APIKey, []byte, error) {
	identifier := uuid.New().String()
	secret := []byte(uuid.New().String())
	salt := []byte(uuid.New().String())
	hash, err := bcrypt.GenerateFromPassword(append(salt, secret...), bcrypt.DefaultCost)
	if err != nil {
		return nil, nil, err
	}

	auth, err := d.sql.Authority.Query().Where(authority.Identifier(authorityID)).Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, nil, ErrNotFound
		}
		return nil, nil, err
	}

	akBuilder := d.sql.APIKey.Create().SetIdentifier(identifier).SetName(name).SetHash(hash).SetSalt(salt).SetAuthority(auth)

	if serverTemplateID != "" {
		st, err := d.sql.ServerTemplate.Query().Where(servertemplate.Identifier(serverTemplateID)).Only(ctx)
		if err != nil {
			if ent.IsNotFound(err) {
				return nil, nil, ErrNotFound
			}
			return nil, nil, err
		}
		akBuilder = akBuilder.SetServerTemplate(st)
	}

	if clientTemplateID != "" {
		ct, err := d.sql.ClientTemplate.Query().Where(clienttemplate.Identifier(clientTemplateID)).Only(ctx)
		if err != nil {
			if ent.IsNotFound(err) {
				return nil, nil, ErrNotFound
			}
			return nil, nil, err
		}
		akBuilder = akBuilder.SetClientTemplate(ct)
	}

	ak, err := akBuilder.Save(ctx)
	if err != nil {
		if ent.IsConstraintError(err) {
			return nil, nil, ErrAlreadyExists
		}
		return nil, nil, err
	}

	return ak, secret, nil
}
