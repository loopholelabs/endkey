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
)

func (d *Database) CreateTemplate(ctx context.Context, name string, authorityName string, uk *ent.UserKey, commonName string, tag string, dnsNames []string, additionalDNS bool, IPs []string, additionalIPs bool, validity string, client bool, server bool) (*ent.Template, error) {
	id := uuid.New().String()
	auth, err := d.sql.Authority.Query().Where(authority.Name(authorityName), authority.HasUserKeyWith(userkey.ID(uk.ID))).Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, ErrNotFound
		}
		return nil, err
	}

	templ, err := d.sql.Template.Create().SetID(id).SetName(name).SetAuthority(auth).SetCommonName(commonName).SetTag(tag).SetDNSNames(dnsNames).SetAllowAdditionalDNSNames(additionalDNS).SetIPAddresses(IPs).SetAllowAdditionalIps(additionalIPs).SetValidity(validity).SetClient(client).SetServer(server).Save(ctx)
	if err != nil {
		if ent.IsConstraintError(err) {
			return nil, ErrAlreadyExists
		}
		return nil, err
	}

	return templ, nil
}

func (d *Database) GetTemplateByNameAndUserKey(ctx context.Context, name string, authorityName string, uk *ent.UserKey) (*ent.Template, error) {
	templ, err := d.sql.Template.Query().Where(template.Name(name), template.HasAuthorityWith(authority.Name(authorityName), authority.HasUserKeyWith(userkey.ID(uk.ID)))).Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, ErrNotFound
		}
		return nil, err
	}

	return templ, nil
}

func (d *Database) GetTemplateByAPIKey(ctx context.Context, name string, ak *ent.APIKey) (*ent.Template, error) {
	templ, err := d.sql.Template.Query().Where(template.Name(name), template.HasAuthorityWith(authority.HasAPIKeysWith(apikey.ID(ak.ID)))).Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, ErrNotFound
		}
		return nil, err
	}

	return templ, nil
}

func (d *Database) ListTemplates(ctx context.Context, authorityName string, uk *ent.UserKey) (ent.Templates, error) {
	templs, err := d.sql.Template.Query().Where(template.HasAuthorityWith(authority.Name(authorityName), authority.HasUserKeyWith(userkey.ID(uk.ID)))).All(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, ErrNotFound
		}
		return nil, err
	}

	return templs, nil
}

func (d *Database) DeleteTemplateByName(ctx context.Context, name string, authorityName string, uk *ent.UserKey) error {
	templ, err := d.sql.Template.Query().Where(template.Name(name), template.HasAuthorityWith(authority.Name(authorityName), authority.HasUserKeyWith(userkey.ID(uk.ID)))).WithAPIKeys().Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return ErrNotFound
		}
		return err
	}

	aks, err := templ.Edges.APIKeysOrErr()
	if err == nil && len(aks) > 0 {
		return ErrAlreadyExists
	}

	err = d.sql.Template.DeleteOne(templ).Exec(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return ErrNotFound
		}

		if ent.IsConstraintError(err) {
			return ErrAlreadyExists
		}

		return err
	}

	return nil
}
