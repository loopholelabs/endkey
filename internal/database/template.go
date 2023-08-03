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
	"github.com/loopholelabs/endkey/internal/ent/userkey"
)

func (d *Database) CreateServerTemplate(ctx context.Context, name string, authorityName string, uk *ent.UserKey, commonName string, tag string, dnsNames []string, additionalDNS bool, IPs []string, additionalIPs bool, validity string) (*ent.ServerTemplate, error) {
	id := uuid.New().String()
	auth, err := d.sql.Authority.Query().Where(authority.Name(authorityName), authority.HasUserKeyWith(userkey.ID(uk.ID))).Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, ErrNotFound
		}
		return nil, err
	}

	templ, err := d.sql.ServerTemplate.Create().SetID(id).SetName(name).SetAuthority(auth).SetCommonName(commonName).SetTag(tag).SetDNSNames(dnsNames).SetAllowAdditionalDNSNames(additionalDNS).SetIPAddresses(IPs).SetAllowAdditionalIps(additionalIPs).SetValidity(validity).Save(ctx)
	if err != nil {
		if ent.IsConstraintError(err) {
			return nil, ErrAlreadyExists
		}
		return nil, err
	}

	return templ, nil
}

func (d *Database) GetServerTemplateByNameAndUserKey(ctx context.Context, name string, authorityName string, uk *ent.UserKey) (*ent.ServerTemplate, error) {
	templ, err := d.sql.ServerTemplate.Query().Where(servertemplate.Name(name), servertemplate.HasAuthorityWith(authority.Name(authorityName), authority.HasUserKeyWith(userkey.ID(uk.ID)))).Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, ErrNotFound
		}
		return nil, err
	}

	return templ, nil
}

func (d *Database) GetServerTemplateByAPIKey(ctx context.Context, name string, ak *ent.APIKey) (*ent.ServerTemplate, error) {
	templ, err := d.sql.ServerTemplate.Query().Where(servertemplate.Name(name), servertemplate.HasAuthorityWith(authority.HasAPIKeysWith(apikey.ID(ak.ID)))).Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, ErrNotFound
		}
		return nil, err
	}

	return templ, nil
}

func (d *Database) ListServerTemplates(ctx context.Context, authorityName string, uk *ent.UserKey) (ent.ServerTemplates, error) {
	templs, err := d.sql.ServerTemplate.Query().Where(servertemplate.HasAuthorityWith(authority.Name(authorityName), authority.HasUserKeyWith(userkey.ID(uk.ID)))).All(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, ErrNotFound
		}
		return nil, err
	}

	return templs, nil
}

func (d *Database) DeleteServerTemplateByName(ctx context.Context, name string, authorityName string, uk *ent.UserKey) error {
	_, err := d.sql.ServerTemplate.Delete().Where(servertemplate.Name(name), servertemplate.HasAuthorityWith(authority.Name(authorityName), authority.HasUserKeyWith(userkey.ID(uk.ID)))).Exec(ctx)
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

func (d *Database) CreateClientTemplate(ctx context.Context, name string, authorityName string, uk *ent.UserKey, commonName string, tag string, dnsNames []string, additionalDNS bool, IPs []string, additionalIPs bool, validity string) (*ent.ClientTemplate, error) {
	id := uuid.New().String()
	auth, err := d.sql.Authority.Query().Where(authority.Name(authorityName), authority.HasUserKeyWith(userkey.ID(uk.ID))).Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, ErrNotFound
		}
		return nil, err
	}

	templ, err := d.sql.ClientTemplate.Create().SetID(id).SetName(name).SetAuthority(auth).SetCommonName(commonName).SetTag(tag).SetDNSNames(dnsNames).SetAllowAdditionalDNSNames(additionalDNS).SetIPAddresses(IPs).SetAllowAdditionalIps(additionalIPs).SetValidity(validity).Save(ctx)
	if err != nil {
		if ent.IsConstraintError(err) {
			return nil, ErrAlreadyExists
		}
		return nil, err
	}

	return templ, nil
}

func (d *Database) GetClientTemplateByNameAndUserKey(ctx context.Context, name string, authorityName string, uk *ent.UserKey) (*ent.ClientTemplate, error) {
	templ, err := d.sql.ClientTemplate.Query().Where(clienttemplate.Name(name), clienttemplate.HasAuthorityWith(authority.Name(authorityName), authority.HasUserKeyWith(userkey.ID(uk.ID)))).Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, ErrNotFound
		}
		return nil, err
	}

	return templ, nil
}

func (d *Database) GetClientTemplateByAPIKey(ctx context.Context, name string, ak *ent.APIKey) (*ent.ClientTemplate, error) {
	templ, err := d.sql.ClientTemplate.Query().Where(clienttemplate.Name(name), clienttemplate.HasAuthorityWith(authority.HasAPIKeysWith(apikey.ID(ak.ID)))).Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, ErrNotFound
		}
		return nil, err
	}

	return templ, nil
}

func (d *Database) ListClientTemplates(ctx context.Context, authorityName string, uk *ent.UserKey) (ent.ClientTemplates, error) {
	templs, err := d.sql.ClientTemplate.Query().Where(clienttemplate.HasAuthorityWith(authority.Name(authorityName), authority.HasUserKeyWith(userkey.ID(uk.ID)))).All(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, ErrNotFound
		}
		return nil, err
	}

	return templs, nil
}

func (d *Database) DeleteClientTemplateByName(ctx context.Context, name string, authorityName string, uk *ent.UserKey) error {
	_, err := d.sql.ClientTemplate.Delete().Where(clienttemplate.Name(name), clienttemplate.HasAuthorityWith(authority.Name(authorityName), authority.HasUserKeyWith(userkey.ID(uk.ID)))).Exec(ctx)
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
