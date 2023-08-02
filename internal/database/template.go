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
	"github.com/loopholelabs/endkey/internal/ent"
	"github.com/loopholelabs/endkey/internal/ent/authority"
	"github.com/loopholelabs/endkey/internal/ent/clienttemplate"
	"github.com/loopholelabs/endkey/internal/ent/servertemplate"
)

func (d *Database) CreateServerTemplate(ctx context.Context, identifier string, authorityID string, commonName string, tag string, dnsNames []string, additionalDNS bool, IPs []string, additionalIPs bool, validity string) (*ent.ServerTemplate, error) {
	auth, err := d.sql.Authority.Query().Where(authority.Identifier(authorityID)).Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, ErrNotFound
		}
		return nil, err
	}

	templ, err := d.sql.ServerTemplate.Create().SetIdentifier(identifier).SetAuthority(auth).SetCommonName(commonName).SetTag(tag).SetDNSNames(dnsNames).SetAllowAdditionalDNSNames(additionalDNS).SetIPAddresses(IPs).SetAllowAdditionalIps(additionalIPs).SetValidity(validity).Save(ctx)
	if err != nil {
		if ent.IsConstraintError(err) {
			return nil, ErrAlreadyExists
		}
		return nil, err
	}

	return templ, nil
}

func (d *Database) GetServerTemplate(ctx context.Context, identifier string, authorityID string) (*ent.ServerTemplate, error) {
	templ, err := d.sql.ServerTemplate.Query().Where(servertemplate.Identifier(identifier), servertemplate.HasAuthorityWith(authority.Identifier(authorityID))).Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, ErrNotFound
		}
		return nil, err
	}

	return templ, nil
}

func (d *Database) ListServerTemplates(ctx context.Context, authorityID string) (ent.ServerTemplates, error) {
	templs, err := d.sql.ServerTemplate.Query().Where(servertemplate.HasAuthorityWith(authority.Identifier(authorityID))).All(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, ErrNotFound
		}
		return nil, err
	}

	return templs, nil
}

func (d *Database) DeleteServerTemplate(ctx context.Context, identifier string, authorityID string) error {
	_, err := d.sql.ServerTemplate.Delete().Where(servertemplate.Identifier(identifier), servertemplate.HasAuthorityWith(authority.Identifier(authorityID))).Exec(ctx)
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

func (d *Database) CreateClientTemplate(ctx context.Context, identifier string, authorityID string, commonName string, tag string, dnsNames []string, additionalDNS bool, IPs []string, additionalIPs bool, validity string) (*ent.ClientTemplate, error) {
	auth, err := d.sql.Authority.Query().Where(authority.Identifier(authorityID)).Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, ErrNotFound
		}
		return nil, err
	}

	templ, err := d.sql.ClientTemplate.Create().SetIdentifier(identifier).SetAuthority(auth).SetCommonName(commonName).SetTag(tag).SetDNSNames(dnsNames).SetAllowAdditionalDNSNames(additionalDNS).SetIPAddresses(IPs).SetAllowAdditionalIps(additionalIPs).SetValidity(validity).Save(ctx)
	if err != nil {
		if ent.IsConstraintError(err) {
			return nil, ErrAlreadyExists
		}
		return nil, err
	}

	return templ, nil
}

func (d *Database) GetClientTemplate(ctx context.Context, identifier string, authorityID string) (*ent.ClientTemplate, error) {
	templ, err := d.sql.ClientTemplate.Query().Where(clienttemplate.Identifier(identifier), clienttemplate.HasAuthorityWith(authority.Identifier(authorityID))).Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, ErrNotFound
		}
		return nil, err
	}

	return templ, nil
}

func (d *Database) ListClientTemplates(ctx context.Context, authorityID string) (ent.ClientTemplates, error) {
	templs, err := d.sql.ClientTemplate.Query().Where(clienttemplate.HasAuthorityWith(authority.Identifier(authorityID))).All(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, ErrNotFound
		}
		return nil, err
	}

	return templs, nil
}

func (d *Database) DeleteClientTemplate(ctx context.Context, identifier string, authorityID string) error {
	_, err := d.sql.ClientTemplate.Delete().Where(clienttemplate.Identifier(identifier), clienttemplate.HasAuthorityWith(authority.Identifier(authorityID))).Exec(ctx)
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
