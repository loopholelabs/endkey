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
	"github.com/loopholelabs/endkey/internal/aes"
	"github.com/loopholelabs/endkey/internal/ent"
	"github.com/loopholelabs/endkey/internal/ent/authority"
)

var (
	AESECDSAPrivateKeyHeader = []byte("ECDSA-PRIVATE-KEY")
)

func (d *Database) CreateAuthority(ctx context.Context, identifier string, caPem []byte, privateKey []byte) (*ent.Authority, error) {
	encrypted, err := aes.Encrypt(d.options.EncryptionKey, AESECDSAPrivateKeyHeader, privateKey)
	if err != nil {
		return nil, err
	}

	a, err := d.sql.Authority.Create().SetIdentifier(identifier).SetCaCertificatePem(caPem).SetEncryptedPrivateKey(encrypted).Save(ctx)
	if err != nil {
		if ent.IsConstraintError(err) {
			return nil, ErrAlreadyExists
		}
		return nil, err
	}

	return a, nil
}

func (d *Database) GetAuthority(ctx context.Context, identifier string) (*ent.Authority, error) {
	a, err := d.sql.Authority.Query().Where(authority.Identifier(identifier)).Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, ErrNotFound
		}
		return nil, err
	}

	return a, nil
}

func (d *Database) ListAuthorities(ctx context.Context) (ent.Authorities, error) {
	as, err := d.sql.Authority.Query().All(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, ErrNotFound
		}
		return nil, err
	}

	return as, nil
}

func (d *Database) DeleteAuthority(ctx context.Context, identifier string) error {
	_, err := d.sql.Authority.Delete().Where(authority.Identifier(identifier)).Exec(ctx)
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

func (d *Database) DecryptAuthorityPrivateKey(a *ent.Authority) ([]byte, error) {
	decrypted, err := aes.Decrypt(d.options.EncryptionKey, AESECDSAPrivateKeyHeader, a.EncryptedPrivateKey)
	if err != nil {
		if d.options.PreviousEncryptionKey != emptyEncryptionKey {
			decrypted, err = aes.Decrypt(d.options.PreviousEncryptionKey, AESECDSAPrivateKeyHeader, a.EncryptedPrivateKey)
			if err != nil {
				return nil, err
			}
		} else {
			return nil, err
		}
	}

	return decrypted, nil
}
