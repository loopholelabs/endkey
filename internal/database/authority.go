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
	"github.com/loopholelabs/endkey/internal/aes"
	"github.com/loopholelabs/endkey/internal/ent"
	"github.com/loopholelabs/endkey/internal/ent/authority"
	"github.com/loopholelabs/endkey/internal/ent/userkey"
)

var (
	AESECDSAPrivateKeyHeader = []byte("ECDSA-PRIVATE-KEY")
)

func (d *Database) CreateAuthority(ctx context.Context, name string, uk *ent.UserKey, caPem []byte, privateKey []byte) (*ent.Authority, error) {
	id := uuid.New().String()
	encrypted, err := aes.Encrypt(d.options.EncryptionKey, AESECDSAPrivateKeyHeader, privateKey)
	if err != nil {
		return nil, err
	}

	a, err := d.sql.Authority.Create().SetID(id).SetName(name).SetCaCertificatePem(caPem).SetEncryptedPrivateKey(encrypted).SetUserKey(uk).Save(ctx)
	if err != nil {
		if ent.IsConstraintError(err) {
			return nil, ErrAlreadyExists
		}
		return nil, err
	}

	return a, nil
}

func (d *Database) GetAuthorityByName(ctx context.Context, name string, uk *ent.UserKey) (*ent.Authority, error) {
	a, err := d.sql.Authority.Query().Where(authority.Name(name), authority.HasUserKeyWith(userkey.ID(uk.ID))).Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, ErrNotFound
		}
		return nil, err
	}

	return a, nil
}

func (d *Database) ListAuthorities(ctx context.Context, uk *ent.UserKey) (ent.Authorities, error) {
	as, err := d.sql.Authority.Query().Where(authority.HasUserKeyWith(userkey.ID(uk.ID))).All(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, ErrNotFound
		}
		return nil, err
	}

	return as, nil
}

func (d *Database) DeleteAuthorityByName(ctx context.Context, name string, uk *ent.UserKey) error {
	_, err := d.sql.Authority.Delete().Where(authority.Name(name), authority.HasUserKeyWith(userkey.ID(uk.ID))).Exec(ctx)
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
