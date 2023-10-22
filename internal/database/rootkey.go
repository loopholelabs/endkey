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
	"fmt"
	"github.com/google/uuid"
	"github.com/loopholelabs/endkey/internal/ent"
	"github.com/loopholelabs/endkey/internal/ent/rootkey"
	"golang.org/x/crypto/bcrypt"
)

func (d *Database) CreateRootKey(ctx context.Context, name string) (*ent.RootKey, []byte, error) {
	id := uuid.New().String()
	secret := []byte(uuid.New().String())
	salt := []byte(uuid.New().String())
	hash, err := bcrypt.GenerateFromPassword(append(salt, secret...), bcrypt.DefaultCost)
	if err != nil {
		return nil, nil, err
	}

	rk, err := d.sql.RootKey.Create().SetID(id).SetName(name).SetHash(hash).SetSalt(salt).Save(ctx)
	if err != nil {
		if ent.IsConstraintError(err) {
			return nil, nil, ErrAlreadyExists
		}
		return nil, nil, err
	}

	return rk, secret, nil
}

func (d *Database) RotateRootKeyByName(ctx context.Context, name string) (*ent.RootKey, []byte, error) {
	id := uuid.New().String()
	secret := []byte(uuid.New().String())
	salt := []byte(uuid.New().String())
	hash, err := bcrypt.GenerateFromPassword(append(salt, secret...), bcrypt.DefaultCost)
	if err != nil {
		return nil, nil, err
	}

	tx, err := d.sql.Tx(ctx)
	if err != nil {
		return nil, nil, err
	}

	oldRk, err := tx.RootKey.Query().Where(rootkey.Name(name)).WithUserKeys().Only(ctx)
	if err != nil {
		rollbackErr := tx.Rollback()
		if rollbackErr != nil {
			return nil, nil, fmt.Errorf("failed to rollback transaction during error %w: %w", err, rollbackErr)
		}
		return nil, nil, err
	}

	uks, err := oldRk.Edges.UserKeysOrErr()
	if err != nil {
		rollbackErr := tx.Rollback()
		if rollbackErr != nil {
			return nil, nil, fmt.Errorf("failed to rollback transaction during error %w: %w", err, rollbackErr)
		}
		return nil, nil, err
	}

	_, err = tx.RootKey.Delete().Where(rootkey.Name(name)).Exec(ctx)
	if err != nil {
		rollbackErr := tx.Rollback()
		if rollbackErr != nil {
			return nil, nil, fmt.Errorf("failed to rollback transaction during error %w: %w", err, rollbackErr)
		}
		return nil, nil, err
	}

	rk, err := tx.RootKey.Create().SetID(id).SetName(name).SetHash(hash).SetSalt(salt).AddUserKeys(uks...).Save(ctx)
	if err != nil {
		rollbackErr := tx.Rollback()
		if rollbackErr != nil {
			return nil, nil, fmt.Errorf("failed to rollback transaction during error %w: %w", err, rollbackErr)
		}
		return nil, nil, err
	}

	err = tx.Commit()
	if err != nil {
		return nil, nil, err
	}

	return rk, secret, nil
}

func (d *Database) GetRootKeyByID(ctx context.Context, id string) (*ent.RootKey, error) {
	rk, err := d.sql.RootKey.Query().Where(rootkey.ID(id)).WithUserKeys().Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, ErrNotFound
		}
		return nil, err
	}

	return rk, nil
}

func (d *Database) ListRootKeys(ctx context.Context) (ent.RootKeys, error) {
	rks, err := d.sql.RootKey.Query().All(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, ErrNotFound
		}
		return nil, err
	}

	return rks, nil
}

func (d *Database) DeleteRootKeyByName(ctx context.Context, name string) error {
	n, err := d.sql.RootKey.Delete().Where(rootkey.Name(name)).Exec(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return ErrNotFound
		}

		if ent.IsConstraintError(err) {
			return ErrAlreadyExists
		}

		return err
	}

	if n == 0 {
		return ErrNotFound
	}

	return nil
}
