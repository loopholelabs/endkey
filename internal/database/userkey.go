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
	"github.com/loopholelabs/endkey/internal/ent/userkey"
	"golang.org/x/crypto/bcrypt"
)

func (d *Database) CreateUserKey(ctx context.Context, name string, rk *ent.RootKey) (*ent.UserKey, []byte, error) {
	id := uuid.New().String()
	secret := []byte(uuid.New().String())
	salt := []byte(uuid.New().String())
	hash, err := bcrypt.GenerateFromPassword(append(salt, secret...), bcrypt.DefaultCost)
	if err != nil {
		return nil, nil, err
	}

	uk, err := d.sql.UserKey.Create().SetID(id).SetName(name).SetHash(hash).SetSalt(salt).SetRootKey(rk).Save(ctx)
	if err != nil {
		if ent.IsConstraintError(err) {
			return nil, nil, ErrAlreadyExists
		}
		return nil, nil, err
	}

	return uk, secret, nil
}

func (d *Database) RotateUserKeyByName(ctx context.Context, name string) (*ent.UserKey, []byte, error) {
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

	oldUk, err := tx.UserKey.Query().Where(userkey.Name(name)).WithRootKey().WithAuthorities().Only(ctx)
	if err != nil {
		rollbackErr := tx.Rollback()
		if rollbackErr != nil {
			return nil, nil, fmt.Errorf("failed to rollback transaction during error %w: %w", err, rollbackErr)
		}
		return nil, nil, err
	}

	rk, err := oldUk.Edges.RootKeyOrErr()
	if err != nil {
		rollbackErr := tx.Rollback()
		if rollbackErr != nil {
			return nil, nil, fmt.Errorf("failed to rollback transaction during error %w: %w", err, rollbackErr)
		}
		return nil, nil, err
	}

	authorities, err := oldUk.Edges.AuthoritiesOrErr()
	if err != nil {
		rollbackErr := tx.Rollback()
		if rollbackErr != nil {
			return nil, nil, fmt.Errorf("failed to rollback transaction during error %w: %w", err, rollbackErr)
		}
		return nil, nil, err
	}

	_, err = tx.UserKey.Delete().Where(userkey.Name(name)).Exec(ctx)
	if err != nil {
		rollbackErr := tx.Rollback()
		if rollbackErr != nil {
			return nil, nil, fmt.Errorf("failed to rollback transaction during error %w: %w", err, rollbackErr)
		}
		return nil, nil, err
	}

	uk, err := tx.UserKey.Create().SetID(id).SetName(name).SetHash(hash).SetSalt(salt).SetRootKey(rk).AddAuthorities(authorities...).Save(ctx)
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

	return uk, secret, nil
}

func (d *Database) GetUserKeyByID(ctx context.Context, id string) (*ent.UserKey, error) {
	uk, err := d.sql.UserKey.Query().Where(userkey.ID(id)).WithAuthorities().Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, ErrNotFound
		}
		return nil, err
	}

	return uk, nil
}

func (d *Database) ListUserKeys(ctx context.Context) (ent.UserKeys, error) {
	uks, err := d.sql.UserKey.Query().All(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, ErrNotFound
		}
		return nil, err
	}

	return uks, nil
}

func (d *Database) DeleteUserKeyByName(ctx context.Context, name string) error {
	_, err := d.sql.UserKey.Delete().Where(userkey.Name(name)).Exec(ctx)
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
