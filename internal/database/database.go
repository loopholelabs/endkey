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
	"database/sql"
	"entgo.io/ent/dialect"
	entSQL "entgo.io/ent/dialect/sql"
	"errors"
	"fmt"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/loopholelabs/endkey/internal/ent"
	"github.com/rs/zerolog"
	"sync"
	"time"
)

var (
	ErrNotFound      = errors.New("entity not found")
	ErrAlreadyExists = errors.New("entity already exists")
)

var (
	zeroTime           time.Time
	emptyEncryptionKey = [32]byte{}
)

type Options struct {
	URL                   string
	EncryptionKey         [32]byte
	PreviousEncryptionKey [32]byte
}

type Database struct {
	logger  *zerolog.Logger
	options *Options

	sql *ent.Client

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

func New(options *Options, logger *zerolog.Logger) (*Database, error) {
	l := logger.With().Str("ENDKEY", "DATABASE").Logger()

	l.Debug().Msgf("connecting to %s", options.URL)
	db, err := sql.Open("pgx", options.URL)
	if err != nil {
		return nil, fmt.Errorf("failed opening connection to postgres: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	sqlClient := ent.NewClient(ent.Driver(entSQL.OpenDB(dialect.Postgres, db)))
	l.Info().Msg("running database migrations")
	err = sqlClient.Schema.Create(ctx)
	if err != nil {
		cancel()
		_ = sqlClient.Close()
		return nil, fmt.Errorf("failed to run database migrations: %w", err)
	}

	d := &Database{
		logger:  &l,
		options: options,
		sql:     sqlClient,
		ctx:     ctx,
		cancel:  cancel,
	}

	rk, secret, err := d.CreateRootKey(ctx, true)
	if err != nil {
		if !errors.Is(err, ErrAlreadyExists) {
			cancel()
			_ = sqlClient.Close()
			return nil, fmt.Errorf("failed to create boostrap root key: %w", err)
		}

		d.logger.Info().Msg("found existing bootstrap root key")
	} else {
		d.logger.Info().Msgf("created bootstrap root key with identifier %s and secret %s (this will not be shown again)", rk.Identifier, string(secret))
	}

	return d, nil
}

// Shutdown shuts down the database as gracefully as possible.
//
// This includes cancelling the context, closing the ent client, closing the etcd client, and closing the s3 client.
func (d *Database) Shutdown() error {
	if d.cancel != nil {
		d.cancel()
	}

	if d.sql != nil {
		err := d.sql.Close()
		if err != nil {
			return fmt.Errorf("failed to close ent client: %w", err)
		}
	}

	d.wg.Wait()

	return nil
}
