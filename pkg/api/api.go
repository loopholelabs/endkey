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

package api

import (
	"context"
	"fmt"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/loopholelabs/endkey/internal/config"
	"github.com/loopholelabs/endkey/internal/database"
	"github.com/loopholelabs/endkey/internal/utils"
	"github.com/loopholelabs/endkey/pkg/api/authorization"
	v1 "github.com/loopholelabs/endkey/pkg/api/v1"
	v1Docs "github.com/loopholelabs/endkey/pkg/api/v1/docs"
	v1Options "github.com/loopholelabs/endkey/pkg/api/v1/options"
	"github.com/rs/zerolog"
	"net"
	"sync"
)

const (
	V1Path = "/v1"
)

type API struct {
	logger *zerolog.Logger
	config *config.Config
	app    *fiber.App

	v1Options *v1Options.Options

	database *database.Database

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

func New(config *config.Config, logger *zerolog.Logger) (*API, error) {
	l := logger.With().Str(zerolog.CallerFieldName, "API").Logger()

	dbOptions := &database.Options{
		URL:           config.DatabaseURL,
		EncryptionKey: [32]byte(config.EncryptionKey),
	}

	if len(config.PreviousEncryptionKey) == 32 {
		dbOptions.PreviousEncryptionKey = [32]byte(config.PreviousEncryptionKey)
	}

	db, err := database.New(dbOptions, &l)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize database: %w", err)
	}

	auth := authorization.New(&l, db)

	v1Opts := v1Options.New(config.Identifier, db, auth)
	ctx, cancel := context.WithCancel(context.Background())

	return &API{
		logger:    &l,
		config:    config,
		app:       utils.DefaultFiberApp(),
		v1Options: v1Opts,
		database:  db,
		ctx:       ctx,
		cancel:    cancel,
	}, nil
}

func (s *API) Start() error {
	listener, err := net.Listen("tcp", s.config.ListenAddress)
	if err != nil {
		return err
	}
	v1Docs.SwaggerInfoapi.Host = s.config.Endpoint
	v1Docs.SwaggerInfoapi.Schemes = []string{"http"}
	if s.config.TLS {
		v1Docs.SwaggerInfoapi.Schemes = []string{"https"}
	}

	s.app.Use(cors.New())
	s.app.Mount(V1Path, v1.New(s.v1Options, s.logger).App())

	return s.app.Listener(listener)
}

func (s *API) Stop() error {
	if s.cancel != nil {
		s.cancel()
	}

	if s.app != nil {
		err := s.app.Shutdown()
		if err != nil {
			return err
		}
	}

	if s.database != nil {
		err := s.database.Shutdown()
		if err != nil {
			return err
		}
	}

	s.wg.Wait()
	return nil
}
