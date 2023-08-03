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

package authorization

import (
	"bytes"
	"errors"
	"github.com/gofiber/fiber/v2"
	"github.com/loopholelabs/endkey/internal/database"
	"github.com/loopholelabs/endkey/internal/ent"
	"github.com/loopholelabs/endkey/internal/key"
	"github.com/loopholelabs/endkey/internal/metrics"
	"github.com/rs/zerolog"
	"golang.org/x/crypto/bcrypt"
)

var (
	authMetric = metrics.NewStatusMetric("auth_total", "The total number of authentication calls")
)

const (
	KindContext = "kind"
	KeyContext  = "key"
)

type Kind string

const (
	RootKey    Kind = "root"
	UserKey    Kind = "user"
	APIKeyKind Kind = "api"
)

const (
	HeaderString = "Authorization"
	BearerString = "Bearer "
)

var (
	Header = []byte(HeaderString)
	Bearer = []byte(BearerString)
)

type Authorization struct {
	logger *zerolog.Logger
	db     *database.Database
}

func New(logger *zerolog.Logger, db *database.Database) *Authorization {
	l := logger.With().Str("MIDDLEWARE", "AUTHORIZATION").Logger()
	return &Authorization{
		logger: &l,
		db:     db,
	}
}

func (v *Authorization) getHeader(ctx *fiber.Ctx) ([]byte, error) {
	authHeader := ctx.Request().Header.PeekBytes(Header)
	if authHeader == nil {
		return nil, authMetric.Error(fiber.StatusUnauthorized, "invalid authorization header")
	}

	if !bytes.Equal(authHeader[:len(Bearer)], Bearer) {
		return nil, authMetric.Error(fiber.StatusUnauthorized, "invalid authorization header")
	}

	return authHeader[len(Bearer):], nil
}

func (v *Authorization) RootKeyValidate(ctx *fiber.Ctx) error {
	header, err := v.getHeader(ctx)
	if err != nil {
		return err
	}

	if !bytes.HasPrefix(header, key.RootPrefix) {
		return authMetric.Error(fiber.StatusUnauthorized, "invalid authorization header")
	}

	rkSplit := bytes.Split(header[len(key.RootPrefix):], key.Delimiter)
	if len(rkSplit) != 2 {
		return authMetric.Error(fiber.StatusUnauthorized, "invalid authorization header")
	}

	rkID := string(rkSplit[0])
	rkSecret := rkSplit[1]

	rk, err := v.db.GetRootKeyByID(ctx.Context(), rkID)
	if err != nil {
		if errors.Is(err, database.ErrNotFound) {
			return authMetric.Error(fiber.StatusUnauthorized, "invalid authorization header")
		}
		v.logger.Error().Err(err).Msg("failed to get root key")
		return authMetric.Error(fiber.StatusInternalServerError, "unable to validate authorization header")
	}

	if bcrypt.CompareHashAndPassword(rk.Hash, append(rk.Salt, rkSecret...)) != nil {
		return authMetric.Error(fiber.StatusUnauthorized, "invalid authorization header")
	}

	ctx.Locals(KindContext, RootKey)
	ctx.Locals(KeyContext, rk)
	return ctx.Next()
}

func (v *Authorization) UserKeyValidate(ctx *fiber.Ctx) error {
	header, err := v.getHeader(ctx)
	if err != nil {
		return err
	}

	if !bytes.HasPrefix(header, key.UserPrefix) {
		return authMetric.Error(fiber.StatusUnauthorized, "invalid authorization header")
	}

	ukSplit := bytes.Split(header[len(key.UserPrefix):], key.Delimiter)
	if len(ukSplit) != 2 {
		return authMetric.Error(fiber.StatusUnauthorized, "invalid authorization header")
	}

	ukID := string(ukSplit[0])
	ukSecret := ukSplit[1]

	uk, err := v.db.GetUserKeyByID(ctx.Context(), ukID)
	if err != nil {
		if errors.Is(err, database.ErrNotFound) {
			return authMetric.Error(fiber.StatusUnauthorized, "invalid authorization header")
		}
		v.logger.Error().Err(err).Msg("failed to get user key")
		return authMetric.Error(fiber.StatusInternalServerError, "unable to validate authorization header")
	}

	if bcrypt.CompareHashAndPassword(uk.Hash, append(uk.Salt, ukSecret...)) != nil {
		return authMetric.Error(fiber.StatusUnauthorized, "invalid authorization header")
	}

	ctx.Locals(KindContext, UserKey)
	ctx.Locals(KeyContext, uk)
	return ctx.Next()
}

func (v *Authorization) APIKeyValidate(ctx *fiber.Ctx) error {
	header, err := v.getHeader(ctx)
	if err != nil {
		return err
	}

	if !bytes.HasPrefix(header, key.APIPrefix) {
		return authMetric.Error(fiber.StatusUnauthorized, "invalid authorization header")
	}

	akSplit := bytes.Split(header[len(key.APIPrefix):], key.Delimiter)
	if len(akSplit) != 2 {
		return authMetric.Error(fiber.StatusUnauthorized, "invalid authorization header")
	}

	akID := string(akSplit[0])
	akSecret := akSplit[1]

	ak, err := v.db.GetAPIKeyByID(ctx.Context(), akID)
	if err != nil {
		if errors.Is(err, database.ErrNotFound) {
			return authMetric.Error(fiber.StatusUnauthorized, "invalid authorization header")
		}
		v.logger.Error().Err(err).Msg("failed to get api key")
		return authMetric.Error(fiber.StatusInternalServerError, "unable to validate authorization header")
	}

	if bcrypt.CompareHashAndPassword(ak.Hash, append(ak.Salt, akSecret...)) != nil {
		return authMetric.Error(fiber.StatusUnauthorized, "invalid authorization header")
	}

	ctx.Locals(KindContext, APIKeyKind)
	ctx.Locals(KeyContext, ak)
	return ctx.Next()
}

func GetRootKey(ctx *fiber.Ctx) (*ent.RootKey, error) {
	kind, ok := ctx.Locals(KindContext).(Kind)
	if !ok {
		return nil, errors.New("could not find key kind")
	}

	switch kind {
	case RootKey:
		rk, ok := ctx.Locals(KeyContext).(*ent.RootKey)
		if !ok {
			return nil, errors.New("could not find root key")
		}
		return rk, nil
	default:
		return nil, errors.New("invalid key kind")
	}
}

func GetUserKey(ctx *fiber.Ctx) (*ent.UserKey, error) {
	kind, ok := ctx.Locals(KindContext).(Kind)
	if !ok {
		return nil, errors.New("could not find key kind")
	}

	switch kind {
	case UserKey:
		uk, ok := ctx.Locals(KeyContext).(*ent.UserKey)
		if !ok {
			return nil, errors.New("could not find user key")
		}
		return uk, nil
	default:
		return nil, errors.New("invalid key kind")
	}
}

func GetAPIKey(ctx *fiber.Ctx) (*ent.APIKey, error) {
	kind, ok := ctx.Locals(KindContext).(Kind)
	if !ok {
		return nil, errors.New("could not find key kind")
	}

	switch kind {
	case APIKeyKind:
		ak, ok := ctx.Locals(KeyContext).(*ent.APIKey)
		if !ok {
			return nil, errors.New("could not find api key")
		}
		return ak, nil
	default:
		return nil, errors.New("invalid key kind")
	}
}
