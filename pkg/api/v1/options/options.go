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

package options

import (
	"github.com/loopholelabs/endkey/internal/database"
	"github.com/loopholelabs/endkey/pkg/api/authorization"
)

type Options struct {
	identifier string
	database   *database.Database
	auth       *authorization.Authorization
}

func New(identifier string, database *database.Database, auth *authorization.Authorization) *Options {
	options := &Options{
		identifier: identifier,
		database:   database,
		auth:       auth,
	}
	return options
}

func (o *Options) Identifier() string {
	return o.identifier
}

func (o *Options) Database() *database.Database {
	return o.database
}

func (o *Options) Auth() *authorization.Authorization {
	return o.auth
}
