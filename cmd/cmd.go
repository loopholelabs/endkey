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

package main

import (
	"github.com/loopholelabs/cmdutils/pkg/command"
	"github.com/loopholelabs/endkey/cmd/api"
	"github.com/loopholelabs/endkey/cmd/certificate"
	"github.com/loopholelabs/endkey/cmd/manage"
	"github.com/loopholelabs/endkey/internal/config"
	"github.com/loopholelabs/endkey/version"
)

var Cmd = command.New[*config.Config](
	"endkey",
	"endkey runs an API for managing Certificate Authorities",
	"endkey runs an API for managing Certificate Authorities",
	true,
	version.V,
	config.New,
	[]command.SetupCommand[*config.Config]{api.Cmd(), manage.Cmd(), certificate.Cmd()},
)
