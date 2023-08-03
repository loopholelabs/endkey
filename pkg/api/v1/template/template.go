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

package template

import (
	"github.com/gofiber/fiber/v2"
	"github.com/loopholelabs/endkey/internal/metrics"
	"github.com/loopholelabs/endkey/internal/utils"
	"github.com/loopholelabs/endkey/pkg/api/v1/options"
	"github.com/rs/zerolog"
)

var (
	createServerMetric = metrics.NewStatusMetric("v1_template_server_create", "The total number of server template create requests")
	listServerMetric   = metrics.NewStatusMetric("v1_template_server_list", "The total number of server template list requests")
	deleteServerMetric = metrics.NewStatusMetric("v1_template_server_delete", "The total number of server template delete requests")

	createClientMetric = metrics.NewStatusMetric("v1_template_client_create", "The total number of client template create requests")
	listClientMetric   = metrics.NewStatusMetric("v1_template_client_list", "The total number of client template list requests")
	deleteClientMetric = metrics.NewStatusMetric("v1_template_client_delete", "The total number of client template delete requests")
)

type Template struct {
	logger  *zerolog.Logger
	app     *fiber.App
	options *options.Options
}

func New(options *options.Options, logger *zerolog.Logger) *Template {
	l := logger.With().Str("COMPONENT", "TEMPLATE").Logger()
	i := &Template{
		logger:  &l,
		app:     utils.DefaultFiberApp(),
		options: options,
	}

	i.init()

	return i
}

func (a *Template) init() {
	a.logger.Debug().Msg("initializing")

	a.app.Use(a.options.Auth().UserKeyValidate)

	a.app.Post("/server", createServerMetric.Middleware(), a.CreateServer)
	a.app.Get("/server/:authority_name", listServerMetric.Middleware(), a.ListServer)
	a.app.Delete("/server", deleteServerMetric.Middleware(), a.DeleteServer)

	a.app.Post("/client", createClientMetric.Middleware(), a.CreateClient)
	a.app.Get("/client/:authority_name", listClientMetric.Middleware(), a.ListClient)
	a.app.Delete("/client", deleteClientMetric.Middleware(), a.DeleteClient)
}

func (a *Template) App() *fiber.App {
	return a.app
}
