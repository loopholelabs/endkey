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

package v1

import (
	"github.com/gofiber/fiber/v2"
	"github.com/loopholelabs/endkey/internal/metrics"
	"github.com/loopholelabs/endkey/internal/utils"
	"github.com/loopholelabs/endkey/pkg/api/v1/apikey"
	"github.com/loopholelabs/endkey/pkg/api/v1/authority"
	"github.com/loopholelabs/endkey/pkg/api/v1/certificate"
	"github.com/loopholelabs/endkey/pkg/api/v1/docs"
	"github.com/loopholelabs/endkey/pkg/api/v1/models"
	"github.com/loopholelabs/endkey/pkg/api/v1/options"
	"github.com/loopholelabs/endkey/pkg/api/v1/rootkey"
	"github.com/loopholelabs/endkey/pkg/api/v1/template"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/zerolog"
	"github.com/valyala/fasthttp/fasthttpadaptor"
)

var (
	healthMetric  = metrics.NewStatusMetric("v1_health_total", "The total number of health calls")
	swaggerMetric = metrics.NewStatusMetric("v1_swagger_total", "The total number of swagger calls")
)

//go:generate swag init -g v1.go -o docs --instanceName api -d ./
type V1 struct {
	logger  *zerolog.Logger
	app     *fiber.App
	options *options.Options
}

func New(options *options.Options, logger *zerolog.Logger) *V1 {
	l := logger.With().Str("VERSION", "v1").Logger()
	v := &V1{
		logger:  &l,
		app:     utils.DefaultFiberApp(),
		options: options,
	}

	v.init()

	return v
}

// @title EndKey API V1
// @version 1.0
// @description API for EndKey, V1
// @termsOfService https://loopholelabs.io/privacy
// @contact.name API Support
// @contact.email admin@loopholelabs.io
// @license.name Apache 2.0
// @license.url https://www.apache.org/licenses/LICENSE-2.0.html
// @host localhost:8080
// @schemes https
// @BasePath /v1
func (v *V1) init() {
	v.logger.Debug().Msg("initializing")

	v.app.Mount("/authority", authority.New(v.options, v.logger).App())
	v.app.Mount("/rootkey", rootkey.New(v.options, v.logger).App())
	v.app.Mount("/apikey", apikey.New(v.options, v.logger).App())
	v.app.Mount("/template", template.New(v.options, v.logger).App())
	v.app.Mount("/certificate", certificate.New(v.options, v.logger).App())

	v.app.Get("/swagger.json", swaggerMetric.Middleware(), func(ctx *fiber.Ctx) error {
		ctx.Response().Header.SetContentType("application/json")
		return ctx.SendString(docs.SwaggerInfoapi.ReadDoc())
	})

	metricsHandler := fasthttpadaptor.NewFastHTTPHandler(
		promhttp.HandlerFor(
			prometheus.DefaultGatherer,
			promhttp.HandlerOpts{EnableOpenMetrics: true},
		),
	)

	v.app.Get("/metrics", func(c *fiber.Ctx) error {
		metricsHandler(c.Context())
		return nil
	})

	v.app.Get("/health", healthMetric.Middleware(), v.Health)
}

// Health godoc
// @Description  Returns the health and status of the various services that make up the API.
// @Tags         health
// @Accept       json
// @Produce      json
// @Success      200 {object} models.HealthResponse
// @Failure      500 {string} string
// @Router       /health [get]
func (v *V1) Health(ctx *fiber.Ctx) error {
	return ctx.JSON(&models.HealthResponse{
		Database: true,
	})
}

func (v *V1) App() *fiber.App {
	return v.app
}
