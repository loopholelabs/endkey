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

package metrics

import (
	"github.com/gofiber/fiber/v2"
	"github.com/prometheus/client_golang/prometheus"
	"strconv"
)

var (
	statusLUT = make(map[int]string)
)

func init() {
	for code := 100; code < 600; code++ {
		statusLUT[code] = strconv.Itoa(code)
	}
}

type StatusMetric struct {
	counter *prometheus.CounterVec
}

func NewStatusMetric(name string, help string) *StatusMetric {
	return &StatusMetric{
		counter: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: name,
			Help: help,
		}, []string{"status"}),
	}
}

func (l *StatusMetric) Inc(labels ...string) {
	l.counter.WithLabelValues(labels...).Inc()
}

func (l *StatusMetric) Error(code int, message string) error {
	if code >= 100 && code < 600 {
		l.counter.WithLabelValues(statusLUT[code]).Inc()
	}
	return fiber.NewError(code, message)
}

func (l *StatusMetric) Middleware() fiber.Handler {
	return func(c *fiber.Ctx) error {
		err := c.Next()
		if err != nil {
			code := err.(*fiber.Error).Code
			if code >= 100 && code < 600 {
				l.counter.WithLabelValues(statusLUT[code]).Inc()
			}
			return err
		}
		code := c.Response().StatusCode()
		if code >= 100 && code < 600 {
			l.counter.WithLabelValues(statusLUT[code]).Inc()
		}
		return nil
	}
}
