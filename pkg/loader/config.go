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

package loader

import (
	"errors"
	"github.com/spf13/pflag"
)

var (
	ErrEndpointRequired = errors.New("endpoint is required")
	ErrAPIKeyRequired   = errors.New("api key is required")
)

const (
	DefaultDisabled = false
)

type Config struct {
	Disabled              bool     `mapstructure:"disabled"`
	Endpoint              string   `mapstructure:"endpoint"`
	APIKey                string   `mapstructure:"api_key"`
	TLS                   bool     `mapstructure:"tls"`
	AdditionalDNSNames    []string `mapstructure:"additional_dns_names"`
	AdditionalIPAddresses []string `mapstructure:"additional_ip_addresses"`
	OverrideCommonName    string   `mapstructure:"override_common_name"`
}

func NewConfig() *Config {
	return &Config{
		Disabled: DefaultDisabled,
	}
}

func (c *Config) Validate() error {
	if !c.Disabled {
		if c.Endpoint == "" {
			return ErrEndpointRequired
		}
		if c.APIKey == "" {
			return ErrAPIKeyRequired
		}

	}
	return nil
}

func (c *Config) RootPersistentFlags(flags *pflag.FlagSet) {
	flags.BoolVar(&c.Disabled, "endkey-disabled", DefaultDisabled, "Disable EndKey Loader")
	flags.StringVar(&c.Endpoint, "endkey-endpoint", "", "EndKey endpoint")
	flags.StringVar(&c.APIKey, "endkey-api-key", "", "EndKey API Key")
	flags.BoolVar(&c.TLS, "endkey-tls", false, "Enable TLS")
	flags.StringSliceVar(&c.AdditionalDNSNames, "endkey-additional-dns-names", []string{}, "Additional DNS names")
	flags.StringSliceVar(&c.AdditionalIPAddresses, "endkey-additional-ip-addresses", []string{}, "Additional IP addresses")
	flags.StringVar(&c.OverrideCommonName, "endkey-override-common-name", "", "Override common name")
}

func (c *Config) GenerateOptions(logName string) (*Options, error) {
	return &Options{
		LogName:               logName,
		Disabled:              c.Disabled,
		Endpoint:              c.Endpoint,
		APIKey:                c.APIKey,
		TLS:                   c.TLS,
		AdditionalDNSNames:    c.AdditionalDNSNames,
		AdditionalIPAddresses: c.AdditionalIPAddresses,
		OverrideCommonName:    c.OverrideCommonName,
	}, nil
}
