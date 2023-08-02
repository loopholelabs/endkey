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

package config

import (
	"fmt"
	httptransport "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"
	"github.com/loopholelabs/cmdutils/pkg/config"
	"github.com/loopholelabs/endkey/pkg/api/authorization"
	"github.com/loopholelabs/endkey/pkg/client"
	"github.com/mitchellh/go-homedir"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"path"
)

var _ config.Config = (*Config)(nil)

var (
	configFile string
	logFile    string
)

const (
	defaultConfigPath = "~/.config/endkey"
	configName        = "endkey.yml"
	logName           = "endkey.log"
)

// Config is dynamically sourced from various files and environment variables.
type Config struct {
	Identifier            string `mapstructure:"identifier"`
	DatabaseURL           string `mapstructure:"database_url"`
	ListenAddress         string `mapstructure:"listen_address"`
	EncryptionKey         []byte `mapstructure:"encryption_key"`
	PreviousEncryptionKey []byte `mapstructure:"previous_encryption_key"`

	Endpoint string `mapstructure:"endpoint"`
	TLS      bool   `mapstructure:"tls"`

	AuthenticationKey string `mapstructure:"authentication_key"`

	client *client.EndKeyAPIV1 `mapstructure:"-"`
}

func New() *Config {
	return new(Config)
}

func (c *Config) RootPersistentFlags(_ *pflag.FlagSet) {}

func (c *Config) GlobalRequiredFlags(_ *cobra.Command) error {
	return nil
}

func (c *Config) Validate() error {
	err := viper.Unmarshal(c)
	if err != nil {
		return fmt.Errorf("unable to unmarshal config: %w", err)
	}

	c.SetClient(c.NewClient())

	return nil
}

func (c *Config) DefaultConfigDir() (string, error) {
	dir, err := homedir.Expand(defaultConfigPath)
	if err != nil {
		return "", fmt.Errorf("can't expand path %q: %s", defaultConfigPath, err)
	}

	return dir, nil
}

func (c *Config) DefaultConfigFile() string {
	return configName
}

func (c *Config) DefaultLogFile() string {
	return logName
}

func (c *Config) DefaultConfigPath() (string, error) {
	configDir, err := c.DefaultConfigDir()
	if err != nil {
		return "", err
	}
	return path.Join(configDir, c.DefaultConfigFile()), nil
}

func (c *Config) DefaultLogPath() (string, error) {
	configDir, err := c.DefaultConfigDir()
	if err != nil {
		return "", err
	}
	return path.Join(configDir, c.DefaultLogFile()), nil
}

func (c *Config) GetConfigFile() string {
	return configFile
}

func (c *Config) GetLogFile() string {
	return logFile
}

func (c *Config) SetLogFile(file string) {
	logFile = file
}

func (c *Config) SetConfigFile(file string) {
	configFile = file
}

// NewClient creates an API client from our configuration
func (c *Config) NewClient() *client.EndKeyAPIV1 {
	scheme := "http"
	if c.TLS {
		scheme = "https"
	}
	r := httptransport.New(c.Endpoint, client.DefaultBasePath, []string{scheme})
	if c.AuthenticationKey != "" {
		r.DefaultAuthentication = httptransport.APIKeyAuth(authorization.HeaderString, "header", authorization.BearerString+c.AuthenticationKey)
	}

	return client.New(r, strfmt.Default)
}

func (c *Config) SetClient(client *client.EndKeyAPIV1) {
	c.client = client
}

func (c *Config) Client() *client.EndKeyAPIV1 {
	return c.client
}
