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
	"errors"
	"fmt"
	"github.com/loopholelabs/cmdutils/pkg/config"
	"github.com/mitchellh/go-homedir"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"path"
)

var _ config.Config = (*Config)(nil)

var (
	ErrIdentifierRequired    = errors.New("identifier is required")
	ErrDatabaseURLRequired   = errors.New("database url is required")
	ErrListenAddressRequired = errors.New("listen address is required")
	ErrEndpointRequired      = errors.New("endpoint is required")
	ErrEncryptionKeyRequired = errors.New("encryption key is required")
)

var (
	configFile string
	logFile    string
)

const (
	defaultConfigPath = "~/.config/endkey"
	configName        = "endkey.yml"
	logName           = "endkey.log"

	DefaultListenAddress = "127.0.0.1:8080"
	DefaultEndpoint      = "localhost:8080"
	DefaultTLS           = false
)

// Config is dynamically sourced from various files and environment variables.
type Config struct {
	Identifier            string `mapstructure:"identifier"`
	DatabaseURL           string `mapstructure:"database_url"`
	ListenAddress         string `mapstructure:"listen_address"`
	Endpoint              string `mapstructure:"endpoint"`
	TLS                   bool   `mapstructure:"tls"`
	EncryptionKey         []byte `mapstructure:"encryption_key"`
	PreviousEncryptionKey []byte `mapstructure:"previous_encryption_key"`
}

func New() *Config {
	return &Config{
		ListenAddress: DefaultListenAddress,
		Endpoint:      DefaultEndpoint,
	}
}

func (c *Config) RootPersistentFlags(flags *pflag.FlagSet) {
	flags.StringVar(&c.Identifier, "identifier", "", "The identifier for the service")
	flags.StringVar(&c.DatabaseURL, "database-url", "", "The database url")
	flags.StringVar(&c.ListenAddress, "listen-address", DefaultListenAddress, "The listen address")
	flags.StringVar(&c.Endpoint, "endpoint", DefaultEndpoint, "The endpoint")
	flags.BoolVar(&c.TLS, "tls", DefaultTLS, "Enable TLS")
	flags.BytesHexVar(&c.EncryptionKey, "encryption-key", nil, "The encryption key (hex encoded)")
	flags.BytesHexVar(&c.PreviousEncryptionKey, "previous-encryption-key", nil, "The previous encryption key (hex encoded)")
}

func (c *Config) GlobalRequiredFlags(cmd *cobra.Command) error {
	err := cmd.MarkFlagRequired("identifier")
	if err != nil {
		return err
	}

	err = cmd.MarkFlagRequired("database-url")
	if err != nil {
		return err
	}

	err = cmd.MarkFlagRequired("encryption-key")
	if err != nil {
		return err
	}

	return nil
}

func (c *Config) Validate() error {
	err := viper.Unmarshal(c)
	if err != nil {
		return fmt.Errorf("unable to unmarshal config: %w", err)
	}

	if c.Identifier == "" {
		return ErrIdentifierRequired
	}

	if c.DatabaseURL == "" {
		return ErrDatabaseURLRequired
	}

	if c.ListenAddress == "" {
		return ErrListenAddressRequired
	}

	if c.Endpoint == "" {
		return ErrEndpointRequired
	}

	if len(c.EncryptionKey) != 32 {
		return ErrEncryptionKeyRequired
	}

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
