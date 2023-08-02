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
	"errors"
	"fmt"
	"github.com/loopholelabs/cmdutils"
	"github.com/loopholelabs/cmdutils/pkg/command"
	"github.com/loopholelabs/endkey/internal/config"
	"github.com/loopholelabs/endkey/internal/log"
	"github.com/loopholelabs/endkey/internal/utils"
	"github.com/loopholelabs/endkey/pkg/api"
	"github.com/spf13/cobra"
)

var (
	ErrIdentifierRequired    = errors.New("identifier is required")
	ErrDatabaseURLRequired   = errors.New("database url is required")
	ErrListenAddressRequired = errors.New("listen address is required")
	ErrEndpointRequired      = errors.New("endpoint is required")
	ErrEncryptionKeyRequired = errors.New("encryption key is required")
)

const (
	DefaultListenAddress = "127.0.0.1:8080"
	DefaultEndpoint      = "localhost:8080"
	DefaultTLS           = false
)

// Cmd encapsulates the commands for starting the API
func Cmd() command.SetupCommand[*config.Config] {
	var identifier string
	var databaseURL string
	var listenAddress string
	var encryptionKey []byte
	var previousEncryptionKey []byte

	var endpoint string
	var tls bool

	return func(cmd *cobra.Command, ch *cmdutils.Helper[*config.Config]) {
		apiCmd := &cobra.Command{
			Use: "api",
			PreRunE: func(cmd *cobra.Command, args []string) error {
				log.Init(ch.Config.GetLogFile(), ch.Debug())
				err := ch.Config.GlobalRequiredFlags(cmd)
				if err != nil {
					return err
				}

				err = cmd.MarkFlagRequired("identifier")
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

				ch.Config.Identifier = identifier
				ch.Config.DatabaseURL = databaseURL
				ch.Config.ListenAddress = listenAddress
				ch.Config.EncryptionKey = encryptionKey
				ch.Config.PreviousEncryptionKey = previousEncryptionKey

				ch.Config.Endpoint = endpoint
				ch.Config.TLS = tls

				err = ch.Config.Validate()
				if err != nil {
					return err
				}

				if ch.Config.Identifier == "" {
					return ErrIdentifierRequired
				}

				if ch.Config.DatabaseURL == "" {
					return ErrDatabaseURLRequired
				}

				if ch.Config.ListenAddress == "" {
					return ErrListenAddressRequired
				}

				if len(ch.Config.EncryptionKey) != 32 {
					return ErrEncryptionKeyRequired
				}

				if ch.Config.Endpoint == "" {
					return ErrEndpointRequired
				}

				return nil
			},
			RunE: func(cmd *cobra.Command, args []string) error {
				ch.Printer.Println("Starting EndKey API listening on ", ch.Config.ListenAddress)
				errCh := make(chan error, 1)
				a, err := api.New(ch.Config, log.Logger)
				if err != nil {
					return fmt.Errorf("failed to create EndKey API: %w", err)
				}
				go func() {
					errCh <- a.Start()
				}()

				err = utils.WaitForSignal(errCh)
				if err != nil {
					_ = a.Stop()
					return fmt.Errorf("error while starting EndKey API: %w", err)
				}

				err = a.Stop()
				if err != nil {
					return fmt.Errorf("failed to stop EndKey API: %w", err)
				}
				return nil
			},
		}

		apiCmd.Flags().StringVar(&identifier, "identifier", "", "The identifier for the service")
		apiCmd.Flags().StringVar(&databaseURL, "database-url", "", "The database url")
		apiCmd.Flags().StringVar(&listenAddress, "listen-address", DefaultListenAddress, "The listen address")
		apiCmd.Flags().BytesHexVar(&encryptionKey, "encryption-key", nil, "The encryption key (hex encoded)")
		apiCmd.Flags().BytesHexVar(&previousEncryptionKey, "previous-encryption-key", nil, "The previous encryption key (hex encoded)")

		apiCmd.Flags().StringVar(&endpoint, "endpoint", DefaultEndpoint, "The endpoint")
		apiCmd.Flags().BoolVar(&tls, "tls", DefaultTLS, "Enable TLS")

		cmd.AddCommand(apiCmd)
	}
}
