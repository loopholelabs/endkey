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

package ca

import (
	"errors"
	"github.com/loopholelabs/cmdutils"
	"github.com/loopholelabs/cmdutils/pkg/command"
	"github.com/loopholelabs/endkey/cmd/ca/apikey"
	"github.com/loopholelabs/endkey/cmd/ca/authority"
	"github.com/loopholelabs/endkey/cmd/ca/template"
	"github.com/loopholelabs/endkey/internal/config"
	"github.com/spf13/cobra"
)

var (
	ErrEndpointRequired = errors.New("endpoint is required")
	ErrUserKeyRequired  = errors.New("userkey is required")
)

const (
	DefaultEndpoint = "localhost:8080"
	DefaultTLS      = false
)

// Cmd encapsulates the commands for ca.
func Cmd() command.SetupCommand[*config.Config] {
	var endpoint string
	var tls bool

	var uk string

	return func(cmd *cobra.Command, ch *cmdutils.Helper[*config.Config]) {
		caCmd := &cobra.Command{
			Use:   "ca",
			Short: "Commands for the CA of the EndKey API",
			PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
				ch.Config.Endpoint = endpoint
				ch.Config.TLS = tls

				ch.Config.AuthenticationKey = uk

				err := ch.Config.Validate()
				if err != nil {
					return err
				}

				if ch.Config.Endpoint == "" {
					return ErrEndpointRequired
				}

				if ch.Config.AuthenticationKey == "" {
					return ErrUserKeyRequired
				}

				return nil
			},
		}

		apiKeySetup := apikey.Cmd()
		apiKeySetup(caCmd, ch)

		authoritySetup := authority.Cmd()
		authoritySetup(caCmd, ch)

		templateSetup := template.Cmd()
		templateSetup(caCmd, ch)

		caCmd.PersistentFlags().StringVar(&endpoint, "endpoint", DefaultEndpoint, "The endpoint of the EndKey API")
		caCmd.PersistentFlags().BoolVar(&tls, "tls", DefaultTLS, "Whether or not to use TLS")

		caCmd.PersistentFlags().StringVar(&uk, "user-key", "", "The user key for the EndKey API")

		cmd.AddCommand(caCmd)
	}
}
