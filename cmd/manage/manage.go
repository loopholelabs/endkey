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

package manage

import (
	"errors"
	"github.com/loopholelabs/cmdutils"
	"github.com/loopholelabs/cmdutils/pkg/command"
	"github.com/loopholelabs/endkey/cmd/manage/apikey"
	"github.com/loopholelabs/endkey/cmd/manage/authority"
	"github.com/loopholelabs/endkey/cmd/manage/rootkey"
	"github.com/loopholelabs/endkey/cmd/manage/template"
	"github.com/loopholelabs/endkey/internal/config"
	"github.com/spf13/cobra"
)

var (
	ErrEndpointRequired = errors.New("endpoint is required")
)

const (
	DefaultEndpoint = "localhost:8080"
	DefaultTLS      = false
)

// Cmd encapsulates the commands for manage.
func Cmd() command.SetupCommand[*config.Config] {
	var endpoint string
	var tls bool

	return func(cmd *cobra.Command, ch *cmdutils.Helper[*config.Config]) {
		manageCmd := &cobra.Command{
			Use:   "manage",
			Short: "Commands for management of the EndKey API",
			PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
				ch.Config.Endpoint = endpoint
				ch.Config.TLS = tls

				err := ch.Config.Validate()
				if err != nil {
					return err
				}

				if ch.Config.Endpoint == "" {
					return ErrEndpointRequired
				}

				return nil
			},
		}

		rootKeySetup := rootkey.Cmd()
		rootKeySetup(manageCmd, ch)

		apiKeySetup := apikey.Cmd()
		apiKeySetup(manageCmd, ch)

		authoritySetup := authority.Cmd()
		authoritySetup(manageCmd, ch)

		templateSetup := template.Cmd()
		templateSetup(manageCmd, ch)

		manageCmd.PersistentFlags().StringVar(&endpoint, "endpoint", DefaultEndpoint, "The endpoint of the EndKey API")
		manageCmd.PersistentFlags().BoolVar(&tls, "tls", DefaultTLS, "Whether or not to use TLS")

		cmd.AddCommand(manageCmd)
	}
}
