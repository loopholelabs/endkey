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

package certificate

import (
	"errors"
	"github.com/loopholelabs/cmdutils"
	"github.com/loopholelabs/cmdutils/pkg/command"
	"github.com/loopholelabs/endkey/internal/config"
	"github.com/spf13/cobra"
)

var (
	ErrEndpointRequired = errors.New("endpoint is required")
	ErrAPIKeyRequired   = errors.New("apikey is required")
)

const (
	DefaultEndpoint = "localhost:8080"
	DefaultTLS      = false
)

type certificateModel struct {
	Authority     string `header:"authority" json:"authority"`
	Template      string `header:"template" json:"template"`
	AdditionalDNS string `header:"additional_dns_names" json:"additional_dns_names"`
	AdditionalIP  string `header:"additional_ip_addresses" json:"additional_ip_addresses"`
	Expiry        string `header:"expiry" json:"expiry"`
}

// Cmd encapsulates the commands for certificate.
func Cmd() command.SetupCommand[*config.Config] {
	var endpoint string
	var tls bool

	var apikey string

	return func(cmd *cobra.Command, ch *cmdutils.Helper[*config.Config]) {
		certificateCmd := &cobra.Command{
			Use:   "certificate",
			Short: "Commands for getting Certificates from the EndKey API",
			PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
				ch.Config.Endpoint = endpoint
				ch.Config.TLS = tls

				ch.Config.AuthenticationKey = apikey

				err := ch.Config.Validate()
				if err != nil {
					return err
				}

				if ch.Config.Endpoint == "" {
					return ErrEndpointRequired
				}

				if ch.Config.AuthenticationKey == "" {
					return ErrAPIKeyRequired
				}

				return nil
			},
		}

		getCmd := GetCmd()
		getCmd(certificateCmd, ch)

		certificateCmd.PersistentFlags().StringVar(&endpoint, "endpoint", DefaultEndpoint, "The endpoint of the EndKey API")
		certificateCmd.PersistentFlags().BoolVar(&tls, "tls", DefaultTLS, "Whether or not to use TLS")

		certificateCmd.PersistentFlags().StringVar(&apikey, "api-key", "", "The api key for the EndKey API")

		cmd.AddCommand(certificateCmd)
	}
}
