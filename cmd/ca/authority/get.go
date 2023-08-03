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

package authority

import (
	"encoding/base64"
	"fmt"
	"github.com/loopholelabs/cmdutils"
	"github.com/loopholelabs/cmdutils/pkg/command"
	"github.com/loopholelabs/cmdutils/pkg/printer"
	"github.com/loopholelabs/endkey/internal/config"
	"github.com/loopholelabs/endkey/pkg/client/authority"
	"github.com/spf13/cobra"
	"os"
)

// GetCmd encapsulates the commands for getting Authorities
func GetCmd() command.SetupCommand[*config.Config] {
	var path string
	return func(cmd *cobra.Command, ch *cmdutils.Helper[*config.Config]) {
		getCmd := &cobra.Command{
			Use:   "get <name>",
			Short: "get an Authority given its name",
			Args:  cobra.ExactArgs(1),
			RunE: func(cmd *cobra.Command, args []string) error {
				ctx := cmd.Context()
				client := ch.Config.Client()

				name := args[0]

				end := ch.Printer.PrintProgress(fmt.Sprintf("Retrieving Authority %s...", name))
				res, err := client.Authority.GetAuthorityName(authority.NewGetAuthorityNameParamsWithContext(ctx).WithName(name))
				end()
				if err != nil {
					return err
				}

				caCert, err := base64.StdEncoding.DecodeString(res.GetPayload().CaCertificate)
				if err != nil {
					return fmt.Errorf("failed to decode CA certificate: %w", err)
				}

				if path != "" {
					if err := os.WriteFile(path, caCert, 0644); err != nil {
						return fmt.Errorf("failed to write CA certificate to %s: %w", path, err)
					}
					if ch.Printer.Format() == printer.Human {
						ch.Printer.Println(fmt.Sprintf("CA certificate written to %s", path))
						return nil
					}
				}

				return ch.Printer.PrintResource(authorityModel{
					Created:       res.GetPayload().CreatedAt,
					ID:            res.GetPayload().ID,
					Name:          res.GetPayload().Name,
					CommonName:    res.GetPayload().CommonName,
					Tag:           res.GetPayload().Tag,
					Expiry:        res.GetPayload().Expiry,
					CACertificate: string(caCert),
				})
			},
		}

		getCmd.Flags().StringVar(&path, "path", "", "The optional path to write the CA certificate to")

		cmd.AddCommand(getCmd)
	}
}
