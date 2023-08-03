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
	"github.com/loopholelabs/endkey/pkg/client/models"
	"github.com/spf13/cobra"
)

// CreateCmd encapsulates the commands for creating Authorities
func CreateCmd() command.SetupCommand[*config.Config] {
	return func(cmd *cobra.Command, ch *cmdutils.Helper[*config.Config]) {
		createCmd := &cobra.Command{
			Use:   "create <name> <common-name> <tag> <validity>",
			Args:  cobra.ExactArgs(4),
			Short: "Create an Authority with the given name, common name, tag, and validity period",
			RunE: func(cmd *cobra.Command, args []string) error {
				ctx := cmd.Context()
				client := ch.Config.Client()

				name := args[0]
				commonName := args[1]
				tag := args[2]
				validity := args[3]

				end := ch.Printer.PrintProgress(fmt.Sprintf("Creating Authority '%s' with Common Name '%s', Tag '%s', and Validity '%s'...", name, commonName, tag, validity))
				req := &models.ModelsCreateAuthorityRequest{
					CommonName: commonName,
					Name:       name,
					Tag:        tag,
					Validity:   validity,
				}
				res, err := client.Authority.PostAuthority(authority.NewPostAuthorityParamsWithContext(ctx).WithRequest(req))
				end()
				if err != nil {
					return err
				}

				if ch.Printer.Format() == printer.Human {
					ch.Printer.Printf("Created Authority '%s' with Expiry %s\n", printer.Bold(res.GetPayload().Name), printer.BoldBlue(res.GetPayload().Expiry))
					return nil
				}

				caCert, err := base64.StdEncoding.DecodeString(res.GetPayload().CaCertificate)
				if err != nil {
					return fmt.Errorf("failed to decode CA certificate: %w", err)
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

		cmd.AddCommand(createCmd)
	}
}
