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
	"github.com/loopholelabs/cmdutils"
	"github.com/loopholelabs/cmdutils/pkg/command"
	"github.com/loopholelabs/cmdutils/pkg/printer"
	"github.com/loopholelabs/endkey/internal/config"
	"github.com/loopholelabs/endkey/pkg/client/authority"
	"github.com/spf13/cobra"
)

// ListCmd encapsulates the commands for listing Authorities
func ListCmd() command.SetupCommand[*config.Config] {
	return func(cmd *cobra.Command, ch *cmdutils.Helper[*config.Config]) {
		listCmd := &cobra.Command{
			Use:   "list",
			Short: "list Authorities",
			Args:  cobra.NoArgs,
			RunE: func(cmd *cobra.Command, args []string) error {
				ctx := cmd.Context()
				client := ch.Config.Client()
				end := ch.Printer.PrintProgress("Retrieving Authorities...")
				res, err := client.Authority.GetAuthority(authority.NewGetAuthorityParamsWithContext(ctx))
				end()
				if err != nil {
					return err
				}

				if len(res.GetPayload()) == 0 && ch.Printer.Format() == printer.Human {
					ch.Printer.Println("No Authorities have been created yet.")
					return nil
				}

				keys := make([]authorityRedactedModel, 0, len(res.GetPayload()))
				for _, auth := range res.GetPayload() {
					keys = append(keys, authorityRedactedModel{
						Created:    auth.CreatedAt,
						ID:         auth.ID,
						Name:       auth.Name,
						CommonName: auth.CommonName,
						Tag:        auth.Tag,
						Expiry:     auth.Expiry,
					})
				}

				return ch.Printer.PrintResource(keys)
			},
		}

		cmd.AddCommand(listCmd)
	}
}
