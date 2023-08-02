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

package rootkey

import (
	"github.com/loopholelabs/cmdutils"
	"github.com/loopholelabs/cmdutils/pkg/command"
	"github.com/loopholelabs/cmdutils/pkg/printer"
	"github.com/loopholelabs/endkey/internal/config"
	"github.com/loopholelabs/endkey/pkg/client/rootkey"
	"github.com/spf13/cobra"
)

// ListCmd encapsulates the commands for listing Root Keys
func ListCmd() command.SetupCommand[*config.Config] {
	return func(cmd *cobra.Command, ch *cmdutils.Helper[*config.Config]) {
		listCmd := &cobra.Command{
			Use:   "list",
			Short: "list Root Keys",
			Args:  cobra.NoArgs,
			RunE: func(cmd *cobra.Command, args []string) error {
				ctx := cmd.Context()
				client := ch.Config.Client()
				end := ch.Printer.PrintProgress("Retrieving Root Keys...")
				res, err := client.Rootkey.GetRootkey(rootkey.NewGetRootkeyParamsWithContext(ctx))
				end()
				if err != nil {
					return err
				}

				if len(res.GetPayload()) == 0 && ch.Printer.Format() == printer.Human {
					ch.Printer.Println("No Root Keys have been created yet.")
					return nil
				}

				keys := make([]rootKeyRedactedModel, 0, len(res.GetPayload()))
				for _, key := range res.GetPayload() {
					keys = append(keys, rootKeyRedactedModel{
						Created:    key.CreatedAt,
						Identifier: key.Identifier,
						Name:       key.Name,
					})
				}

				return ch.Printer.PrintResource(keys)
			},
		}

		cmd.AddCommand(listCmd)
	}
}
