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

package client

import (
	"fmt"
	"github.com/loopholelabs/cmdutils"
	"github.com/loopholelabs/cmdutils/pkg/command"
	"github.com/loopholelabs/cmdutils/pkg/printer"
	"github.com/loopholelabs/endkey/internal/config"
	"github.com/loopholelabs/endkey/pkg/client/models"
	"github.com/loopholelabs/endkey/pkg/client/template"
	"github.com/spf13/cobra"
)

// DeleteCmd encapsulates the commands for deleting Client Templates
func DeleteCmd() command.SetupCommand[*config.Config] {
	return func(cmd *cobra.Command, ch *cmdutils.Helper[*config.Config]) {
		deleteCmd := &cobra.Command{
			Use:   "delete <authority> <name>",
			Args:  cobra.ExactArgs(2),
			Short: "delete a Client Template with the given name and authority",
			RunE: func(cmd *cobra.Command, args []string) error {
				ctx := cmd.Context()
				client := ch.Config.Client()

				authority := args[0]
				name := args[1]

				end := ch.Printer.PrintProgress(fmt.Sprintf("Deleting Client Template %s for authority %s...", name, authority))

				req := &models.ModelsDeleteClientTemplateRequest{
					AuthorityName: authority,
					Name:          name,
				}

				_, err := client.Template.DeleteTemplateClient(template.NewDeleteTemplateClientParamsWithContext(ctx).WithRequest(req))
				end()
				if err != nil {
					return err
				}

				if ch.Printer.Format() == printer.Human {
					ch.Printer.Printf("%s %s %s\n", printer.BoldRed("Client Template"), printer.BoldGreen(name), printer.BoldRed("deleted"))
					return nil
				}

				return ch.Printer.PrintResource(map[string]string{
					"deleted": name,
				})
			},
		}

		cmd.AddCommand(deleteCmd)
	}
}
