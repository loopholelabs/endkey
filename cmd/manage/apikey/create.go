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

package apikey

import (
	"fmt"
	"github.com/loopholelabs/cmdutils"
	"github.com/loopholelabs/cmdutils/pkg/command"
	"github.com/loopholelabs/cmdutils/pkg/printer"
	"github.com/loopholelabs/endkey/internal/config"
	"github.com/loopholelabs/endkey/internal/key"
	"github.com/loopholelabs/endkey/pkg/client/apikey"
	"github.com/loopholelabs/endkey/pkg/client/models"
	"github.com/spf13/cobra"
)

// CreateCmd encapsulates the commands for creating API Keys
func CreateCmd() command.SetupCommand[*config.Config] {
	var serverTemplate string
	var clientTemplate string
	return func(cmd *cobra.Command, ch *cmdutils.Helper[*config.Config]) {
		createCmd := &cobra.Command{
			Use:   "create <authority> <name>",
			Args:  cobra.ExactArgs(2),
			Short: "Create an API Key with the given name and authority",
			RunE: func(cmd *cobra.Command, args []string) error {
				ctx := cmd.Context()
				client := ch.Config.Client()

				authority := args[0]
				name := args[1]

				end := ch.Printer.PrintProgress(fmt.Sprintf("Creating API Key %s for authority %s...", name, authority))
				req := &models.ModelsCreateAPIKeyRequest{
					AuthorityName:      authority,
					Name:               name,
					ClientTemplateName: clientTemplate,
					ServerTemplateName: serverTemplate,
				}
				res, err := client.Apikey.PostApikey(apikey.NewPostApikeyParamsWithContext(ctx).WithRequest(req))
				end()
				if err != nil {
					return err
				}

				value := fmt.Sprintf("%s%s.%s", key.APIPrefixString, res.GetPayload().ID, res.GetPayload().Secret)

				if ch.Printer.Format() == printer.Human {
					ch.Printer.Printf("Created API Key '%s': %s (this will only be displayed once)\n", printer.Bold(res.Payload.Name), printer.BoldGreen(value))
					return nil
				}

				return ch.Printer.PrintResource(apiKeyModel{
					Created:        res.GetPayload().CreatedAt,
					ID:             res.GetPayload().ID,
					Name:           res.GetPayload().Name,
					Authority:      res.GetPayload().AuthorityName,
					ServerTemplate: res.GetPayload().ServerTemplateName,
					ClientTemplate: res.GetPayload().ClientTemplateName,
					Value:          value,
				})
			},
		}

		createCmd.Flags().StringVar(&serverTemplate, "server-template", "", "The server template to use for the API Key")
		createCmd.Flags().StringVar(&clientTemplate, "client-template", "", "The client template to use for the API Key")

		cmd.AddCommand(createCmd)
	}
}
