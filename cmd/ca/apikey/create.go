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
	"github.com/loopholelabs/endkey/pkg/template"
	"github.com/spf13/cobra"
)

// CreateCmd encapsulates the commands for creating API Keys
func CreateCmd() command.SetupCommand[*config.Config] {
	return func(cmd *cobra.Command, ch *cmdutils.Helper[*config.Config]) {
		createCmd := &cobra.Command{
			Use:   "create <authority> <name> <client|server> <template>",
			Args:  cobra.ExactArgs(4),
			Short: "Create an API Key with the given name and authority for the given template",
			RunE: func(cmd *cobra.Command, args []string) error {
				ctx := cmd.Context()
				client := ch.Config.Client()

				authority := args[0]
				name := args[1]
				kind := template.Kind(args[2])
				templ := args[3]

				switch kind {
				case template.Client, template.Server:
				default:
					return fmt.Errorf("invalid template kind: %s", kind)
				}

				end := ch.Printer.PrintProgress(fmt.Sprintf("Creating API Key %s for authority %s for template %s...", name, authority, templ))
				req := &models.ModelsCreateAPIKeyRequest{
					AuthorityName: authority,
					Name:          name,
					TemplateKind:  string(kind),
					TemplateName:  templ,
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
					Created:      res.GetPayload().CreatedAt,
					ID:           res.GetPayload().ID,
					Name:         res.GetPayload().Name,
					Authority:    res.GetPayload().AuthorityName,
					TemplateKind: res.GetPayload().TemplateKind,
					TemplateName: res.GetPayload().TemplateName,
					Value:        value,
				})
			},
		}

		cmd.AddCommand(createCmd)
	}
}
