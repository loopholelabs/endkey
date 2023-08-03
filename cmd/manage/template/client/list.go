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
	"github.com/loopholelabs/endkey/pkg/client/template"
	"github.com/spf13/cobra"
	"strings"
)

// ListCmd encapsulates the commands for listing Client Templates
func ListCmd() command.SetupCommand[*config.Config] {
	return func(cmd *cobra.Command, ch *cmdutils.Helper[*config.Config]) {
		listCmd := &cobra.Command{
			Use:   "list <authority>",
			Short: "list Client Templates",
			Args:  cobra.ExactArgs(1),
			RunE: func(cmd *cobra.Command, args []string) error {
				ctx := cmd.Context()
				client := ch.Config.Client()

				authority := args[0]

				end := ch.Printer.PrintProgress(fmt.Sprintf("Retrieving Client Templates for authority %s...", authority))

				res, err := client.Template.GetTemplateClientAuthorityName(template.NewGetTemplateClientAuthorityNameParamsWithContext(ctx).WithAuthorityName(authority))
				end()
				if err != nil {
					return err
				}

				if len(res.GetPayload()) == 0 && ch.Printer.Format() == printer.Human {
					ch.Printer.Println("No Client Templates have been created yet.")
					return nil
				}

				templs := make([]clientTemplateModel, 0, len(res.GetPayload()))
				for _, templ := range res.GetPayload() {
					templs = append(templs, clientTemplateModel{
						Created:       templ.CreatedAt,
						ID:            templ.ID,
						Name:          templ.Name,
						Authority:     templ.AuthorityName,
						CommonName:    templ.CommonName,
						Tag:           templ.Tag,
						DNSNames:      strings.Join(templ.DNSNames, ","),
						IPAddresses:   strings.Join(templ.IPAddresses, ","),
						Validity:      templ.Validity,
						AdditionalDNS: fmt.Sprintf("%t", templ.AllowAdditionalDNSNames),
						AdditionalIPs: fmt.Sprintf("%t", templ.AllowAdditionalIps),
					})
				}

				return ch.Printer.PrintResource(templs)
			},
		}

		cmd.AddCommand(listCmd)
	}
}
