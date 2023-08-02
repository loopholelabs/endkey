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

package server

import (
	"fmt"
	"github.com/loopholelabs/cmdutils"
	"github.com/loopholelabs/cmdutils/pkg/command"
	"github.com/loopholelabs/endkey/internal/config"
	"github.com/loopholelabs/endkey/pkg/client/models"
	"github.com/loopholelabs/endkey/pkg/client/template"
	"github.com/spf13/cobra"
	"strings"
)

// CreateCmd encapsulates the commands for creating Server Templates
func CreateCmd() command.SetupCommand[*config.Config] {
	var allowAdditionalDNSNames bool
	var allowAdditionalIPs bool
	var dnsNames []string
	var ipAddresses []string
	return func(cmd *cobra.Command, ch *cmdutils.Helper[*config.Config]) {
		createCmd := &cobra.Command{
			Use:   "create <authority> <identifier> <common-name> <tag> <validity>",
			Args:  cobra.ExactArgs(5),
			Short: "Create a Server Template with the given name ",
			RunE: func(cmd *cobra.Command, args []string) error {
				ctx := cmd.Context()
				client := ch.Config.Client()

				authority := args[0]
				identifier := args[1]
				commonName := args[2]
				tag := args[3]
				validity := args[4]

				end := ch.Printer.PrintProgress(fmt.Sprintf("Creating Server Template %s for authority %s...", identifier, authority))
				req := &models.ModelsCreateServerTemplateRequest{
					AllowAdditionalDNSNames: allowAdditionalDNSNames,
					AllowAdditionalIps:      allowAdditionalIPs,
					Authority:               authority,
					CommonName:              commonName,
					DNSNames:                dnsNames,
					Identifier:              identifier,
					IPAddresses:             ipAddresses,
					Tag:                     tag,
					Validity:                validity,
				}

				res, err := client.Template.PostTemplateServer(template.NewPostTemplateServerParamsWithContext(ctx).WithRequest(req))
				end()
				if err != nil {
					return err
				}

				return ch.Printer.PrintResource(serverTemplateModel{
					Created:       res.GetPayload().CreatedAt,
					Identifier:    res.GetPayload().Identifier,
					Authority:     res.GetPayload().Authority,
					CommonName:    res.GetPayload().CommonName,
					Tag:           res.GetPayload().Tag,
					DNSNames:      strings.Join(res.GetPayload().DNSNames, ","),
					IPAddresses:   strings.Join(res.GetPayload().IPAddresses, ","),
					Validity:      res.GetPayload().Validity,
					AdditionalDNS: fmt.Sprintf("%t", res.GetPayload().AllowAdditionalDNSNames),
					AdditionalIPs: fmt.Sprintf("%t", res.GetPayload().AllowAdditionalIps),
				})
			},
		}

		createCmd.Flags().BoolVar(&allowAdditionalDNSNames, "allow-additional-dns-names", false, "Allow additional DNS names")
		createCmd.Flags().BoolVar(&allowAdditionalIPs, "allow-additional-ips", false, "Allow additional IP addresses")
		createCmd.Flags().StringSliceVar(&dnsNames, "dns-names", []string{}, "DNS names")
		createCmd.Flags().StringSliceVar(&ipAddresses, "ip-addresses", []string{}, "IP addresses")

		cmd.AddCommand(createCmd)
	}
}
