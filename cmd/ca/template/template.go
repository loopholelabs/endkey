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

package template

import (
	"github.com/loopholelabs/cmdutils"
	"github.com/loopholelabs/cmdutils/pkg/command"
	"github.com/loopholelabs/endkey/internal/config"
	"github.com/spf13/cobra"
)

type templateModel struct {
	Created       string `header:"created_at" json:"created_at"`
	ID            string `header:"id" json:"id"`
	Name          string `header:"name" json:"name"`
	Authority     string `header:"authority" json:"authority"`
	CommonName    string `header:"common_name" json:"common_name"`
	Tag           string `header:"tag" json:"tag"`
	DNSNames      string `header:"dns_names" json:"dns_names"`
	IPAddresses   string `header:"ip_addresses" json:"ip_addresses"`
	Validity      string `header:"validity" json:"validity"`
	AdditionalDNS string `header:"allow_additional_dns_names" json:"allow_additional_dns_names"`
	AdditionalIPs string `header:"allow_additional_ips" json:"allow_additional_ips"`
	Client        string `header:"client" json:"client"`
	Server        string `header:"server" json:"server"`
}

// Cmd encapsulates the commands for template.
func Cmd() command.SetupCommand[*config.Config] {
	return func(cmd *cobra.Command, ch *cmdutils.Helper[*config.Config]) {
		templateCmd := &cobra.Command{
			Use:   "template",
			Short: "Create, list, and manage Templates",
		}

		listSetup := ListCmd()
		listSetup(templateCmd, ch)

		createSetup := CreateCmd()
		createSetup(templateCmd, ch)

		deleteSetup := DeleteCmd()
		deleteSetup(templateCmd, ch)

		cmd.AddCommand(templateCmd)
	}
}
