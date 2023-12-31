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
	"github.com/loopholelabs/endkey/internal/config"
	"github.com/spf13/cobra"
)

type authorityModel struct {
	Created       string `header:"created_at" json:"created_at"`
	ID            string `header:"id" json:"id"`
	Name          string `header:"name" json:"name"`
	CommonName    string `header:"common_name" json:"common_name"`
	Tag           string `header:"tag" json:"tag"`
	Expiry        string `header:"expiry" json:"expiry"`
	CACertificate string `header:"ca_certificate" json:"ca_certificate"`
}

type authorityRedactedModel struct {
	Created       string `header:"created_at" json:"created_at"`
	ID            string `header:"id" json:"id"`
	Name          string `header:"name" json:"name"`
	CommonName    string `header:"common_name" json:"common_name"`
	Tag           string `header:"tag" json:"tag"`
	Expiry        string `header:"expiry" json:"expiry"`
	CACertificate string `header:"ca_certificate" json:"ca_certificate"`
}

// Cmd encapsulates the commands for authority.
func Cmd() command.SetupCommand[*config.Config] {
	return func(cmd *cobra.Command, ch *cmdutils.Helper[*config.Config]) {
		authorityCmd := &cobra.Command{
			Use:   "authority",
			Short: "Create, list, and manage Authorities",
		}

		listSetup := ListCmd()
		listSetup(authorityCmd, ch)

		createSetup := CreateCmd()
		createSetup(authorityCmd, ch)

		deleteSetup := DeleteCmd()
		deleteSetup(authorityCmd, ch)

		getSetup := GetCmd()
		getSetup(authorityCmd, ch)

		cmd.AddCommand(authorityCmd)
	}
}
