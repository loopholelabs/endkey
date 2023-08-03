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
	"github.com/loopholelabs/endkey/cmd/ca/template/client"
	"github.com/loopholelabs/endkey/cmd/ca/template/server"
	"github.com/loopholelabs/endkey/internal/config"
	"github.com/spf13/cobra"
)

// Cmd encapsulates the commands for template.
func Cmd() command.SetupCommand[*config.Config] {
	return func(cmd *cobra.Command, ch *cmdutils.Helper[*config.Config]) {
		templateCmd := &cobra.Command{
			Use:   "template",
			Short: "Create, list, and manage Templates",
		}

		serverSetup := server.Cmd()
		serverSetup(templateCmd, ch)

		clientSetup := client.Cmd()
		clientSetup(templateCmd, ch)

		cmd.AddCommand(templateCmd)
	}
}
