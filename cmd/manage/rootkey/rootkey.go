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
	"errors"
	"github.com/loopholelabs/cmdutils"
	"github.com/loopholelabs/cmdutils/pkg/command"
	"github.com/loopholelabs/endkey/internal/config"
	"github.com/spf13/cobra"
)

var (
	ErrRootKeyRequired = errors.New("rootkey is required")
)

type rootKeyModel struct {
	Created    string `header:"created_at" json:"created_at"`
	Identifier string `header:"identifier" json:"identifier"`
	Name       string `header:"name" json:"name"`
	Value      string `header:"value" json:"value"`
}

type rootKeyRedactedModel struct {
	Created    string `header:"created_at" json:"created_at"`
	Identifier string `header:"identifier" json:"identifier"`
	Name       string `header:"name" json:"name"`
}

// Cmd encapsulates the commands for rootkey.
func Cmd() command.SetupCommand[*config.Config] {

	var rootkey string

	return func(cmd *cobra.Command, ch *cmdutils.Helper[*config.Config]) {
		rootkeyCmd := &cobra.Command{
			Use:   "rootkey",
			Short: "Create, list, and manage Root Keys",
			PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
				if rootkey == "" {
					return ErrRootKeyRequired
				}

				ch.Config.AuthenticationKey = rootkey

				return ch.Config.Validate()
			},
		}

		listSetup := ListCmd()
		listSetup(rootkeyCmd, ch)

		createSetup := CreateCmd()
		createSetup(rootkeyCmd, ch)

		deleteSetup := DeleteCmd()
		deleteSetup(rootkeyCmd, ch)

		rotateSetup := RotateCmd()
		rotateSetup(rootkeyCmd, ch)

		rootkeyCmd.PersistentFlags().StringVar(&rootkey, "root-key", "", "The root key for the EndKey API")

		cmd.AddCommand(rootkeyCmd)
	}
}
