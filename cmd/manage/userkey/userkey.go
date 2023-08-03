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

package userkey

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

type userKeyModel struct {
	Created string `header:"created_at" json:"created_at"`
	ID      string `header:"id" json:"id"`
	Name    string `header:"name" json:"name"`
	Value   string `header:"value" json:"value"`
}

type userKeyRedactedModel struct {
	Created string `header:"created_at" json:"created_at"`
	ID      string `header:"id" json:"id"`
	Name    string `header:"name" json:"name"`
}

// Cmd encapsulates the commands for rootkey.
func Cmd() command.SetupCommand[*config.Config] {

	var rootkey string

	return func(cmd *cobra.Command, ch *cmdutils.Helper[*config.Config]) {
		userkeyCmd := &cobra.Command{
			Use:   "userkey",
			Short: "Create, list, and manage User Keys",
			PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
				ch.Config.AuthenticationKey = rootkey

				err := ch.Config.Validate()
				if err != nil {
					return err
				}

				if ch.Config.AuthenticationKey == "" {
					return ErrRootKeyRequired
				}

				return nil
			},
		}

		listSetup := ListCmd()
		listSetup(userkeyCmd, ch)

		createSetup := CreateCmd()
		createSetup(userkeyCmd, ch)

		deleteSetup := DeleteCmd()
		deleteSetup(userkeyCmd, ch)

		rotateSetup := RotateCmd()
		rotateSetup(userkeyCmd, ch)

		userkeyCmd.PersistentFlags().StringVar(&rootkey, "root-key", "", "The root key for the EndKey API")

		cmd.AddCommand(userkeyCmd)
	}
}
