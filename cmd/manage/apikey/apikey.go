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
	"errors"
	"github.com/loopholelabs/cmdutils"
	"github.com/loopholelabs/cmdutils/pkg/command"
	"github.com/loopholelabs/endkey/internal/config"
	"github.com/spf13/cobra"
)

var (
	ErrRootKeyRequired = errors.New("rootkey is required")
)

type apiKeyModel struct {
	Created        string `header:"created_at" json:"created_at"`
	ID             string `header:"id" json:"id"`
	Name           string `header:"name" json:"name"`
	Authority      string `header:"authority_id" json:"authority"`
	ServerTemplate string `header:"server_template_id" json:"server_template"`
	ClientTemplate string `header:"client_template_id" json:"client_template_id"`
	Value          string `header:"value" json:"value"`
}

type apiKeyRedactedModel struct {
	Created        string `header:"created_at" json:"created_at"`
	ID             string `header:"id" json:"id"`
	Name           string `header:"name" json:"name"`
	Authority      string `header:"authority" json:"authority"`
	ServerTemplate string `header:"server_template" json:"server_template"`
	ClientTemplate string `header:"client_template" json:"client_template"`
}

// Cmd encapsulates the commands for rootkey.
func Cmd() command.SetupCommand[*config.Config] {

	var rootkey string

	return func(cmd *cobra.Command, ch *cmdutils.Helper[*config.Config]) {
		apikeyCmd := &cobra.Command{
			Use:   "apikey",
			Short: "Create, list, and manage API Keys",
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
		listSetup(apikeyCmd, ch)

		createSetup := CreateCmd()
		createSetup(apikeyCmd, ch)

		deleteSetup := DeleteCmd()
		deleteSetup(apikeyCmd, ch)

		apikeyCmd.PersistentFlags().StringVar(&rootkey, "root-key", "", "The root key for the EndKey API")

		cmd.AddCommand(apikeyCmd)
	}
}
