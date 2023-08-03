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
	"fmt"
	"github.com/loopholelabs/cmdutils"
	"github.com/loopholelabs/cmdutils/pkg/command"
	"github.com/loopholelabs/cmdutils/pkg/printer"
	"github.com/loopholelabs/endkey/internal/config"
	"github.com/loopholelabs/endkey/internal/key"
	"github.com/loopholelabs/endkey/pkg/client/userkey"
	"github.com/spf13/cobra"
)

// RotateCmd encapsulates the commands for rotating User Keys
func RotateCmd() command.SetupCommand[*config.Config] {
	return func(cmd *cobra.Command, ch *cmdutils.Helper[*config.Config]) {
		deleteCmd := &cobra.Command{
			Use:   "rotate <name>",
			Args:  cobra.ExactArgs(1),
			Short: "rotate a User Key with the given name",
			RunE: func(cmd *cobra.Command, args []string) error {
				ctx := cmd.Context()
				client := ch.Config.Client()
				name := args[0]

				end := ch.Printer.PrintProgress(fmt.Sprintf("Rotating User Key %s...", name))

				res, err := client.Userkey.PostUserkeyRotateName(userkey.NewPostUserkeyRotateNameParamsWithContext(ctx).WithName(name))
				end()
				if err != nil {
					return err
				}

				value := fmt.Sprintf("%s%s.%s", key.UserPrefixString, res.GetPayload().ID, res.GetPayload().Secret)

				if ch.Printer.Format() == printer.Human {
					ch.Printer.Printf("Rotated User Key '%s': %s (this will only be displayed once)\n", printer.Bold(res.Payload.Name), printer.BoldGreen(value))
					return nil
				}

				return ch.Printer.PrintResource(userKeyModel{
					Created: res.GetPayload().CreatedAt,
					ID:      res.GetPayload().ID,
					Name:    res.GetPayload().Name,
					Value:   value,
				})
			},
		}

		cmd.AddCommand(deleteCmd)
	}
}
