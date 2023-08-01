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

package api

import (
	"fmt"
	"github.com/loopholelabs/cmdutils"
	"github.com/loopholelabs/cmdutils/pkg/command"
	"github.com/loopholelabs/endkey/internal/log"
	"github.com/loopholelabs/endkey/internal/utils"
	"github.com/loopholelabs/endkey/pkg/api"
	"github.com/loopholelabs/endkey/pkg/config"
	"github.com/spf13/cobra"
)

// Cmd encapsulates the commands for starting the API
func Cmd() command.SetupCommand[*config.Config] {
	return func(cmd *cobra.Command, ch *cmdutils.Helper[*config.Config]) {
		apiCmd := &cobra.Command{
			Use: "api",
			PreRunE: func(cmd *cobra.Command, args []string) error {
				log.Init(ch.Config.GetLogFile(), ch.Debug())
				err := ch.Config.GlobalRequiredFlags(cmd)
				if err != nil {
					return err
				}

				return ch.Config.Validate()
			},
			RunE: func(cmd *cobra.Command, args []string) error {
				ch.Printer.Println("Starting EndKey API listening on ", ch.Config.ListenAddress)
				errCh := make(chan error, 1)
				a, err := api.New(ch.Config, log.Logger)
				go func() {
					errCh <- a.Start()
				}()

				err = utils.WaitForSignal(errCh)
				if err != nil {
					_ = a.Stop()
					return fmt.Errorf("error while starting EndKey API: %w", err)
				}

				err = a.Stop()
				if err != nil {
					return fmt.Errorf("failed to stop EndKey API: %w", err)
				}
				return nil
			},
		}
		cmd.AddCommand(apiCmd)
	}
}
