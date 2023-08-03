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

package certificate

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"github.com/loopholelabs/cmdutils"
	"github.com/loopholelabs/cmdutils/pkg/command"
	"github.com/loopholelabs/cmdutils/pkg/printer"
	"github.com/loopholelabs/endkey/internal/config"
	"github.com/loopholelabs/endkey/internal/utils"
	"github.com/loopholelabs/endkey/pkg/client"
	"github.com/loopholelabs/endkey/pkg/client/certificate"
	"github.com/loopholelabs/endkey/pkg/client/models"
	"github.com/spf13/cobra"
	"os"
	"os/exec"
	"strings"
	"time"
)

// ClientCmd encapsulates the commands for getting a Client Certificate
func ClientCmd() command.SetupCommand[*config.Config] {
	var additionalDNSNames []string
	var additionalIPAddresses []string

	var daemon bool
	var execute string

	return func(cmd *cobra.Command, ch *cmdutils.Helper[*config.Config]) {
		clientCmd := &cobra.Command{
			Use:   "client <template> <root-path> <certificate-path> <key-path>",
			Args:  cobra.ExactArgs(4),
			Short: "Get a Client Certificate with the given template",
			RunE: func(cmd *cobra.Command, args []string) error {
				ctx := cmd.Context()

				template := args[0]
				rootPath := args[1]
				certificatePath := args[2]
				keyPath := args[3]

				var end func()
				interval := time.NewTimer(time.Millisecond * 100)
				if daemon {
					ch.Printer.Printf("Starting Daemon for Client Certificate for Template %s ...", template)
				} else {
					end = ch.Printer.PrintProgress(fmt.Sprintf("Getting Client Certificate for Template %s ...", template))
				}

				for {
					select {
					case <-ctx.Done():
						if end != nil {
							end()
						}
						return nil
					case <-interval.C:
						res, privateKey, err := GetCertificate(ctx, ch.Config.Client(), template, additionalDNSNames, additionalIPAddresses)
						if end != nil {
							end()
						}
						if err != nil {
							return fmt.Errorf("failed to get client certificate: %w", err)
						}

						root, err := base64.StdEncoding.DecodeString(res.CaCertificate)
						if err != nil {
							return fmt.Errorf("failed to decode root certificate: %w", err)
						}

						err = os.WriteFile(rootPath, root, 0644)
						if err != nil {
							return fmt.Errorf("failed to write root certificate: %w", err)
						}

						cert, err := base64.StdEncoding.DecodeString(res.PublicCertificate)
						if err != nil {
							return fmt.Errorf("failed to decode certificate: %w", err)
						}

						err = os.WriteFile(certificatePath, cert, 0644)
						if err != nil {
							return fmt.Errorf("failed to write certificate: %w", err)
						}

						err = os.WriteFile(keyPath, utils.EncodeECDSAPrivateKey(privateKey), 0644)
						if err != nil {
							return fmt.Errorf("failed to write private key: %w", err)
						}

						if ch.Printer.Format() == printer.Human {
							ch.Printer.Printf("Created Client Certificate from Template '%s'\n", printer.Bold(res.TemplateName))
						} else {
							err := ch.Printer.PrintResource(clientModel{
								Authority:     res.AuthorityName,
								Template:      res.TemplateName,
								AdditionalDNS: strings.Join(res.AdditionalDNSNames, ","),
								AdditionalIP:  strings.Join(res.AdditionalIPAddresses, ","),
								Expiry:        res.Expiry,
							})
							if err != nil {
								return fmt.Errorf("failed to print resource: %w", err)
							}
						}

						if execute != "" {
							ch.Printer.Printf("Executing Command: %s\n\n", execute)
							a := strings.Fields(execute)
							c := exec.CommandContext(ctx, a[0], a[1:]...)
							out, err := c.CombinedOutput()
							if err != nil {
								return fmt.Errorf("failed to execute command: %w\n%s\n", err, out)
							}
							ch.Printer.Printf("%s\n\nFinished Executing Command\n", out)

						}

						if daemon {
							decodedCert, err := utils.DecodeX509Certificate(cert)
							if err != nil {
								return fmt.Errorf("failed to decode certificate: %w", err)
							}
							expiry := time.Until(decodedCert.NotAfter) / 2
							ch.Printer.Printf("Waiting for %s to renew certificate...\n", expiry)
							interval.Reset(expiry)
						} else {
							return nil
						}
					}
				}
			},
		}

		clientCmd.Flags().StringSliceVar(&additionalDNSNames, "dns", []string{}, "Additional DNS Names to add to the certificate")
		clientCmd.Flags().StringSliceVar(&additionalIPAddresses, "ip", []string{}, "Additional IP Addresses to add to the certificate")

		clientCmd.Flags().BoolVar(&daemon, "daemon", false, "Run the command as a daemon")
		clientCmd.Flags().StringVar(&execute, "execute", "", "Execute a command after creating the certificate")

		cmd.AddCommand(clientCmd)
	}
}

func GetCertificate(ctx context.Context, client *client.EndKeyAPIV1, template string, additionalDNSNames []string, additionalIPAddresses []string) (*models.ModelsClientCertificateResponse, *ecdsa.PrivateKey, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	t := &x509.CertificateRequest{
		SignatureAlgorithm: x509.ECDSAWithSHA256,
	}

	csrPEM, err := x509.CreateCertificateRequest(rand.Reader, t, privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create CSR: %w", err)
	}

	req := &models.ModelsCreateClientCertificateRequest{
		AdditionalDNSNames:    additionalDNSNames,
		AdditionalIPAddresses: additionalIPAddresses,
		Csr:                   base64.StdEncoding.EncodeToString(csrPEM),
		TemplateName:          template,
	}

	res, err := client.Certificate.PostCertificateClient(certificate.NewPostCertificateClientParamsWithContext(ctx).WithRequest(req))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get client certificate: %w", err)
	}

	return res.GetPayload(), privateKey, nil
}
