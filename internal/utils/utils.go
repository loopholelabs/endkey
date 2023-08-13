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

// Package utils contains general utility helpers for use throughout Lynk
package utils

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"github.com/gofiber/fiber/v2"
	"math/rand"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
const (
	letterIdxBits = 6                    // 6 bits to represent a letter index
	letterIdxMask = 1<<letterIdxBits - 1 // All 1-bits, as many as letterIdxBits
	letterIdxMax  = 63 / letterIdxBits   // # of letter indices fitting in 63 bits
)

var (
	invalidString = regexp.MustCompile(`[^a-zA-Z0-9\-]`)

	ErrInvalidPKCS8PrivateKey = errors.New("invalid PKCS8 private key")
)

// RandomString generates a random string of length n
func RandomString(n int) string {
	b := make([]byte, n)
	// A src.Int63() generates 63 random bits, enough for letterIdxMax characters!
	for i, cache, remain := n-1, rand.Int63(), letterIdxMax; i >= 0; {
		if remain == 0 {
			cache, remain = rand.Int63(), letterIdxMax
		}
		if idx := int(cache & letterIdxMask); idx < len(letterBytes) {
			b[i] = letterBytes[idx]
			i--
		}
		cache >>= letterIdxBits
		remain--
	}

	return *(*string)(unsafe.Pointer(&b))
}

// DefaultFiberApp returns a new fiber app with sensible defaults
func DefaultFiberApp() *fiber.App {
	return fiber.New(fiber.Config{
		DisableStartupMessage: true,
		ReadTimeout:           time.Second * 10,
		WriteTimeout:          time.Second * 10,
		IdleTimeout:           time.Second * 10,
		JSONEncoder:           json.Marshal,
		JSONDecoder:           json.Unmarshal,
		BodyLimit:             1024 * 1024 * 10,
	})
}

func EncodeECDSAPrivateKey(privateKey *ecdsa.PrivateKey) []byte {
	marshalled, _ := x509.MarshalPKCS8PrivateKey(privateKey)
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: marshalled})
}

func DecodeECDSAPrivateKey(encoded []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(encoded)
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	if privateKey, ok := key.(*ecdsa.PrivateKey); ok {
		return privateKey, nil
	}
	return nil, ErrInvalidPKCS8PrivateKey
}

func EncodeX509Certificate(caBytes []byte) ([]byte, error) {
	caPEMBuffer := new(bytes.Buffer)
	err := pem.Encode(caPEMBuffer, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caBytes,
	})
	if err != nil {
		return nil, err
	}

	return caPEMBuffer.Bytes(), nil
}

func DecodeX509Certificate(encoded []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(encoded)
	return x509.ParseCertificate(block.Bytes)
}

func DecodeX509CSR(encoded []byte) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode(encoded)
	if block == nil {
		return x509.ParseCertificateRequest(encoded)
	} else {
		return x509.ParseCertificateRequest(block.Bytes)
	}
}

func WaitForSignal(errChan chan error) error {
	sig := make(chan os.Signal, 2)
	defer close(sig)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sig)
	for {
		select {
		case <-sig:
			return nil
		case err := <-errChan:
			if err == nil {
				continue
			}
			return err
		}
	}
}

func ValidString(s string) bool {
	return !invalidString.MatchString(s)
}

func ValidDNS(s string) bool {
	if strings.HasPrefix(s, "-") || strings.HasSuffix(s, "-") {
		return false
	}
	labels := strings.Split(s, ".")
	for _, label := range labels {
		if len(label) < 1 || len(label) > 63 {
			return false
		}
		match, _ := regexp.MatchString("^[a-zA-Z0-9-]+$", label)
		if !match {
			return false
		}
		if strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
	}
	return true
}
