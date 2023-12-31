// Code generated by ent, DO NOT EDIT.

package ent

import (
	"time"

	"github.com/loopholelabs/endkey/internal/ent/apikey"
	"github.com/loopholelabs/endkey/internal/ent/authority"
	"github.com/loopholelabs/endkey/internal/ent/rootkey"
	"github.com/loopholelabs/endkey/internal/ent/schema"
	"github.com/loopholelabs/endkey/internal/ent/template"
	"github.com/loopholelabs/endkey/internal/ent/userkey"
)

// The init function reads all schema descriptors with runtime code
// (default values, validators, hooks and policies) and stitches it
// to their package variables.
func init() {
	apikeyFields := schema.APIKey{}.Fields()
	_ = apikeyFields
	// apikeyDescCreatedAt is the schema descriptor for created_at field.
	apikeyDescCreatedAt := apikeyFields[0].Descriptor()
	// apikey.DefaultCreatedAt holds the default value on creation for the created_at field.
	apikey.DefaultCreatedAt = apikeyDescCreatedAt.Default.(func() time.Time)
	// apikeyDescName is the schema descriptor for name field.
	apikeyDescName := apikeyFields[2].Descriptor()
	// apikey.NameValidator is a validator for the "name" field. It is called by the builders before save.
	apikey.NameValidator = apikeyDescName.Validators[0].(func(string) error)
	// apikeyDescSalt is the schema descriptor for salt field.
	apikeyDescSalt := apikeyFields[3].Descriptor()
	// apikey.SaltValidator is a validator for the "salt" field. It is called by the builders before save.
	apikey.SaltValidator = apikeyDescSalt.Validators[0].(func([]byte) error)
	// apikeyDescHash is the schema descriptor for hash field.
	apikeyDescHash := apikeyFields[4].Descriptor()
	// apikey.HashValidator is a validator for the "hash" field. It is called by the builders before save.
	apikey.HashValidator = apikeyDescHash.Validators[0].(func([]byte) error)
	// apikeyDescID is the schema descriptor for id field.
	apikeyDescID := apikeyFields[1].Descriptor()
	// apikey.IDValidator is a validator for the "id" field. It is called by the builders before save.
	apikey.IDValidator = apikeyDescID.Validators[0].(func(string) error)
	authorityFields := schema.Authority{}.Fields()
	_ = authorityFields
	// authorityDescCreatedAt is the schema descriptor for created_at field.
	authorityDescCreatedAt := authorityFields[0].Descriptor()
	// authority.DefaultCreatedAt holds the default value on creation for the created_at field.
	authority.DefaultCreatedAt = authorityDescCreatedAt.Default.(func() time.Time)
	// authorityDescName is the schema descriptor for name field.
	authorityDescName := authorityFields[2].Descriptor()
	// authority.NameValidator is a validator for the "name" field. It is called by the builders before save.
	authority.NameValidator = authorityDescName.Validators[0].(func(string) error)
	// authorityDescCaCertificatePem is the schema descriptor for ca_certificate_pem field.
	authorityDescCaCertificatePem := authorityFields[3].Descriptor()
	// authority.CaCertificatePemValidator is a validator for the "ca_certificate_pem" field. It is called by the builders before save.
	authority.CaCertificatePemValidator = authorityDescCaCertificatePem.Validators[0].(func([]byte) error)
	// authorityDescEncryptedPrivateKey is the schema descriptor for encrypted_private_key field.
	authorityDescEncryptedPrivateKey := authorityFields[4].Descriptor()
	// authority.EncryptedPrivateKeyValidator is a validator for the "encrypted_private_key" field. It is called by the builders before save.
	authority.EncryptedPrivateKeyValidator = authorityDescEncryptedPrivateKey.Validators[0].(func(string) error)
	// authorityDescID is the schema descriptor for id field.
	authorityDescID := authorityFields[1].Descriptor()
	// authority.IDValidator is a validator for the "id" field. It is called by the builders before save.
	authority.IDValidator = authorityDescID.Validators[0].(func(string) error)
	rootkeyFields := schema.RootKey{}.Fields()
	_ = rootkeyFields
	// rootkeyDescCreatedAt is the schema descriptor for created_at field.
	rootkeyDescCreatedAt := rootkeyFields[0].Descriptor()
	// rootkey.DefaultCreatedAt holds the default value on creation for the created_at field.
	rootkey.DefaultCreatedAt = rootkeyDescCreatedAt.Default.(func() time.Time)
	// rootkeyDescName is the schema descriptor for name field.
	rootkeyDescName := rootkeyFields[2].Descriptor()
	// rootkey.NameValidator is a validator for the "name" field. It is called by the builders before save.
	rootkey.NameValidator = rootkeyDescName.Validators[0].(func(string) error)
	// rootkeyDescSalt is the schema descriptor for salt field.
	rootkeyDescSalt := rootkeyFields[3].Descriptor()
	// rootkey.SaltValidator is a validator for the "salt" field. It is called by the builders before save.
	rootkey.SaltValidator = rootkeyDescSalt.Validators[0].(func([]byte) error)
	// rootkeyDescHash is the schema descriptor for hash field.
	rootkeyDescHash := rootkeyFields[4].Descriptor()
	// rootkey.HashValidator is a validator for the "hash" field. It is called by the builders before save.
	rootkey.HashValidator = rootkeyDescHash.Validators[0].(func([]byte) error)
	// rootkeyDescID is the schema descriptor for id field.
	rootkeyDescID := rootkeyFields[1].Descriptor()
	// rootkey.IDValidator is a validator for the "id" field. It is called by the builders before save.
	rootkey.IDValidator = rootkeyDescID.Validators[0].(func(string) error)
	templateFields := schema.Template{}.Fields()
	_ = templateFields
	// templateDescCreatedAt is the schema descriptor for created_at field.
	templateDescCreatedAt := templateFields[0].Descriptor()
	// template.DefaultCreatedAt holds the default value on creation for the created_at field.
	template.DefaultCreatedAt = templateDescCreatedAt.Default.(func() time.Time)
	// templateDescName is the schema descriptor for name field.
	templateDescName := templateFields[2].Descriptor()
	// template.NameValidator is a validator for the "name" field. It is called by the builders before save.
	template.NameValidator = templateDescName.Validators[0].(func(string) error)
	// templateDescCommonName is the schema descriptor for common_name field.
	templateDescCommonName := templateFields[3].Descriptor()
	// template.CommonNameValidator is a validator for the "common_name" field. It is called by the builders before save.
	template.CommonNameValidator = templateDescCommonName.Validators[0].(func(string) error)
	// templateDescTag is the schema descriptor for tag field.
	templateDescTag := templateFields[4].Descriptor()
	// template.TagValidator is a validator for the "tag" field. It is called by the builders before save.
	template.TagValidator = templateDescTag.Validators[0].(func(string) error)
	// templateDescValidity is the schema descriptor for validity field.
	templateDescValidity := templateFields[5].Descriptor()
	// template.ValidityValidator is a validator for the "validity" field. It is called by the builders before save.
	template.ValidityValidator = templateDescValidity.Validators[0].(func(string) error)
	// templateDescAllowAdditionalDNSNames is the schema descriptor for allow_additional_dns_names field.
	templateDescAllowAdditionalDNSNames := templateFields[7].Descriptor()
	// template.DefaultAllowAdditionalDNSNames holds the default value on creation for the allow_additional_dns_names field.
	template.DefaultAllowAdditionalDNSNames = templateDescAllowAdditionalDNSNames.Default.(bool)
	// templateDescAllowAdditionalIps is the schema descriptor for allow_additional_ips field.
	templateDescAllowAdditionalIps := templateFields[9].Descriptor()
	// template.DefaultAllowAdditionalIps holds the default value on creation for the allow_additional_ips field.
	template.DefaultAllowAdditionalIps = templateDescAllowAdditionalIps.Default.(bool)
	// templateDescAllowOverrideCommonName is the schema descriptor for allow_override_common_name field.
	templateDescAllowOverrideCommonName := templateFields[10].Descriptor()
	// template.DefaultAllowOverrideCommonName holds the default value on creation for the allow_override_common_name field.
	template.DefaultAllowOverrideCommonName = templateDescAllowOverrideCommonName.Default.(bool)
	// templateDescClient is the schema descriptor for client field.
	templateDescClient := templateFields[11].Descriptor()
	// template.DefaultClient holds the default value on creation for the client field.
	template.DefaultClient = templateDescClient.Default.(bool)
	// templateDescServer is the schema descriptor for server field.
	templateDescServer := templateFields[12].Descriptor()
	// template.DefaultServer holds the default value on creation for the server field.
	template.DefaultServer = templateDescServer.Default.(bool)
	// templateDescID is the schema descriptor for id field.
	templateDescID := templateFields[1].Descriptor()
	// template.IDValidator is a validator for the "id" field. It is called by the builders before save.
	template.IDValidator = templateDescID.Validators[0].(func(string) error)
	userkeyFields := schema.UserKey{}.Fields()
	_ = userkeyFields
	// userkeyDescCreatedAt is the schema descriptor for created_at field.
	userkeyDescCreatedAt := userkeyFields[0].Descriptor()
	// userkey.DefaultCreatedAt holds the default value on creation for the created_at field.
	userkey.DefaultCreatedAt = userkeyDescCreatedAt.Default.(func() time.Time)
	// userkeyDescName is the schema descriptor for name field.
	userkeyDescName := userkeyFields[2].Descriptor()
	// userkey.NameValidator is a validator for the "name" field. It is called by the builders before save.
	userkey.NameValidator = userkeyDescName.Validators[0].(func(string) error)
	// userkeyDescSalt is the schema descriptor for salt field.
	userkeyDescSalt := userkeyFields[3].Descriptor()
	// userkey.SaltValidator is a validator for the "salt" field. It is called by the builders before save.
	userkey.SaltValidator = userkeyDescSalt.Validators[0].(func([]byte) error)
	// userkeyDescHash is the schema descriptor for hash field.
	userkeyDescHash := userkeyFields[4].Descriptor()
	// userkey.HashValidator is a validator for the "hash" field. It is called by the builders before save.
	userkey.HashValidator = userkeyDescHash.Validators[0].(func([]byte) error)
	// userkeyDescID is the schema descriptor for id field.
	userkeyDescID := userkeyFields[1].Descriptor()
	// userkey.IDValidator is a validator for the "id" field. It is called by the builders before save.
	userkey.IDValidator = userkeyDescID.Validators[0].(func(string) error)
}
