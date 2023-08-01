// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// ModelsClientTemplateResponse models client template response
//
// swagger:model models.ClientTemplateResponse
type ModelsClientTemplateResponse struct {

	// allow additional dns names
	AllowAdditionalDNSNames bool `json:"allow_additional_dns_names,omitempty"`

	// allow additional ips
	AllowAdditionalIps bool `json:"allow_additional_ips,omitempty"`

	// authority
	Authority string `json:"authority,omitempty"`

	// common name
	CommonName string `json:"common_name,omitempty"`

	// dns names
	DNSNames []string `json:"dns_names"`

	// identifier
	Identifier string `json:"identifier,omitempty"`

	// ip addresses
	IPAddresses []string `json:"ip_addresses"`

	// tag
	Tag string `json:"tag,omitempty"`

	// validity
	Validity string `json:"validity,omitempty"`
}

// Validate validates this models client template response
func (m *ModelsClientTemplateResponse) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this models client template response based on context it is used
func (m *ModelsClientTemplateResponse) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *ModelsClientTemplateResponse) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *ModelsClientTemplateResponse) UnmarshalBinary(b []byte) error {
	var res ModelsClientTemplateResponse
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}