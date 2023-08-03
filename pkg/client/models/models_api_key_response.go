// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// ModelsAPIKeyResponse models API key response
//
// swagger:model models.APIKeyResponse
type ModelsAPIKeyResponse struct {

	// authority name
	AuthorityName string `json:"authority_name,omitempty"`

	// created at
	CreatedAt string `json:"created_at,omitempty"`

	// id
	ID string `json:"id,omitempty"`

	// name
	Name string `json:"name,omitempty"`

	// secret
	Secret string `json:"secret,omitempty"`

	// template kind
	TemplateKind string `json:"template_kind,omitempty"`

	// template name
	TemplateName string `json:"template_name,omitempty"`
}

// Validate validates this models API key response
func (m *ModelsAPIKeyResponse) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this models API key response based on context it is used
func (m *ModelsAPIKeyResponse) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *ModelsAPIKeyResponse) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *ModelsAPIKeyResponse) UnmarshalBinary(b []byte) error {
	var res ModelsAPIKeyResponse
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
