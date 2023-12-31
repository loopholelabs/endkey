// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// ModelsDeleteAPIKeyRequest models delete API key request
//
// swagger:model models.DeleteAPIKeyRequest
type ModelsDeleteAPIKeyRequest struct {

	// authority name
	AuthorityName string `json:"authority_name,omitempty"`

	// name
	Name string `json:"name,omitempty"`
}

// Validate validates this models delete API key request
func (m *ModelsDeleteAPIKeyRequest) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this models delete API key request based on context it is used
func (m *ModelsDeleteAPIKeyRequest) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *ModelsDeleteAPIKeyRequest) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *ModelsDeleteAPIKeyRequest) UnmarshalBinary(b []byte) error {
	var res ModelsDeleteAPIKeyRequest
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
