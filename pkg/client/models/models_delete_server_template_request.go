// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// ModelsDeleteServerTemplateRequest models delete server template request
//
// swagger:model models.DeleteServerTemplateRequest
type ModelsDeleteServerTemplateRequest struct {

	// authority name
	AuthorityName string `json:"authority_name,omitempty"`

	// name
	Name string `json:"name,omitempty"`
}

// Validate validates this models delete server template request
func (m *ModelsDeleteServerTemplateRequest) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this models delete server template request based on context it is used
func (m *ModelsDeleteServerTemplateRequest) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *ModelsDeleteServerTemplateRequest) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *ModelsDeleteServerTemplateRequest) UnmarshalBinary(b []byte) error {
	var res ModelsDeleteServerTemplateRequest
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}