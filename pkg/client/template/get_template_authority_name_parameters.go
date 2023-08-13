// Code generated by go-swagger; DO NOT EDIT.

package template

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"
	"net/http"
	"time"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/runtime"
	cr "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"
)

// NewGetTemplateAuthorityNameParams creates a new GetTemplateAuthorityNameParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewGetTemplateAuthorityNameParams() *GetTemplateAuthorityNameParams {
	return &GetTemplateAuthorityNameParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewGetTemplateAuthorityNameParamsWithTimeout creates a new GetTemplateAuthorityNameParams object
// with the ability to set a timeout on a request.
func NewGetTemplateAuthorityNameParamsWithTimeout(timeout time.Duration) *GetTemplateAuthorityNameParams {
	return &GetTemplateAuthorityNameParams{
		timeout: timeout,
	}
}

// NewGetTemplateAuthorityNameParamsWithContext creates a new GetTemplateAuthorityNameParams object
// with the ability to set a context for a request.
func NewGetTemplateAuthorityNameParamsWithContext(ctx context.Context) *GetTemplateAuthorityNameParams {
	return &GetTemplateAuthorityNameParams{
		Context: ctx,
	}
}

// NewGetTemplateAuthorityNameParamsWithHTTPClient creates a new GetTemplateAuthorityNameParams object
// with the ability to set a custom HTTPClient for a request.
func NewGetTemplateAuthorityNameParamsWithHTTPClient(client *http.Client) *GetTemplateAuthorityNameParams {
	return &GetTemplateAuthorityNameParams{
		HTTPClient: client,
	}
}

/*
GetTemplateAuthorityNameParams contains all the parameters to send to the API endpoint

	for the get template authority name operation.

	Typically these are written to a http.Request.
*/
type GetTemplateAuthorityNameParams struct {

	/* AuthorityName.

	   Authority Name
	*/
	AuthorityName string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the get template authority name params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetTemplateAuthorityNameParams) WithDefaults() *GetTemplateAuthorityNameParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the get template authority name params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetTemplateAuthorityNameParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the get template authority name params
func (o *GetTemplateAuthorityNameParams) WithTimeout(timeout time.Duration) *GetTemplateAuthorityNameParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the get template authority name params
func (o *GetTemplateAuthorityNameParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the get template authority name params
func (o *GetTemplateAuthorityNameParams) WithContext(ctx context.Context) *GetTemplateAuthorityNameParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the get template authority name params
func (o *GetTemplateAuthorityNameParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the get template authority name params
func (o *GetTemplateAuthorityNameParams) WithHTTPClient(client *http.Client) *GetTemplateAuthorityNameParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the get template authority name params
func (o *GetTemplateAuthorityNameParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithAuthorityName adds the authorityName to the get template authority name params
func (o *GetTemplateAuthorityNameParams) WithAuthorityName(authorityName string) *GetTemplateAuthorityNameParams {
	o.SetAuthorityName(authorityName)
	return o
}

// SetAuthorityName adds the authorityName to the get template authority name params
func (o *GetTemplateAuthorityNameParams) SetAuthorityName(authorityName string) {
	o.AuthorityName = authorityName
}

// WriteToRequest writes these params to a swagger request
func (o *GetTemplateAuthorityNameParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	// path param authority_name
	if err := r.SetPathParam("authority_name", o.AuthorityName); err != nil {
		return err
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}