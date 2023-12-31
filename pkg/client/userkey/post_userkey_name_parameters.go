// Code generated by go-swagger; DO NOT EDIT.

package userkey

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

// NewPostUserkeyNameParams creates a new PostUserkeyNameParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewPostUserkeyNameParams() *PostUserkeyNameParams {
	return &PostUserkeyNameParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewPostUserkeyNameParamsWithTimeout creates a new PostUserkeyNameParams object
// with the ability to set a timeout on a request.
func NewPostUserkeyNameParamsWithTimeout(timeout time.Duration) *PostUserkeyNameParams {
	return &PostUserkeyNameParams{
		timeout: timeout,
	}
}

// NewPostUserkeyNameParamsWithContext creates a new PostUserkeyNameParams object
// with the ability to set a context for a request.
func NewPostUserkeyNameParamsWithContext(ctx context.Context) *PostUserkeyNameParams {
	return &PostUserkeyNameParams{
		Context: ctx,
	}
}

// NewPostUserkeyNameParamsWithHTTPClient creates a new PostUserkeyNameParams object
// with the ability to set a custom HTTPClient for a request.
func NewPostUserkeyNameParamsWithHTTPClient(client *http.Client) *PostUserkeyNameParams {
	return &PostUserkeyNameParams{
		HTTPClient: client,
	}
}

/*
PostUserkeyNameParams contains all the parameters to send to the API endpoint

	for the post userkey name operation.

	Typically these are written to a http.Request.
*/
type PostUserkeyNameParams struct {

	/* Name.

	   User Key Name
	*/
	Name string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the post userkey name params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *PostUserkeyNameParams) WithDefaults() *PostUserkeyNameParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the post userkey name params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *PostUserkeyNameParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the post userkey name params
func (o *PostUserkeyNameParams) WithTimeout(timeout time.Duration) *PostUserkeyNameParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the post userkey name params
func (o *PostUserkeyNameParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the post userkey name params
func (o *PostUserkeyNameParams) WithContext(ctx context.Context) *PostUserkeyNameParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the post userkey name params
func (o *PostUserkeyNameParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the post userkey name params
func (o *PostUserkeyNameParams) WithHTTPClient(client *http.Client) *PostUserkeyNameParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the post userkey name params
func (o *PostUserkeyNameParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithName adds the name to the post userkey name params
func (o *PostUserkeyNameParams) WithName(name string) *PostUserkeyNameParams {
	o.SetName(name)
	return o
}

// SetName adds the name to the post userkey name params
func (o *PostUserkeyNameParams) SetName(name string) {
	o.Name = name
}

// WriteToRequest writes these params to a swagger request
func (o *PostUserkeyNameParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	// path param name
	if err := r.SetPathParam("name", o.Name); err != nil {
		return err
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
