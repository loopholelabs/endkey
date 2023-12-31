// Code generated by go-swagger; DO NOT EDIT.

package apikey

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

	"github.com/loopholelabs/endkey/pkg/client/models"
)

// NewPostApikeyParams creates a new PostApikeyParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewPostApikeyParams() *PostApikeyParams {
	return &PostApikeyParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewPostApikeyParamsWithTimeout creates a new PostApikeyParams object
// with the ability to set a timeout on a request.
func NewPostApikeyParamsWithTimeout(timeout time.Duration) *PostApikeyParams {
	return &PostApikeyParams{
		timeout: timeout,
	}
}

// NewPostApikeyParamsWithContext creates a new PostApikeyParams object
// with the ability to set a context for a request.
func NewPostApikeyParamsWithContext(ctx context.Context) *PostApikeyParams {
	return &PostApikeyParams{
		Context: ctx,
	}
}

// NewPostApikeyParamsWithHTTPClient creates a new PostApikeyParams object
// with the ability to set a custom HTTPClient for a request.
func NewPostApikeyParamsWithHTTPClient(client *http.Client) *PostApikeyParams {
	return &PostApikeyParams{
		HTTPClient: client,
	}
}

/*
PostApikeyParams contains all the parameters to send to the API endpoint

	for the post apikey operation.

	Typically these are written to a http.Request.
*/
type PostApikeyParams struct {

	/* Request.

	   Create API Key Request
	*/
	Request *models.ModelsCreateAPIKeyRequest

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the post apikey params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *PostApikeyParams) WithDefaults() *PostApikeyParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the post apikey params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *PostApikeyParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the post apikey params
func (o *PostApikeyParams) WithTimeout(timeout time.Duration) *PostApikeyParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the post apikey params
func (o *PostApikeyParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the post apikey params
func (o *PostApikeyParams) WithContext(ctx context.Context) *PostApikeyParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the post apikey params
func (o *PostApikeyParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the post apikey params
func (o *PostApikeyParams) WithHTTPClient(client *http.Client) *PostApikeyParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the post apikey params
func (o *PostApikeyParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithRequest adds the request to the post apikey params
func (o *PostApikeyParams) WithRequest(request *models.ModelsCreateAPIKeyRequest) *PostApikeyParams {
	o.SetRequest(request)
	return o
}

// SetRequest adds the request to the post apikey params
func (o *PostApikeyParams) SetRequest(request *models.ModelsCreateAPIKeyRequest) {
	o.Request = request
}

// WriteToRequest writes these params to a swagger request
func (o *PostApikeyParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error
	if o.Request != nil {
		if err := r.SetBodyParam(o.Request); err != nil {
			return err
		}
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
