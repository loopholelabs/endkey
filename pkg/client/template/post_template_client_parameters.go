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

	"github.com/loopholelabs/endkey/pkg/client/models"
)

// NewPostTemplateClientParams creates a new PostTemplateClientParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewPostTemplateClientParams() *PostTemplateClientParams {
	return &PostTemplateClientParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewPostTemplateClientParamsWithTimeout creates a new PostTemplateClientParams object
// with the ability to set a timeout on a request.
func NewPostTemplateClientParamsWithTimeout(timeout time.Duration) *PostTemplateClientParams {
	return &PostTemplateClientParams{
		timeout: timeout,
	}
}

// NewPostTemplateClientParamsWithContext creates a new PostTemplateClientParams object
// with the ability to set a context for a request.
func NewPostTemplateClientParamsWithContext(ctx context.Context) *PostTemplateClientParams {
	return &PostTemplateClientParams{
		Context: ctx,
	}
}

// NewPostTemplateClientParamsWithHTTPClient creates a new PostTemplateClientParams object
// with the ability to set a custom HTTPClient for a request.
func NewPostTemplateClientParamsWithHTTPClient(client *http.Client) *PostTemplateClientParams {
	return &PostTemplateClientParams{
		HTTPClient: client,
	}
}

/*
PostTemplateClientParams contains all the parameters to send to the API endpoint

	for the post template client operation.

	Typically these are written to a http.Request.
*/
type PostTemplateClientParams struct {

	/* Request.

	   Create Client Template Request
	*/
	Request *models.ModelsCreateClientTemplateRequest

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the post template client params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *PostTemplateClientParams) WithDefaults() *PostTemplateClientParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the post template client params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *PostTemplateClientParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the post template client params
func (o *PostTemplateClientParams) WithTimeout(timeout time.Duration) *PostTemplateClientParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the post template client params
func (o *PostTemplateClientParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the post template client params
func (o *PostTemplateClientParams) WithContext(ctx context.Context) *PostTemplateClientParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the post template client params
func (o *PostTemplateClientParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the post template client params
func (o *PostTemplateClientParams) WithHTTPClient(client *http.Client) *PostTemplateClientParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the post template client params
func (o *PostTemplateClientParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithRequest adds the request to the post template client params
func (o *PostTemplateClientParams) WithRequest(request *models.ModelsCreateClientTemplateRequest) *PostTemplateClientParams {
	o.SetRequest(request)
	return o
}

// SetRequest adds the request to the post template client params
func (o *PostTemplateClientParams) SetRequest(request *models.ModelsCreateClientTemplateRequest) {
	o.Request = request
}

// WriteToRequest writes these params to a swagger request
func (o *PostTemplateClientParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

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
