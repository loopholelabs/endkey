// Code generated by go-swagger; DO NOT EDIT.

package certificate

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
)

// New creates a new certificate API client.
func New(transport runtime.ClientTransport, formats strfmt.Registry) ClientService {
	return &Client{transport: transport, formats: formats}
}

/*
Client for certificate API
*/
type Client struct {
	transport runtime.ClientTransport
	formats   strfmt.Registry
}

// ClientOption is the option for Client methods
type ClientOption func(*runtime.ClientOperation)

// ClientService is the interface for Client methods
type ClientService interface {
	PostCertificateClient(params *PostCertificateClientParams, opts ...ClientOption) (*PostCertificateClientOK, error)

	PostCertificateServer(params *PostCertificateServerParams, opts ...ClientOption) (*PostCertificateServerOK, error)

	SetTransport(transport runtime.ClientTransport)
}

/*
PostCertificateClient Create a new Client Certificate
*/
func (a *Client) PostCertificateClient(params *PostCertificateClientParams, opts ...ClientOption) (*PostCertificateClientOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewPostCertificateClientParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "PostCertificateClient",
		Method:             "POST",
		PathPattern:        "/certificate/client",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &PostCertificateClientReader{formats: a.formats},
		Context:            params.Context,
		Client:             params.HTTPClient,
	}
	for _, opt := range opts {
		opt(op)
	}

	result, err := a.transport.Submit(op)
	if err != nil {
		return nil, err
	}
	success, ok := result.(*PostCertificateClientOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for PostCertificateClient: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
PostCertificateServer Create a new Server Certificate
*/
func (a *Client) PostCertificateServer(params *PostCertificateServerParams, opts ...ClientOption) (*PostCertificateServerOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewPostCertificateServerParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "PostCertificateServer",
		Method:             "POST",
		PathPattern:        "/certificate/server",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &PostCertificateServerReader{formats: a.formats},
		Context:            params.Context,
		Client:             params.HTTPClient,
	}
	for _, opt := range opts {
		opt(op)
	}

	result, err := a.transport.Submit(op)
	if err != nil {
		return nil, err
	}
	success, ok := result.(*PostCertificateServerOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for PostCertificateServer: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

// SetTransport changes the transport on the client
func (a *Client) SetTransport(transport runtime.ClientTransport) {
	a.transport = transport
}
