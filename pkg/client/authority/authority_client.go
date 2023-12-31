// Code generated by go-swagger; DO NOT EDIT.

package authority

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
)

// New creates a new authority API client.
func New(transport runtime.ClientTransport, formats strfmt.Registry) ClientService {
	return &Client{transport: transport, formats: formats}
}

/*
Client for authority API
*/
type Client struct {
	transport runtime.ClientTransport
	formats   strfmt.Registry
}

// ClientOption is the option for Client methods
type ClientOption func(*runtime.ClientOperation)

// ClientService is the interface for Client methods
type ClientService interface {
	DeleteAuthorityName(params *DeleteAuthorityNameParams, opts ...ClientOption) (*DeleteAuthorityNameOK, error)

	GetAuthority(params *GetAuthorityParams, opts ...ClientOption) (*GetAuthorityOK, error)

	GetAuthorityName(params *GetAuthorityNameParams, opts ...ClientOption) (*GetAuthorityNameOK, error)

	PostAuthority(params *PostAuthorityParams, opts ...ClientOption) (*PostAuthorityOK, error)

	SetTransport(transport runtime.ClientTransport)
}

/*
DeleteAuthorityName Delete an authority
*/
func (a *Client) DeleteAuthorityName(params *DeleteAuthorityNameParams, opts ...ClientOption) (*DeleteAuthorityNameOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewDeleteAuthorityNameParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "DeleteAuthorityName",
		Method:             "DELETE",
		PathPattern:        "/authority/{name}",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &DeleteAuthorityNameReader{formats: a.formats},
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
	success, ok := result.(*DeleteAuthorityNameOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for DeleteAuthorityName: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
GetAuthority List authorities
*/
func (a *Client) GetAuthority(params *GetAuthorityParams, opts ...ClientOption) (*GetAuthorityOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewGetAuthorityParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "GetAuthority",
		Method:             "GET",
		PathPattern:        "/authority",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &GetAuthorityReader{formats: a.formats},
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
	success, ok := result.(*GetAuthorityOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for GetAuthority: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
GetAuthorityName Get an authority
*/
func (a *Client) GetAuthorityName(params *GetAuthorityNameParams, opts ...ClientOption) (*GetAuthorityNameOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewGetAuthorityNameParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "GetAuthorityName",
		Method:             "GET",
		PathPattern:        "/authority/{name}",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &GetAuthorityNameReader{formats: a.formats},
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
	success, ok := result.(*GetAuthorityNameOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for GetAuthorityName: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
PostAuthority Create a new Authority
*/
func (a *Client) PostAuthority(params *PostAuthorityParams, opts ...ClientOption) (*PostAuthorityOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewPostAuthorityParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "PostAuthority",
		Method:             "POST",
		PathPattern:        "/authority",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &PostAuthorityReader{formats: a.formats},
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
	success, ok := result.(*PostAuthorityOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for PostAuthority: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

// SetTransport changes the transport on the client
func (a *Client) SetTransport(transport runtime.ClientTransport) {
	a.transport = transport
}
