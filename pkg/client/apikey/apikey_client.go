// Code generated by go-swagger; DO NOT EDIT.

package apikey

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
)

// New creates a new apikey API client.
func New(transport runtime.ClientTransport, formats strfmt.Registry) ClientService {
	return &Client{transport: transport, formats: formats}
}

/*
Client for apikey API
*/
type Client struct {
	transport runtime.ClientTransport
	formats   strfmt.Registry
}

// ClientOption is the option for Client methods
type ClientOption func(*runtime.ClientOperation)

// ClientService is the interface for Client methods
type ClientService interface {
	DeleteApikey(params *DeleteApikeyParams, opts ...ClientOption) (*DeleteApikeyOK, error)

	GetApikeyAuthorityName(params *GetApikeyAuthorityNameParams, opts ...ClientOption) (*GetApikeyAuthorityNameOK, error)

	PostApikey(params *PostApikeyParams, opts ...ClientOption) (*PostApikeyOK, error)

	SetTransport(transport runtime.ClientTransport)
}

/*
DeleteApikey Delete an API Key
*/
func (a *Client) DeleteApikey(params *DeleteApikeyParams, opts ...ClientOption) (*DeleteApikeyOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewDeleteApikeyParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "DeleteApikey",
		Method:             "DELETE",
		PathPattern:        "/apikey",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &DeleteApikeyReader{formats: a.formats},
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
	success, ok := result.(*DeleteApikeyOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for DeleteApikey: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
GetApikeyAuthorityName Lists all the api keys
*/
func (a *Client) GetApikeyAuthorityName(params *GetApikeyAuthorityNameParams, opts ...ClientOption) (*GetApikeyAuthorityNameOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewGetApikeyAuthorityNameParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "GetApikeyAuthorityName",
		Method:             "GET",
		PathPattern:        "/apikey/{authority_name}",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &GetApikeyAuthorityNameReader{formats: a.formats},
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
	success, ok := result.(*GetApikeyAuthorityNameOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for GetApikeyAuthorityName: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
PostApikey Create a new API Key for a given Authority
*/
func (a *Client) PostApikey(params *PostApikeyParams, opts ...ClientOption) (*PostApikeyOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewPostApikeyParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "PostApikey",
		Method:             "POST",
		PathPattern:        "/apikey",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &PostApikeyReader{formats: a.formats},
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
	success, ok := result.(*PostApikeyOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for PostApikey: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

// SetTransport changes the transport on the client
func (a *Client) SetTransport(transport runtime.ClientTransport) {
	a.transport = transport
}
