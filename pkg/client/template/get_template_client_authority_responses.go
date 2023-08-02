// Code generated by go-swagger; DO NOT EDIT.

package template

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/loopholelabs/endkey/pkg/client/models"
)

// GetTemplateClientAuthorityReader is a Reader for the GetTemplateClientAuthority structure.
type GetTemplateClientAuthorityReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetTemplateClientAuthorityReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetTemplateClientAuthorityOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewGetTemplateClientAuthorityBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewGetTemplateClientAuthorityUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewGetTemplateClientAuthorityNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 409:
		result := NewGetTemplateClientAuthorityConflict()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 412:
		result := NewGetTemplateClientAuthorityPreconditionFailed()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewGetTemplateClientAuthorityInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /template/client/{authority}] GetTemplateClientAuthority", response, response.Code())
	}
}

// NewGetTemplateClientAuthorityOK creates a GetTemplateClientAuthorityOK with default headers values
func NewGetTemplateClientAuthorityOK() *GetTemplateClientAuthorityOK {
	return &GetTemplateClientAuthorityOK{}
}

/*
GetTemplateClientAuthorityOK describes a response with status code 200, with default header values.

OK
*/
type GetTemplateClientAuthorityOK struct {
	Payload []*models.ModelsClientTemplateResponse
}

// IsSuccess returns true when this get template client authority o k response has a 2xx status code
func (o *GetTemplateClientAuthorityOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this get template client authority o k response has a 3xx status code
func (o *GetTemplateClientAuthorityOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get template client authority o k response has a 4xx status code
func (o *GetTemplateClientAuthorityOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this get template client authority o k response has a 5xx status code
func (o *GetTemplateClientAuthorityOK) IsServerError() bool {
	return false
}

// IsCode returns true when this get template client authority o k response a status code equal to that given
func (o *GetTemplateClientAuthorityOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the get template client authority o k response
func (o *GetTemplateClientAuthorityOK) Code() int {
	return 200
}

func (o *GetTemplateClientAuthorityOK) Error() string {
	return fmt.Sprintf("[GET /template/client/{authority}][%d] getTemplateClientAuthorityOK  %+v", 200, o.Payload)
}

func (o *GetTemplateClientAuthorityOK) String() string {
	return fmt.Sprintf("[GET /template/client/{authority}][%d] getTemplateClientAuthorityOK  %+v", 200, o.Payload)
}

func (o *GetTemplateClientAuthorityOK) GetPayload() []*models.ModelsClientTemplateResponse {
	return o.Payload
}

func (o *GetTemplateClientAuthorityOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetTemplateClientAuthorityBadRequest creates a GetTemplateClientAuthorityBadRequest with default headers values
func NewGetTemplateClientAuthorityBadRequest() *GetTemplateClientAuthorityBadRequest {
	return &GetTemplateClientAuthorityBadRequest{}
}

/*
GetTemplateClientAuthorityBadRequest describes a response with status code 400, with default header values.

Bad Request
*/
type GetTemplateClientAuthorityBadRequest struct {
	Payload string
}

// IsSuccess returns true when this get template client authority bad request response has a 2xx status code
func (o *GetTemplateClientAuthorityBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get template client authority bad request response has a 3xx status code
func (o *GetTemplateClientAuthorityBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get template client authority bad request response has a 4xx status code
func (o *GetTemplateClientAuthorityBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this get template client authority bad request response has a 5xx status code
func (o *GetTemplateClientAuthorityBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this get template client authority bad request response a status code equal to that given
func (o *GetTemplateClientAuthorityBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the get template client authority bad request response
func (o *GetTemplateClientAuthorityBadRequest) Code() int {
	return 400
}

func (o *GetTemplateClientAuthorityBadRequest) Error() string {
	return fmt.Sprintf("[GET /template/client/{authority}][%d] getTemplateClientAuthorityBadRequest  %+v", 400, o.Payload)
}

func (o *GetTemplateClientAuthorityBadRequest) String() string {
	return fmt.Sprintf("[GET /template/client/{authority}][%d] getTemplateClientAuthorityBadRequest  %+v", 400, o.Payload)
}

func (o *GetTemplateClientAuthorityBadRequest) GetPayload() string {
	return o.Payload
}

func (o *GetTemplateClientAuthorityBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetTemplateClientAuthorityUnauthorized creates a GetTemplateClientAuthorityUnauthorized with default headers values
func NewGetTemplateClientAuthorityUnauthorized() *GetTemplateClientAuthorityUnauthorized {
	return &GetTemplateClientAuthorityUnauthorized{}
}

/*
GetTemplateClientAuthorityUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type GetTemplateClientAuthorityUnauthorized struct {
	Payload string
}

// IsSuccess returns true when this get template client authority unauthorized response has a 2xx status code
func (o *GetTemplateClientAuthorityUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get template client authority unauthorized response has a 3xx status code
func (o *GetTemplateClientAuthorityUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get template client authority unauthorized response has a 4xx status code
func (o *GetTemplateClientAuthorityUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this get template client authority unauthorized response has a 5xx status code
func (o *GetTemplateClientAuthorityUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this get template client authority unauthorized response a status code equal to that given
func (o *GetTemplateClientAuthorityUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the get template client authority unauthorized response
func (o *GetTemplateClientAuthorityUnauthorized) Code() int {
	return 401
}

func (o *GetTemplateClientAuthorityUnauthorized) Error() string {
	return fmt.Sprintf("[GET /template/client/{authority}][%d] getTemplateClientAuthorityUnauthorized  %+v", 401, o.Payload)
}

func (o *GetTemplateClientAuthorityUnauthorized) String() string {
	return fmt.Sprintf("[GET /template/client/{authority}][%d] getTemplateClientAuthorityUnauthorized  %+v", 401, o.Payload)
}

func (o *GetTemplateClientAuthorityUnauthorized) GetPayload() string {
	return o.Payload
}

func (o *GetTemplateClientAuthorityUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetTemplateClientAuthorityNotFound creates a GetTemplateClientAuthorityNotFound with default headers values
func NewGetTemplateClientAuthorityNotFound() *GetTemplateClientAuthorityNotFound {
	return &GetTemplateClientAuthorityNotFound{}
}

/*
GetTemplateClientAuthorityNotFound describes a response with status code 404, with default header values.

Not Found
*/
type GetTemplateClientAuthorityNotFound struct {
	Payload string
}

// IsSuccess returns true when this get template client authority not found response has a 2xx status code
func (o *GetTemplateClientAuthorityNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get template client authority not found response has a 3xx status code
func (o *GetTemplateClientAuthorityNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get template client authority not found response has a 4xx status code
func (o *GetTemplateClientAuthorityNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this get template client authority not found response has a 5xx status code
func (o *GetTemplateClientAuthorityNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this get template client authority not found response a status code equal to that given
func (o *GetTemplateClientAuthorityNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the get template client authority not found response
func (o *GetTemplateClientAuthorityNotFound) Code() int {
	return 404
}

func (o *GetTemplateClientAuthorityNotFound) Error() string {
	return fmt.Sprintf("[GET /template/client/{authority}][%d] getTemplateClientAuthorityNotFound  %+v", 404, o.Payload)
}

func (o *GetTemplateClientAuthorityNotFound) String() string {
	return fmt.Sprintf("[GET /template/client/{authority}][%d] getTemplateClientAuthorityNotFound  %+v", 404, o.Payload)
}

func (o *GetTemplateClientAuthorityNotFound) GetPayload() string {
	return o.Payload
}

func (o *GetTemplateClientAuthorityNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetTemplateClientAuthorityConflict creates a GetTemplateClientAuthorityConflict with default headers values
func NewGetTemplateClientAuthorityConflict() *GetTemplateClientAuthorityConflict {
	return &GetTemplateClientAuthorityConflict{}
}

/*
GetTemplateClientAuthorityConflict describes a response with status code 409, with default header values.

Conflict
*/
type GetTemplateClientAuthorityConflict struct {
	Payload string
}

// IsSuccess returns true when this get template client authority conflict response has a 2xx status code
func (o *GetTemplateClientAuthorityConflict) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get template client authority conflict response has a 3xx status code
func (o *GetTemplateClientAuthorityConflict) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get template client authority conflict response has a 4xx status code
func (o *GetTemplateClientAuthorityConflict) IsClientError() bool {
	return true
}

// IsServerError returns true when this get template client authority conflict response has a 5xx status code
func (o *GetTemplateClientAuthorityConflict) IsServerError() bool {
	return false
}

// IsCode returns true when this get template client authority conflict response a status code equal to that given
func (o *GetTemplateClientAuthorityConflict) IsCode(code int) bool {
	return code == 409
}

// Code gets the status code for the get template client authority conflict response
func (o *GetTemplateClientAuthorityConflict) Code() int {
	return 409
}

func (o *GetTemplateClientAuthorityConflict) Error() string {
	return fmt.Sprintf("[GET /template/client/{authority}][%d] getTemplateClientAuthorityConflict  %+v", 409, o.Payload)
}

func (o *GetTemplateClientAuthorityConflict) String() string {
	return fmt.Sprintf("[GET /template/client/{authority}][%d] getTemplateClientAuthorityConflict  %+v", 409, o.Payload)
}

func (o *GetTemplateClientAuthorityConflict) GetPayload() string {
	return o.Payload
}

func (o *GetTemplateClientAuthorityConflict) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetTemplateClientAuthorityPreconditionFailed creates a GetTemplateClientAuthorityPreconditionFailed with default headers values
func NewGetTemplateClientAuthorityPreconditionFailed() *GetTemplateClientAuthorityPreconditionFailed {
	return &GetTemplateClientAuthorityPreconditionFailed{}
}

/*
GetTemplateClientAuthorityPreconditionFailed describes a response with status code 412, with default header values.

Precondition Failed
*/
type GetTemplateClientAuthorityPreconditionFailed struct {
	Payload string
}

// IsSuccess returns true when this get template client authority precondition failed response has a 2xx status code
func (o *GetTemplateClientAuthorityPreconditionFailed) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get template client authority precondition failed response has a 3xx status code
func (o *GetTemplateClientAuthorityPreconditionFailed) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get template client authority precondition failed response has a 4xx status code
func (o *GetTemplateClientAuthorityPreconditionFailed) IsClientError() bool {
	return true
}

// IsServerError returns true when this get template client authority precondition failed response has a 5xx status code
func (o *GetTemplateClientAuthorityPreconditionFailed) IsServerError() bool {
	return false
}

// IsCode returns true when this get template client authority precondition failed response a status code equal to that given
func (o *GetTemplateClientAuthorityPreconditionFailed) IsCode(code int) bool {
	return code == 412
}

// Code gets the status code for the get template client authority precondition failed response
func (o *GetTemplateClientAuthorityPreconditionFailed) Code() int {
	return 412
}

func (o *GetTemplateClientAuthorityPreconditionFailed) Error() string {
	return fmt.Sprintf("[GET /template/client/{authority}][%d] getTemplateClientAuthorityPreconditionFailed  %+v", 412, o.Payload)
}

func (o *GetTemplateClientAuthorityPreconditionFailed) String() string {
	return fmt.Sprintf("[GET /template/client/{authority}][%d] getTemplateClientAuthorityPreconditionFailed  %+v", 412, o.Payload)
}

func (o *GetTemplateClientAuthorityPreconditionFailed) GetPayload() string {
	return o.Payload
}

func (o *GetTemplateClientAuthorityPreconditionFailed) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetTemplateClientAuthorityInternalServerError creates a GetTemplateClientAuthorityInternalServerError with default headers values
func NewGetTemplateClientAuthorityInternalServerError() *GetTemplateClientAuthorityInternalServerError {
	return &GetTemplateClientAuthorityInternalServerError{}
}

/*
GetTemplateClientAuthorityInternalServerError describes a response with status code 500, with default header values.

Internal Server Error
*/
type GetTemplateClientAuthorityInternalServerError struct {
	Payload string
}

// IsSuccess returns true when this get template client authority internal server error response has a 2xx status code
func (o *GetTemplateClientAuthorityInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get template client authority internal server error response has a 3xx status code
func (o *GetTemplateClientAuthorityInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get template client authority internal server error response has a 4xx status code
func (o *GetTemplateClientAuthorityInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this get template client authority internal server error response has a 5xx status code
func (o *GetTemplateClientAuthorityInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this get template client authority internal server error response a status code equal to that given
func (o *GetTemplateClientAuthorityInternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the get template client authority internal server error response
func (o *GetTemplateClientAuthorityInternalServerError) Code() int {
	return 500
}

func (o *GetTemplateClientAuthorityInternalServerError) Error() string {
	return fmt.Sprintf("[GET /template/client/{authority}][%d] getTemplateClientAuthorityInternalServerError  %+v", 500, o.Payload)
}

func (o *GetTemplateClientAuthorityInternalServerError) String() string {
	return fmt.Sprintf("[GET /template/client/{authority}][%d] getTemplateClientAuthorityInternalServerError  %+v", 500, o.Payload)
}

func (o *GetTemplateClientAuthorityInternalServerError) GetPayload() string {
	return o.Payload
}

func (o *GetTemplateClientAuthorityInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
