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

// GetTemplateServerAuthorityNameReader is a Reader for the GetTemplateServerAuthorityName structure.
type GetTemplateServerAuthorityNameReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetTemplateServerAuthorityNameReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetTemplateServerAuthorityNameOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewGetTemplateServerAuthorityNameBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewGetTemplateServerAuthorityNameUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewGetTemplateServerAuthorityNameNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 409:
		result := NewGetTemplateServerAuthorityNameConflict()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 412:
		result := NewGetTemplateServerAuthorityNamePreconditionFailed()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewGetTemplateServerAuthorityNameInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /template/server/{authority_name}] GetTemplateServerAuthorityName", response, response.Code())
	}
}

// NewGetTemplateServerAuthorityNameOK creates a GetTemplateServerAuthorityNameOK with default headers values
func NewGetTemplateServerAuthorityNameOK() *GetTemplateServerAuthorityNameOK {
	return &GetTemplateServerAuthorityNameOK{}
}

/*
GetTemplateServerAuthorityNameOK describes a response with status code 200, with default header values.

OK
*/
type GetTemplateServerAuthorityNameOK struct {
	Payload []*models.ModelsServerTemplateResponse
}

// IsSuccess returns true when this get template server authority name o k response has a 2xx status code
func (o *GetTemplateServerAuthorityNameOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this get template server authority name o k response has a 3xx status code
func (o *GetTemplateServerAuthorityNameOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get template server authority name o k response has a 4xx status code
func (o *GetTemplateServerAuthorityNameOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this get template server authority name o k response has a 5xx status code
func (o *GetTemplateServerAuthorityNameOK) IsServerError() bool {
	return false
}

// IsCode returns true when this get template server authority name o k response a status code equal to that given
func (o *GetTemplateServerAuthorityNameOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the get template server authority name o k response
func (o *GetTemplateServerAuthorityNameOK) Code() int {
	return 200
}

func (o *GetTemplateServerAuthorityNameOK) Error() string {
	return fmt.Sprintf("[GET /template/server/{authority_name}][%d] getTemplateServerAuthorityNameOK  %+v", 200, o.Payload)
}

func (o *GetTemplateServerAuthorityNameOK) String() string {
	return fmt.Sprintf("[GET /template/server/{authority_name}][%d] getTemplateServerAuthorityNameOK  %+v", 200, o.Payload)
}

func (o *GetTemplateServerAuthorityNameOK) GetPayload() []*models.ModelsServerTemplateResponse {
	return o.Payload
}

func (o *GetTemplateServerAuthorityNameOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetTemplateServerAuthorityNameBadRequest creates a GetTemplateServerAuthorityNameBadRequest with default headers values
func NewGetTemplateServerAuthorityNameBadRequest() *GetTemplateServerAuthorityNameBadRequest {
	return &GetTemplateServerAuthorityNameBadRequest{}
}

/*
GetTemplateServerAuthorityNameBadRequest describes a response with status code 400, with default header values.

Bad Request
*/
type GetTemplateServerAuthorityNameBadRequest struct {
	Payload string
}

// IsSuccess returns true when this get template server authority name bad request response has a 2xx status code
func (o *GetTemplateServerAuthorityNameBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get template server authority name bad request response has a 3xx status code
func (o *GetTemplateServerAuthorityNameBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get template server authority name bad request response has a 4xx status code
func (o *GetTemplateServerAuthorityNameBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this get template server authority name bad request response has a 5xx status code
func (o *GetTemplateServerAuthorityNameBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this get template server authority name bad request response a status code equal to that given
func (o *GetTemplateServerAuthorityNameBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the get template server authority name bad request response
func (o *GetTemplateServerAuthorityNameBadRequest) Code() int {
	return 400
}

func (o *GetTemplateServerAuthorityNameBadRequest) Error() string {
	return fmt.Sprintf("[GET /template/server/{authority_name}][%d] getTemplateServerAuthorityNameBadRequest  %+v", 400, o.Payload)
}

func (o *GetTemplateServerAuthorityNameBadRequest) String() string {
	return fmt.Sprintf("[GET /template/server/{authority_name}][%d] getTemplateServerAuthorityNameBadRequest  %+v", 400, o.Payload)
}

func (o *GetTemplateServerAuthorityNameBadRequest) GetPayload() string {
	return o.Payload
}

func (o *GetTemplateServerAuthorityNameBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetTemplateServerAuthorityNameUnauthorized creates a GetTemplateServerAuthorityNameUnauthorized with default headers values
func NewGetTemplateServerAuthorityNameUnauthorized() *GetTemplateServerAuthorityNameUnauthorized {
	return &GetTemplateServerAuthorityNameUnauthorized{}
}

/*
GetTemplateServerAuthorityNameUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type GetTemplateServerAuthorityNameUnauthorized struct {
	Payload string
}

// IsSuccess returns true when this get template server authority name unauthorized response has a 2xx status code
func (o *GetTemplateServerAuthorityNameUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get template server authority name unauthorized response has a 3xx status code
func (o *GetTemplateServerAuthorityNameUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get template server authority name unauthorized response has a 4xx status code
func (o *GetTemplateServerAuthorityNameUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this get template server authority name unauthorized response has a 5xx status code
func (o *GetTemplateServerAuthorityNameUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this get template server authority name unauthorized response a status code equal to that given
func (o *GetTemplateServerAuthorityNameUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the get template server authority name unauthorized response
func (o *GetTemplateServerAuthorityNameUnauthorized) Code() int {
	return 401
}

func (o *GetTemplateServerAuthorityNameUnauthorized) Error() string {
	return fmt.Sprintf("[GET /template/server/{authority_name}][%d] getTemplateServerAuthorityNameUnauthorized  %+v", 401, o.Payload)
}

func (o *GetTemplateServerAuthorityNameUnauthorized) String() string {
	return fmt.Sprintf("[GET /template/server/{authority_name}][%d] getTemplateServerAuthorityNameUnauthorized  %+v", 401, o.Payload)
}

func (o *GetTemplateServerAuthorityNameUnauthorized) GetPayload() string {
	return o.Payload
}

func (o *GetTemplateServerAuthorityNameUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetTemplateServerAuthorityNameNotFound creates a GetTemplateServerAuthorityNameNotFound with default headers values
func NewGetTemplateServerAuthorityNameNotFound() *GetTemplateServerAuthorityNameNotFound {
	return &GetTemplateServerAuthorityNameNotFound{}
}

/*
GetTemplateServerAuthorityNameNotFound describes a response with status code 404, with default header values.

Not Found
*/
type GetTemplateServerAuthorityNameNotFound struct {
	Payload string
}

// IsSuccess returns true when this get template server authority name not found response has a 2xx status code
func (o *GetTemplateServerAuthorityNameNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get template server authority name not found response has a 3xx status code
func (o *GetTemplateServerAuthorityNameNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get template server authority name not found response has a 4xx status code
func (o *GetTemplateServerAuthorityNameNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this get template server authority name not found response has a 5xx status code
func (o *GetTemplateServerAuthorityNameNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this get template server authority name not found response a status code equal to that given
func (o *GetTemplateServerAuthorityNameNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the get template server authority name not found response
func (o *GetTemplateServerAuthorityNameNotFound) Code() int {
	return 404
}

func (o *GetTemplateServerAuthorityNameNotFound) Error() string {
	return fmt.Sprintf("[GET /template/server/{authority_name}][%d] getTemplateServerAuthorityNameNotFound  %+v", 404, o.Payload)
}

func (o *GetTemplateServerAuthorityNameNotFound) String() string {
	return fmt.Sprintf("[GET /template/server/{authority_name}][%d] getTemplateServerAuthorityNameNotFound  %+v", 404, o.Payload)
}

func (o *GetTemplateServerAuthorityNameNotFound) GetPayload() string {
	return o.Payload
}

func (o *GetTemplateServerAuthorityNameNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetTemplateServerAuthorityNameConflict creates a GetTemplateServerAuthorityNameConflict with default headers values
func NewGetTemplateServerAuthorityNameConflict() *GetTemplateServerAuthorityNameConflict {
	return &GetTemplateServerAuthorityNameConflict{}
}

/*
GetTemplateServerAuthorityNameConflict describes a response with status code 409, with default header values.

Conflict
*/
type GetTemplateServerAuthorityNameConflict struct {
	Payload string
}

// IsSuccess returns true when this get template server authority name conflict response has a 2xx status code
func (o *GetTemplateServerAuthorityNameConflict) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get template server authority name conflict response has a 3xx status code
func (o *GetTemplateServerAuthorityNameConflict) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get template server authority name conflict response has a 4xx status code
func (o *GetTemplateServerAuthorityNameConflict) IsClientError() bool {
	return true
}

// IsServerError returns true when this get template server authority name conflict response has a 5xx status code
func (o *GetTemplateServerAuthorityNameConflict) IsServerError() bool {
	return false
}

// IsCode returns true when this get template server authority name conflict response a status code equal to that given
func (o *GetTemplateServerAuthorityNameConflict) IsCode(code int) bool {
	return code == 409
}

// Code gets the status code for the get template server authority name conflict response
func (o *GetTemplateServerAuthorityNameConflict) Code() int {
	return 409
}

func (o *GetTemplateServerAuthorityNameConflict) Error() string {
	return fmt.Sprintf("[GET /template/server/{authority_name}][%d] getTemplateServerAuthorityNameConflict  %+v", 409, o.Payload)
}

func (o *GetTemplateServerAuthorityNameConflict) String() string {
	return fmt.Sprintf("[GET /template/server/{authority_name}][%d] getTemplateServerAuthorityNameConflict  %+v", 409, o.Payload)
}

func (o *GetTemplateServerAuthorityNameConflict) GetPayload() string {
	return o.Payload
}

func (o *GetTemplateServerAuthorityNameConflict) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetTemplateServerAuthorityNamePreconditionFailed creates a GetTemplateServerAuthorityNamePreconditionFailed with default headers values
func NewGetTemplateServerAuthorityNamePreconditionFailed() *GetTemplateServerAuthorityNamePreconditionFailed {
	return &GetTemplateServerAuthorityNamePreconditionFailed{}
}

/*
GetTemplateServerAuthorityNamePreconditionFailed describes a response with status code 412, with default header values.

Precondition Failed
*/
type GetTemplateServerAuthorityNamePreconditionFailed struct {
	Payload string
}

// IsSuccess returns true when this get template server authority name precondition failed response has a 2xx status code
func (o *GetTemplateServerAuthorityNamePreconditionFailed) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get template server authority name precondition failed response has a 3xx status code
func (o *GetTemplateServerAuthorityNamePreconditionFailed) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get template server authority name precondition failed response has a 4xx status code
func (o *GetTemplateServerAuthorityNamePreconditionFailed) IsClientError() bool {
	return true
}

// IsServerError returns true when this get template server authority name precondition failed response has a 5xx status code
func (o *GetTemplateServerAuthorityNamePreconditionFailed) IsServerError() bool {
	return false
}

// IsCode returns true when this get template server authority name precondition failed response a status code equal to that given
func (o *GetTemplateServerAuthorityNamePreconditionFailed) IsCode(code int) bool {
	return code == 412
}

// Code gets the status code for the get template server authority name precondition failed response
func (o *GetTemplateServerAuthorityNamePreconditionFailed) Code() int {
	return 412
}

func (o *GetTemplateServerAuthorityNamePreconditionFailed) Error() string {
	return fmt.Sprintf("[GET /template/server/{authority_name}][%d] getTemplateServerAuthorityNamePreconditionFailed  %+v", 412, o.Payload)
}

func (o *GetTemplateServerAuthorityNamePreconditionFailed) String() string {
	return fmt.Sprintf("[GET /template/server/{authority_name}][%d] getTemplateServerAuthorityNamePreconditionFailed  %+v", 412, o.Payload)
}

func (o *GetTemplateServerAuthorityNamePreconditionFailed) GetPayload() string {
	return o.Payload
}

func (o *GetTemplateServerAuthorityNamePreconditionFailed) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetTemplateServerAuthorityNameInternalServerError creates a GetTemplateServerAuthorityNameInternalServerError with default headers values
func NewGetTemplateServerAuthorityNameInternalServerError() *GetTemplateServerAuthorityNameInternalServerError {
	return &GetTemplateServerAuthorityNameInternalServerError{}
}

/*
GetTemplateServerAuthorityNameInternalServerError describes a response with status code 500, with default header values.

Internal Server Error
*/
type GetTemplateServerAuthorityNameInternalServerError struct {
	Payload string
}

// IsSuccess returns true when this get template server authority name internal server error response has a 2xx status code
func (o *GetTemplateServerAuthorityNameInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get template server authority name internal server error response has a 3xx status code
func (o *GetTemplateServerAuthorityNameInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get template server authority name internal server error response has a 4xx status code
func (o *GetTemplateServerAuthorityNameInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this get template server authority name internal server error response has a 5xx status code
func (o *GetTemplateServerAuthorityNameInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this get template server authority name internal server error response a status code equal to that given
func (o *GetTemplateServerAuthorityNameInternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the get template server authority name internal server error response
func (o *GetTemplateServerAuthorityNameInternalServerError) Code() int {
	return 500
}

func (o *GetTemplateServerAuthorityNameInternalServerError) Error() string {
	return fmt.Sprintf("[GET /template/server/{authority_name}][%d] getTemplateServerAuthorityNameInternalServerError  %+v", 500, o.Payload)
}

func (o *GetTemplateServerAuthorityNameInternalServerError) String() string {
	return fmt.Sprintf("[GET /template/server/{authority_name}][%d] getTemplateServerAuthorityNameInternalServerError  %+v", 500, o.Payload)
}

func (o *GetTemplateServerAuthorityNameInternalServerError) GetPayload() string {
	return o.Payload
}

func (o *GetTemplateServerAuthorityNameInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}