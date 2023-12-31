// Code generated by go-swagger; DO NOT EDIT.

package userkey

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/loopholelabs/endkey/pkg/client/models"
)

// GetUserkeyReader is a Reader for the GetUserkey structure.
type GetUserkeyReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetUserkeyReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetUserkeyOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewGetUserkeyBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewGetUserkeyUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewGetUserkeyNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 409:
		result := NewGetUserkeyConflict()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 412:
		result := NewGetUserkeyPreconditionFailed()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewGetUserkeyInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /userkey] GetUserkey", response, response.Code())
	}
}

// NewGetUserkeyOK creates a GetUserkeyOK with default headers values
func NewGetUserkeyOK() *GetUserkeyOK {
	return &GetUserkeyOK{}
}

/*
GetUserkeyOK describes a response with status code 200, with default header values.

OK
*/
type GetUserkeyOK struct {
	Payload []*models.ModelsUserKeyResponse
}

// IsSuccess returns true when this get userkey o k response has a 2xx status code
func (o *GetUserkeyOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this get userkey o k response has a 3xx status code
func (o *GetUserkeyOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get userkey o k response has a 4xx status code
func (o *GetUserkeyOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this get userkey o k response has a 5xx status code
func (o *GetUserkeyOK) IsServerError() bool {
	return false
}

// IsCode returns true when this get userkey o k response a status code equal to that given
func (o *GetUserkeyOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the get userkey o k response
func (o *GetUserkeyOK) Code() int {
	return 200
}

func (o *GetUserkeyOK) Error() string {
	return fmt.Sprintf("[GET /userkey][%d] getUserkeyOK  %+v", 200, o.Payload)
}

func (o *GetUserkeyOK) String() string {
	return fmt.Sprintf("[GET /userkey][%d] getUserkeyOK  %+v", 200, o.Payload)
}

func (o *GetUserkeyOK) GetPayload() []*models.ModelsUserKeyResponse {
	return o.Payload
}

func (o *GetUserkeyOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetUserkeyBadRequest creates a GetUserkeyBadRequest with default headers values
func NewGetUserkeyBadRequest() *GetUserkeyBadRequest {
	return &GetUserkeyBadRequest{}
}

/*
GetUserkeyBadRequest describes a response with status code 400, with default header values.

Bad Request
*/
type GetUserkeyBadRequest struct {
	Payload string
}

// IsSuccess returns true when this get userkey bad request response has a 2xx status code
func (o *GetUserkeyBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get userkey bad request response has a 3xx status code
func (o *GetUserkeyBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get userkey bad request response has a 4xx status code
func (o *GetUserkeyBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this get userkey bad request response has a 5xx status code
func (o *GetUserkeyBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this get userkey bad request response a status code equal to that given
func (o *GetUserkeyBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the get userkey bad request response
func (o *GetUserkeyBadRequest) Code() int {
	return 400
}

func (o *GetUserkeyBadRequest) Error() string {
	return fmt.Sprintf("[GET /userkey][%d] getUserkeyBadRequest  %+v", 400, o.Payload)
}

func (o *GetUserkeyBadRequest) String() string {
	return fmt.Sprintf("[GET /userkey][%d] getUserkeyBadRequest  %+v", 400, o.Payload)
}

func (o *GetUserkeyBadRequest) GetPayload() string {
	return o.Payload
}

func (o *GetUserkeyBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetUserkeyUnauthorized creates a GetUserkeyUnauthorized with default headers values
func NewGetUserkeyUnauthorized() *GetUserkeyUnauthorized {
	return &GetUserkeyUnauthorized{}
}

/*
GetUserkeyUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type GetUserkeyUnauthorized struct {
	Payload string
}

// IsSuccess returns true when this get userkey unauthorized response has a 2xx status code
func (o *GetUserkeyUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get userkey unauthorized response has a 3xx status code
func (o *GetUserkeyUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get userkey unauthorized response has a 4xx status code
func (o *GetUserkeyUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this get userkey unauthorized response has a 5xx status code
func (o *GetUserkeyUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this get userkey unauthorized response a status code equal to that given
func (o *GetUserkeyUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the get userkey unauthorized response
func (o *GetUserkeyUnauthorized) Code() int {
	return 401
}

func (o *GetUserkeyUnauthorized) Error() string {
	return fmt.Sprintf("[GET /userkey][%d] getUserkeyUnauthorized  %+v", 401, o.Payload)
}

func (o *GetUserkeyUnauthorized) String() string {
	return fmt.Sprintf("[GET /userkey][%d] getUserkeyUnauthorized  %+v", 401, o.Payload)
}

func (o *GetUserkeyUnauthorized) GetPayload() string {
	return o.Payload
}

func (o *GetUserkeyUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetUserkeyNotFound creates a GetUserkeyNotFound with default headers values
func NewGetUserkeyNotFound() *GetUserkeyNotFound {
	return &GetUserkeyNotFound{}
}

/*
GetUserkeyNotFound describes a response with status code 404, with default header values.

Not Found
*/
type GetUserkeyNotFound struct {
	Payload string
}

// IsSuccess returns true when this get userkey not found response has a 2xx status code
func (o *GetUserkeyNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get userkey not found response has a 3xx status code
func (o *GetUserkeyNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get userkey not found response has a 4xx status code
func (o *GetUserkeyNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this get userkey not found response has a 5xx status code
func (o *GetUserkeyNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this get userkey not found response a status code equal to that given
func (o *GetUserkeyNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the get userkey not found response
func (o *GetUserkeyNotFound) Code() int {
	return 404
}

func (o *GetUserkeyNotFound) Error() string {
	return fmt.Sprintf("[GET /userkey][%d] getUserkeyNotFound  %+v", 404, o.Payload)
}

func (o *GetUserkeyNotFound) String() string {
	return fmt.Sprintf("[GET /userkey][%d] getUserkeyNotFound  %+v", 404, o.Payload)
}

func (o *GetUserkeyNotFound) GetPayload() string {
	return o.Payload
}

func (o *GetUserkeyNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetUserkeyConflict creates a GetUserkeyConflict with default headers values
func NewGetUserkeyConflict() *GetUserkeyConflict {
	return &GetUserkeyConflict{}
}

/*
GetUserkeyConflict describes a response with status code 409, with default header values.

Conflict
*/
type GetUserkeyConflict struct {
	Payload string
}

// IsSuccess returns true when this get userkey conflict response has a 2xx status code
func (o *GetUserkeyConflict) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get userkey conflict response has a 3xx status code
func (o *GetUserkeyConflict) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get userkey conflict response has a 4xx status code
func (o *GetUserkeyConflict) IsClientError() bool {
	return true
}

// IsServerError returns true when this get userkey conflict response has a 5xx status code
func (o *GetUserkeyConflict) IsServerError() bool {
	return false
}

// IsCode returns true when this get userkey conflict response a status code equal to that given
func (o *GetUserkeyConflict) IsCode(code int) bool {
	return code == 409
}

// Code gets the status code for the get userkey conflict response
func (o *GetUserkeyConflict) Code() int {
	return 409
}

func (o *GetUserkeyConflict) Error() string {
	return fmt.Sprintf("[GET /userkey][%d] getUserkeyConflict  %+v", 409, o.Payload)
}

func (o *GetUserkeyConflict) String() string {
	return fmt.Sprintf("[GET /userkey][%d] getUserkeyConflict  %+v", 409, o.Payload)
}

func (o *GetUserkeyConflict) GetPayload() string {
	return o.Payload
}

func (o *GetUserkeyConflict) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetUserkeyPreconditionFailed creates a GetUserkeyPreconditionFailed with default headers values
func NewGetUserkeyPreconditionFailed() *GetUserkeyPreconditionFailed {
	return &GetUserkeyPreconditionFailed{}
}

/*
GetUserkeyPreconditionFailed describes a response with status code 412, with default header values.

Precondition Failed
*/
type GetUserkeyPreconditionFailed struct {
	Payload string
}

// IsSuccess returns true when this get userkey precondition failed response has a 2xx status code
func (o *GetUserkeyPreconditionFailed) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get userkey precondition failed response has a 3xx status code
func (o *GetUserkeyPreconditionFailed) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get userkey precondition failed response has a 4xx status code
func (o *GetUserkeyPreconditionFailed) IsClientError() bool {
	return true
}

// IsServerError returns true when this get userkey precondition failed response has a 5xx status code
func (o *GetUserkeyPreconditionFailed) IsServerError() bool {
	return false
}

// IsCode returns true when this get userkey precondition failed response a status code equal to that given
func (o *GetUserkeyPreconditionFailed) IsCode(code int) bool {
	return code == 412
}

// Code gets the status code for the get userkey precondition failed response
func (o *GetUserkeyPreconditionFailed) Code() int {
	return 412
}

func (o *GetUserkeyPreconditionFailed) Error() string {
	return fmt.Sprintf("[GET /userkey][%d] getUserkeyPreconditionFailed  %+v", 412, o.Payload)
}

func (o *GetUserkeyPreconditionFailed) String() string {
	return fmt.Sprintf("[GET /userkey][%d] getUserkeyPreconditionFailed  %+v", 412, o.Payload)
}

func (o *GetUserkeyPreconditionFailed) GetPayload() string {
	return o.Payload
}

func (o *GetUserkeyPreconditionFailed) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetUserkeyInternalServerError creates a GetUserkeyInternalServerError with default headers values
func NewGetUserkeyInternalServerError() *GetUserkeyInternalServerError {
	return &GetUserkeyInternalServerError{}
}

/*
GetUserkeyInternalServerError describes a response with status code 500, with default header values.

Internal Server Error
*/
type GetUserkeyInternalServerError struct {
	Payload string
}

// IsSuccess returns true when this get userkey internal server error response has a 2xx status code
func (o *GetUserkeyInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get userkey internal server error response has a 3xx status code
func (o *GetUserkeyInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get userkey internal server error response has a 4xx status code
func (o *GetUserkeyInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this get userkey internal server error response has a 5xx status code
func (o *GetUserkeyInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this get userkey internal server error response a status code equal to that given
func (o *GetUserkeyInternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the get userkey internal server error response
func (o *GetUserkeyInternalServerError) Code() int {
	return 500
}

func (o *GetUserkeyInternalServerError) Error() string {
	return fmt.Sprintf("[GET /userkey][%d] getUserkeyInternalServerError  %+v", 500, o.Payload)
}

func (o *GetUserkeyInternalServerError) String() string {
	return fmt.Sprintf("[GET /userkey][%d] getUserkeyInternalServerError  %+v", 500, o.Payload)
}

func (o *GetUserkeyInternalServerError) GetPayload() string {
	return o.Payload
}

func (o *GetUserkeyInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
