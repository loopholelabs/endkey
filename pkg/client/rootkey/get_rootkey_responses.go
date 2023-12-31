// Code generated by go-swagger; DO NOT EDIT.

package rootkey

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/loopholelabs/endkey/pkg/client/models"
)

// GetRootkeyReader is a Reader for the GetRootkey structure.
type GetRootkeyReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetRootkeyReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetRootkeyOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewGetRootkeyBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewGetRootkeyUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewGetRootkeyNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 409:
		result := NewGetRootkeyConflict()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 412:
		result := NewGetRootkeyPreconditionFailed()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewGetRootkeyInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /rootkey] GetRootkey", response, response.Code())
	}
}

// NewGetRootkeyOK creates a GetRootkeyOK with default headers values
func NewGetRootkeyOK() *GetRootkeyOK {
	return &GetRootkeyOK{}
}

/*
GetRootkeyOK describes a response with status code 200, with default header values.

OK
*/
type GetRootkeyOK struct {
	Payload []*models.ModelsRootKeyResponse
}

// IsSuccess returns true when this get rootkey o k response has a 2xx status code
func (o *GetRootkeyOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this get rootkey o k response has a 3xx status code
func (o *GetRootkeyOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get rootkey o k response has a 4xx status code
func (o *GetRootkeyOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this get rootkey o k response has a 5xx status code
func (o *GetRootkeyOK) IsServerError() bool {
	return false
}

// IsCode returns true when this get rootkey o k response a status code equal to that given
func (o *GetRootkeyOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the get rootkey o k response
func (o *GetRootkeyOK) Code() int {
	return 200
}

func (o *GetRootkeyOK) Error() string {
	return fmt.Sprintf("[GET /rootkey][%d] getRootkeyOK  %+v", 200, o.Payload)
}

func (o *GetRootkeyOK) String() string {
	return fmt.Sprintf("[GET /rootkey][%d] getRootkeyOK  %+v", 200, o.Payload)
}

func (o *GetRootkeyOK) GetPayload() []*models.ModelsRootKeyResponse {
	return o.Payload
}

func (o *GetRootkeyOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetRootkeyBadRequest creates a GetRootkeyBadRequest with default headers values
func NewGetRootkeyBadRequest() *GetRootkeyBadRequest {
	return &GetRootkeyBadRequest{}
}

/*
GetRootkeyBadRequest describes a response with status code 400, with default header values.

Bad Request
*/
type GetRootkeyBadRequest struct {
	Payload string
}

// IsSuccess returns true when this get rootkey bad request response has a 2xx status code
func (o *GetRootkeyBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get rootkey bad request response has a 3xx status code
func (o *GetRootkeyBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get rootkey bad request response has a 4xx status code
func (o *GetRootkeyBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this get rootkey bad request response has a 5xx status code
func (o *GetRootkeyBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this get rootkey bad request response a status code equal to that given
func (o *GetRootkeyBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the get rootkey bad request response
func (o *GetRootkeyBadRequest) Code() int {
	return 400
}

func (o *GetRootkeyBadRequest) Error() string {
	return fmt.Sprintf("[GET /rootkey][%d] getRootkeyBadRequest  %+v", 400, o.Payload)
}

func (o *GetRootkeyBadRequest) String() string {
	return fmt.Sprintf("[GET /rootkey][%d] getRootkeyBadRequest  %+v", 400, o.Payload)
}

func (o *GetRootkeyBadRequest) GetPayload() string {
	return o.Payload
}

func (o *GetRootkeyBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetRootkeyUnauthorized creates a GetRootkeyUnauthorized with default headers values
func NewGetRootkeyUnauthorized() *GetRootkeyUnauthorized {
	return &GetRootkeyUnauthorized{}
}

/*
GetRootkeyUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type GetRootkeyUnauthorized struct {
	Payload string
}

// IsSuccess returns true when this get rootkey unauthorized response has a 2xx status code
func (o *GetRootkeyUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get rootkey unauthorized response has a 3xx status code
func (o *GetRootkeyUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get rootkey unauthorized response has a 4xx status code
func (o *GetRootkeyUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this get rootkey unauthorized response has a 5xx status code
func (o *GetRootkeyUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this get rootkey unauthorized response a status code equal to that given
func (o *GetRootkeyUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the get rootkey unauthorized response
func (o *GetRootkeyUnauthorized) Code() int {
	return 401
}

func (o *GetRootkeyUnauthorized) Error() string {
	return fmt.Sprintf("[GET /rootkey][%d] getRootkeyUnauthorized  %+v", 401, o.Payload)
}

func (o *GetRootkeyUnauthorized) String() string {
	return fmt.Sprintf("[GET /rootkey][%d] getRootkeyUnauthorized  %+v", 401, o.Payload)
}

func (o *GetRootkeyUnauthorized) GetPayload() string {
	return o.Payload
}

func (o *GetRootkeyUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetRootkeyNotFound creates a GetRootkeyNotFound with default headers values
func NewGetRootkeyNotFound() *GetRootkeyNotFound {
	return &GetRootkeyNotFound{}
}

/*
GetRootkeyNotFound describes a response with status code 404, with default header values.

Not Found
*/
type GetRootkeyNotFound struct {
	Payload string
}

// IsSuccess returns true when this get rootkey not found response has a 2xx status code
func (o *GetRootkeyNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get rootkey not found response has a 3xx status code
func (o *GetRootkeyNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get rootkey not found response has a 4xx status code
func (o *GetRootkeyNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this get rootkey not found response has a 5xx status code
func (o *GetRootkeyNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this get rootkey not found response a status code equal to that given
func (o *GetRootkeyNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the get rootkey not found response
func (o *GetRootkeyNotFound) Code() int {
	return 404
}

func (o *GetRootkeyNotFound) Error() string {
	return fmt.Sprintf("[GET /rootkey][%d] getRootkeyNotFound  %+v", 404, o.Payload)
}

func (o *GetRootkeyNotFound) String() string {
	return fmt.Sprintf("[GET /rootkey][%d] getRootkeyNotFound  %+v", 404, o.Payload)
}

func (o *GetRootkeyNotFound) GetPayload() string {
	return o.Payload
}

func (o *GetRootkeyNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetRootkeyConflict creates a GetRootkeyConflict with default headers values
func NewGetRootkeyConflict() *GetRootkeyConflict {
	return &GetRootkeyConflict{}
}

/*
GetRootkeyConflict describes a response with status code 409, with default header values.

Conflict
*/
type GetRootkeyConflict struct {
	Payload string
}

// IsSuccess returns true when this get rootkey conflict response has a 2xx status code
func (o *GetRootkeyConflict) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get rootkey conflict response has a 3xx status code
func (o *GetRootkeyConflict) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get rootkey conflict response has a 4xx status code
func (o *GetRootkeyConflict) IsClientError() bool {
	return true
}

// IsServerError returns true when this get rootkey conflict response has a 5xx status code
func (o *GetRootkeyConflict) IsServerError() bool {
	return false
}

// IsCode returns true when this get rootkey conflict response a status code equal to that given
func (o *GetRootkeyConflict) IsCode(code int) bool {
	return code == 409
}

// Code gets the status code for the get rootkey conflict response
func (o *GetRootkeyConflict) Code() int {
	return 409
}

func (o *GetRootkeyConflict) Error() string {
	return fmt.Sprintf("[GET /rootkey][%d] getRootkeyConflict  %+v", 409, o.Payload)
}

func (o *GetRootkeyConflict) String() string {
	return fmt.Sprintf("[GET /rootkey][%d] getRootkeyConflict  %+v", 409, o.Payload)
}

func (o *GetRootkeyConflict) GetPayload() string {
	return o.Payload
}

func (o *GetRootkeyConflict) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetRootkeyPreconditionFailed creates a GetRootkeyPreconditionFailed with default headers values
func NewGetRootkeyPreconditionFailed() *GetRootkeyPreconditionFailed {
	return &GetRootkeyPreconditionFailed{}
}

/*
GetRootkeyPreconditionFailed describes a response with status code 412, with default header values.

Precondition Failed
*/
type GetRootkeyPreconditionFailed struct {
	Payload string
}

// IsSuccess returns true when this get rootkey precondition failed response has a 2xx status code
func (o *GetRootkeyPreconditionFailed) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get rootkey precondition failed response has a 3xx status code
func (o *GetRootkeyPreconditionFailed) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get rootkey precondition failed response has a 4xx status code
func (o *GetRootkeyPreconditionFailed) IsClientError() bool {
	return true
}

// IsServerError returns true when this get rootkey precondition failed response has a 5xx status code
func (o *GetRootkeyPreconditionFailed) IsServerError() bool {
	return false
}

// IsCode returns true when this get rootkey precondition failed response a status code equal to that given
func (o *GetRootkeyPreconditionFailed) IsCode(code int) bool {
	return code == 412
}

// Code gets the status code for the get rootkey precondition failed response
func (o *GetRootkeyPreconditionFailed) Code() int {
	return 412
}

func (o *GetRootkeyPreconditionFailed) Error() string {
	return fmt.Sprintf("[GET /rootkey][%d] getRootkeyPreconditionFailed  %+v", 412, o.Payload)
}

func (o *GetRootkeyPreconditionFailed) String() string {
	return fmt.Sprintf("[GET /rootkey][%d] getRootkeyPreconditionFailed  %+v", 412, o.Payload)
}

func (o *GetRootkeyPreconditionFailed) GetPayload() string {
	return o.Payload
}

func (o *GetRootkeyPreconditionFailed) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetRootkeyInternalServerError creates a GetRootkeyInternalServerError with default headers values
func NewGetRootkeyInternalServerError() *GetRootkeyInternalServerError {
	return &GetRootkeyInternalServerError{}
}

/*
GetRootkeyInternalServerError describes a response with status code 500, with default header values.

Internal Server Error
*/
type GetRootkeyInternalServerError struct {
	Payload string
}

// IsSuccess returns true when this get rootkey internal server error response has a 2xx status code
func (o *GetRootkeyInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get rootkey internal server error response has a 3xx status code
func (o *GetRootkeyInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get rootkey internal server error response has a 4xx status code
func (o *GetRootkeyInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this get rootkey internal server error response has a 5xx status code
func (o *GetRootkeyInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this get rootkey internal server error response a status code equal to that given
func (o *GetRootkeyInternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the get rootkey internal server error response
func (o *GetRootkeyInternalServerError) Code() int {
	return 500
}

func (o *GetRootkeyInternalServerError) Error() string {
	return fmt.Sprintf("[GET /rootkey][%d] getRootkeyInternalServerError  %+v", 500, o.Payload)
}

func (o *GetRootkeyInternalServerError) String() string {
	return fmt.Sprintf("[GET /rootkey][%d] getRootkeyInternalServerError  %+v", 500, o.Payload)
}

func (o *GetRootkeyInternalServerError) GetPayload() string {
	return o.Payload
}

func (o *GetRootkeyInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
