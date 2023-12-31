// Code generated by go-swagger; DO NOT EDIT.

package userkey

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
)

// DeleteUserkeyNameReader is a Reader for the DeleteUserkeyName structure.
type DeleteUserkeyNameReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *DeleteUserkeyNameReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewDeleteUserkeyNameOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewDeleteUserkeyNameBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewDeleteUserkeyNameUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewDeleteUserkeyNameNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 409:
		result := NewDeleteUserkeyNameConflict()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 412:
		result := NewDeleteUserkeyNamePreconditionFailed()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewDeleteUserkeyNameInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[DELETE /userkey/{name}] DeleteUserkeyName", response, response.Code())
	}
}

// NewDeleteUserkeyNameOK creates a DeleteUserkeyNameOK with default headers values
func NewDeleteUserkeyNameOK() *DeleteUserkeyNameOK {
	return &DeleteUserkeyNameOK{}
}

/*
DeleteUserkeyNameOK describes a response with status code 200, with default header values.

OK
*/
type DeleteUserkeyNameOK struct {
	Payload string
}

// IsSuccess returns true when this delete userkey name o k response has a 2xx status code
func (o *DeleteUserkeyNameOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this delete userkey name o k response has a 3xx status code
func (o *DeleteUserkeyNameOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this delete userkey name o k response has a 4xx status code
func (o *DeleteUserkeyNameOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this delete userkey name o k response has a 5xx status code
func (o *DeleteUserkeyNameOK) IsServerError() bool {
	return false
}

// IsCode returns true when this delete userkey name o k response a status code equal to that given
func (o *DeleteUserkeyNameOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the delete userkey name o k response
func (o *DeleteUserkeyNameOK) Code() int {
	return 200
}

func (o *DeleteUserkeyNameOK) Error() string {
	return fmt.Sprintf("[DELETE /userkey/{name}][%d] deleteUserkeyNameOK  %+v", 200, o.Payload)
}

func (o *DeleteUserkeyNameOK) String() string {
	return fmt.Sprintf("[DELETE /userkey/{name}][%d] deleteUserkeyNameOK  %+v", 200, o.Payload)
}

func (o *DeleteUserkeyNameOK) GetPayload() string {
	return o.Payload
}

func (o *DeleteUserkeyNameOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDeleteUserkeyNameBadRequest creates a DeleteUserkeyNameBadRequest with default headers values
func NewDeleteUserkeyNameBadRequest() *DeleteUserkeyNameBadRequest {
	return &DeleteUserkeyNameBadRequest{}
}

/*
DeleteUserkeyNameBadRequest describes a response with status code 400, with default header values.

Bad Request
*/
type DeleteUserkeyNameBadRequest struct {
	Payload string
}

// IsSuccess returns true when this delete userkey name bad request response has a 2xx status code
func (o *DeleteUserkeyNameBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this delete userkey name bad request response has a 3xx status code
func (o *DeleteUserkeyNameBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this delete userkey name bad request response has a 4xx status code
func (o *DeleteUserkeyNameBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this delete userkey name bad request response has a 5xx status code
func (o *DeleteUserkeyNameBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this delete userkey name bad request response a status code equal to that given
func (o *DeleteUserkeyNameBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the delete userkey name bad request response
func (o *DeleteUserkeyNameBadRequest) Code() int {
	return 400
}

func (o *DeleteUserkeyNameBadRequest) Error() string {
	return fmt.Sprintf("[DELETE /userkey/{name}][%d] deleteUserkeyNameBadRequest  %+v", 400, o.Payload)
}

func (o *DeleteUserkeyNameBadRequest) String() string {
	return fmt.Sprintf("[DELETE /userkey/{name}][%d] deleteUserkeyNameBadRequest  %+v", 400, o.Payload)
}

func (o *DeleteUserkeyNameBadRequest) GetPayload() string {
	return o.Payload
}

func (o *DeleteUserkeyNameBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDeleteUserkeyNameUnauthorized creates a DeleteUserkeyNameUnauthorized with default headers values
func NewDeleteUserkeyNameUnauthorized() *DeleteUserkeyNameUnauthorized {
	return &DeleteUserkeyNameUnauthorized{}
}

/*
DeleteUserkeyNameUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type DeleteUserkeyNameUnauthorized struct {
	Payload string
}

// IsSuccess returns true when this delete userkey name unauthorized response has a 2xx status code
func (o *DeleteUserkeyNameUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this delete userkey name unauthorized response has a 3xx status code
func (o *DeleteUserkeyNameUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this delete userkey name unauthorized response has a 4xx status code
func (o *DeleteUserkeyNameUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this delete userkey name unauthorized response has a 5xx status code
func (o *DeleteUserkeyNameUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this delete userkey name unauthorized response a status code equal to that given
func (o *DeleteUserkeyNameUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the delete userkey name unauthorized response
func (o *DeleteUserkeyNameUnauthorized) Code() int {
	return 401
}

func (o *DeleteUserkeyNameUnauthorized) Error() string {
	return fmt.Sprintf("[DELETE /userkey/{name}][%d] deleteUserkeyNameUnauthorized  %+v", 401, o.Payload)
}

func (o *DeleteUserkeyNameUnauthorized) String() string {
	return fmt.Sprintf("[DELETE /userkey/{name}][%d] deleteUserkeyNameUnauthorized  %+v", 401, o.Payload)
}

func (o *DeleteUserkeyNameUnauthorized) GetPayload() string {
	return o.Payload
}

func (o *DeleteUserkeyNameUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDeleteUserkeyNameNotFound creates a DeleteUserkeyNameNotFound with default headers values
func NewDeleteUserkeyNameNotFound() *DeleteUserkeyNameNotFound {
	return &DeleteUserkeyNameNotFound{}
}

/*
DeleteUserkeyNameNotFound describes a response with status code 404, with default header values.

Not Found
*/
type DeleteUserkeyNameNotFound struct {
	Payload string
}

// IsSuccess returns true when this delete userkey name not found response has a 2xx status code
func (o *DeleteUserkeyNameNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this delete userkey name not found response has a 3xx status code
func (o *DeleteUserkeyNameNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this delete userkey name not found response has a 4xx status code
func (o *DeleteUserkeyNameNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this delete userkey name not found response has a 5xx status code
func (o *DeleteUserkeyNameNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this delete userkey name not found response a status code equal to that given
func (o *DeleteUserkeyNameNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the delete userkey name not found response
func (o *DeleteUserkeyNameNotFound) Code() int {
	return 404
}

func (o *DeleteUserkeyNameNotFound) Error() string {
	return fmt.Sprintf("[DELETE /userkey/{name}][%d] deleteUserkeyNameNotFound  %+v", 404, o.Payload)
}

func (o *DeleteUserkeyNameNotFound) String() string {
	return fmt.Sprintf("[DELETE /userkey/{name}][%d] deleteUserkeyNameNotFound  %+v", 404, o.Payload)
}

func (o *DeleteUserkeyNameNotFound) GetPayload() string {
	return o.Payload
}

func (o *DeleteUserkeyNameNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDeleteUserkeyNameConflict creates a DeleteUserkeyNameConflict with default headers values
func NewDeleteUserkeyNameConflict() *DeleteUserkeyNameConflict {
	return &DeleteUserkeyNameConflict{}
}

/*
DeleteUserkeyNameConflict describes a response with status code 409, with default header values.

Conflict
*/
type DeleteUserkeyNameConflict struct {
	Payload string
}

// IsSuccess returns true when this delete userkey name conflict response has a 2xx status code
func (o *DeleteUserkeyNameConflict) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this delete userkey name conflict response has a 3xx status code
func (o *DeleteUserkeyNameConflict) IsRedirect() bool {
	return false
}

// IsClientError returns true when this delete userkey name conflict response has a 4xx status code
func (o *DeleteUserkeyNameConflict) IsClientError() bool {
	return true
}

// IsServerError returns true when this delete userkey name conflict response has a 5xx status code
func (o *DeleteUserkeyNameConflict) IsServerError() bool {
	return false
}

// IsCode returns true when this delete userkey name conflict response a status code equal to that given
func (o *DeleteUserkeyNameConflict) IsCode(code int) bool {
	return code == 409
}

// Code gets the status code for the delete userkey name conflict response
func (o *DeleteUserkeyNameConflict) Code() int {
	return 409
}

func (o *DeleteUserkeyNameConflict) Error() string {
	return fmt.Sprintf("[DELETE /userkey/{name}][%d] deleteUserkeyNameConflict  %+v", 409, o.Payload)
}

func (o *DeleteUserkeyNameConflict) String() string {
	return fmt.Sprintf("[DELETE /userkey/{name}][%d] deleteUserkeyNameConflict  %+v", 409, o.Payload)
}

func (o *DeleteUserkeyNameConflict) GetPayload() string {
	return o.Payload
}

func (o *DeleteUserkeyNameConflict) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDeleteUserkeyNamePreconditionFailed creates a DeleteUserkeyNamePreconditionFailed with default headers values
func NewDeleteUserkeyNamePreconditionFailed() *DeleteUserkeyNamePreconditionFailed {
	return &DeleteUserkeyNamePreconditionFailed{}
}

/*
DeleteUserkeyNamePreconditionFailed describes a response with status code 412, with default header values.

Precondition Failed
*/
type DeleteUserkeyNamePreconditionFailed struct {
	Payload string
}

// IsSuccess returns true when this delete userkey name precondition failed response has a 2xx status code
func (o *DeleteUserkeyNamePreconditionFailed) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this delete userkey name precondition failed response has a 3xx status code
func (o *DeleteUserkeyNamePreconditionFailed) IsRedirect() bool {
	return false
}

// IsClientError returns true when this delete userkey name precondition failed response has a 4xx status code
func (o *DeleteUserkeyNamePreconditionFailed) IsClientError() bool {
	return true
}

// IsServerError returns true when this delete userkey name precondition failed response has a 5xx status code
func (o *DeleteUserkeyNamePreconditionFailed) IsServerError() bool {
	return false
}

// IsCode returns true when this delete userkey name precondition failed response a status code equal to that given
func (o *DeleteUserkeyNamePreconditionFailed) IsCode(code int) bool {
	return code == 412
}

// Code gets the status code for the delete userkey name precondition failed response
func (o *DeleteUserkeyNamePreconditionFailed) Code() int {
	return 412
}

func (o *DeleteUserkeyNamePreconditionFailed) Error() string {
	return fmt.Sprintf("[DELETE /userkey/{name}][%d] deleteUserkeyNamePreconditionFailed  %+v", 412, o.Payload)
}

func (o *DeleteUserkeyNamePreconditionFailed) String() string {
	return fmt.Sprintf("[DELETE /userkey/{name}][%d] deleteUserkeyNamePreconditionFailed  %+v", 412, o.Payload)
}

func (o *DeleteUserkeyNamePreconditionFailed) GetPayload() string {
	return o.Payload
}

func (o *DeleteUserkeyNamePreconditionFailed) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDeleteUserkeyNameInternalServerError creates a DeleteUserkeyNameInternalServerError with default headers values
func NewDeleteUserkeyNameInternalServerError() *DeleteUserkeyNameInternalServerError {
	return &DeleteUserkeyNameInternalServerError{}
}

/*
DeleteUserkeyNameInternalServerError describes a response with status code 500, with default header values.

Internal Server Error
*/
type DeleteUserkeyNameInternalServerError struct {
	Payload string
}

// IsSuccess returns true when this delete userkey name internal server error response has a 2xx status code
func (o *DeleteUserkeyNameInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this delete userkey name internal server error response has a 3xx status code
func (o *DeleteUserkeyNameInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this delete userkey name internal server error response has a 4xx status code
func (o *DeleteUserkeyNameInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this delete userkey name internal server error response has a 5xx status code
func (o *DeleteUserkeyNameInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this delete userkey name internal server error response a status code equal to that given
func (o *DeleteUserkeyNameInternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the delete userkey name internal server error response
func (o *DeleteUserkeyNameInternalServerError) Code() int {
	return 500
}

func (o *DeleteUserkeyNameInternalServerError) Error() string {
	return fmt.Sprintf("[DELETE /userkey/{name}][%d] deleteUserkeyNameInternalServerError  %+v", 500, o.Payload)
}

func (o *DeleteUserkeyNameInternalServerError) String() string {
	return fmt.Sprintf("[DELETE /userkey/{name}][%d] deleteUserkeyNameInternalServerError  %+v", 500, o.Payload)
}

func (o *DeleteUserkeyNameInternalServerError) GetPayload() string {
	return o.Payload
}

func (o *DeleteUserkeyNameInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
