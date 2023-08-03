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

// PostUserkeyRotateNameReader is a Reader for the PostUserkeyRotateName structure.
type PostUserkeyRotateNameReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *PostUserkeyRotateNameReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewPostUserkeyRotateNameOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewPostUserkeyRotateNameBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewPostUserkeyRotateNameUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewPostUserkeyRotateNameNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 409:
		result := NewPostUserkeyRotateNameConflict()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 412:
		result := NewPostUserkeyRotateNamePreconditionFailed()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewPostUserkeyRotateNameInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[POST /userkey/rotate/{name}] PostUserkeyRotateName", response, response.Code())
	}
}

// NewPostUserkeyRotateNameOK creates a PostUserkeyRotateNameOK with default headers values
func NewPostUserkeyRotateNameOK() *PostUserkeyRotateNameOK {
	return &PostUserkeyRotateNameOK{}
}

/*
PostUserkeyRotateNameOK describes a response with status code 200, with default header values.

OK
*/
type PostUserkeyRotateNameOK struct {
	Payload *models.ModelsUserKeyResponse
}

// IsSuccess returns true when this post userkey rotate name o k response has a 2xx status code
func (o *PostUserkeyRotateNameOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this post userkey rotate name o k response has a 3xx status code
func (o *PostUserkeyRotateNameOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this post userkey rotate name o k response has a 4xx status code
func (o *PostUserkeyRotateNameOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this post userkey rotate name o k response has a 5xx status code
func (o *PostUserkeyRotateNameOK) IsServerError() bool {
	return false
}

// IsCode returns true when this post userkey rotate name o k response a status code equal to that given
func (o *PostUserkeyRotateNameOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the post userkey rotate name o k response
func (o *PostUserkeyRotateNameOK) Code() int {
	return 200
}

func (o *PostUserkeyRotateNameOK) Error() string {
	return fmt.Sprintf("[POST /userkey/rotate/{name}][%d] postUserkeyRotateNameOK  %+v", 200, o.Payload)
}

func (o *PostUserkeyRotateNameOK) String() string {
	return fmt.Sprintf("[POST /userkey/rotate/{name}][%d] postUserkeyRotateNameOK  %+v", 200, o.Payload)
}

func (o *PostUserkeyRotateNameOK) GetPayload() *models.ModelsUserKeyResponse {
	return o.Payload
}

func (o *PostUserkeyRotateNameOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ModelsUserKeyResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPostUserkeyRotateNameBadRequest creates a PostUserkeyRotateNameBadRequest with default headers values
func NewPostUserkeyRotateNameBadRequest() *PostUserkeyRotateNameBadRequest {
	return &PostUserkeyRotateNameBadRequest{}
}

/*
PostUserkeyRotateNameBadRequest describes a response with status code 400, with default header values.

Bad Request
*/
type PostUserkeyRotateNameBadRequest struct {
	Payload string
}

// IsSuccess returns true when this post userkey rotate name bad request response has a 2xx status code
func (o *PostUserkeyRotateNameBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this post userkey rotate name bad request response has a 3xx status code
func (o *PostUserkeyRotateNameBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this post userkey rotate name bad request response has a 4xx status code
func (o *PostUserkeyRotateNameBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this post userkey rotate name bad request response has a 5xx status code
func (o *PostUserkeyRotateNameBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this post userkey rotate name bad request response a status code equal to that given
func (o *PostUserkeyRotateNameBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the post userkey rotate name bad request response
func (o *PostUserkeyRotateNameBadRequest) Code() int {
	return 400
}

func (o *PostUserkeyRotateNameBadRequest) Error() string {
	return fmt.Sprintf("[POST /userkey/rotate/{name}][%d] postUserkeyRotateNameBadRequest  %+v", 400, o.Payload)
}

func (o *PostUserkeyRotateNameBadRequest) String() string {
	return fmt.Sprintf("[POST /userkey/rotate/{name}][%d] postUserkeyRotateNameBadRequest  %+v", 400, o.Payload)
}

func (o *PostUserkeyRotateNameBadRequest) GetPayload() string {
	return o.Payload
}

func (o *PostUserkeyRotateNameBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPostUserkeyRotateNameUnauthorized creates a PostUserkeyRotateNameUnauthorized with default headers values
func NewPostUserkeyRotateNameUnauthorized() *PostUserkeyRotateNameUnauthorized {
	return &PostUserkeyRotateNameUnauthorized{}
}

/*
PostUserkeyRotateNameUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type PostUserkeyRotateNameUnauthorized struct {
	Payload string
}

// IsSuccess returns true when this post userkey rotate name unauthorized response has a 2xx status code
func (o *PostUserkeyRotateNameUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this post userkey rotate name unauthorized response has a 3xx status code
func (o *PostUserkeyRotateNameUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this post userkey rotate name unauthorized response has a 4xx status code
func (o *PostUserkeyRotateNameUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this post userkey rotate name unauthorized response has a 5xx status code
func (o *PostUserkeyRotateNameUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this post userkey rotate name unauthorized response a status code equal to that given
func (o *PostUserkeyRotateNameUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the post userkey rotate name unauthorized response
func (o *PostUserkeyRotateNameUnauthorized) Code() int {
	return 401
}

func (o *PostUserkeyRotateNameUnauthorized) Error() string {
	return fmt.Sprintf("[POST /userkey/rotate/{name}][%d] postUserkeyRotateNameUnauthorized  %+v", 401, o.Payload)
}

func (o *PostUserkeyRotateNameUnauthorized) String() string {
	return fmt.Sprintf("[POST /userkey/rotate/{name}][%d] postUserkeyRotateNameUnauthorized  %+v", 401, o.Payload)
}

func (o *PostUserkeyRotateNameUnauthorized) GetPayload() string {
	return o.Payload
}

func (o *PostUserkeyRotateNameUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPostUserkeyRotateNameNotFound creates a PostUserkeyRotateNameNotFound with default headers values
func NewPostUserkeyRotateNameNotFound() *PostUserkeyRotateNameNotFound {
	return &PostUserkeyRotateNameNotFound{}
}

/*
PostUserkeyRotateNameNotFound describes a response with status code 404, with default header values.

Not Found
*/
type PostUserkeyRotateNameNotFound struct {
	Payload string
}

// IsSuccess returns true when this post userkey rotate name not found response has a 2xx status code
func (o *PostUserkeyRotateNameNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this post userkey rotate name not found response has a 3xx status code
func (o *PostUserkeyRotateNameNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this post userkey rotate name not found response has a 4xx status code
func (o *PostUserkeyRotateNameNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this post userkey rotate name not found response has a 5xx status code
func (o *PostUserkeyRotateNameNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this post userkey rotate name not found response a status code equal to that given
func (o *PostUserkeyRotateNameNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the post userkey rotate name not found response
func (o *PostUserkeyRotateNameNotFound) Code() int {
	return 404
}

func (o *PostUserkeyRotateNameNotFound) Error() string {
	return fmt.Sprintf("[POST /userkey/rotate/{name}][%d] postUserkeyRotateNameNotFound  %+v", 404, o.Payload)
}

func (o *PostUserkeyRotateNameNotFound) String() string {
	return fmt.Sprintf("[POST /userkey/rotate/{name}][%d] postUserkeyRotateNameNotFound  %+v", 404, o.Payload)
}

func (o *PostUserkeyRotateNameNotFound) GetPayload() string {
	return o.Payload
}

func (o *PostUserkeyRotateNameNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPostUserkeyRotateNameConflict creates a PostUserkeyRotateNameConflict with default headers values
func NewPostUserkeyRotateNameConflict() *PostUserkeyRotateNameConflict {
	return &PostUserkeyRotateNameConflict{}
}

/*
PostUserkeyRotateNameConflict describes a response with status code 409, with default header values.

Conflict
*/
type PostUserkeyRotateNameConflict struct {
	Payload string
}

// IsSuccess returns true when this post userkey rotate name conflict response has a 2xx status code
func (o *PostUserkeyRotateNameConflict) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this post userkey rotate name conflict response has a 3xx status code
func (o *PostUserkeyRotateNameConflict) IsRedirect() bool {
	return false
}

// IsClientError returns true when this post userkey rotate name conflict response has a 4xx status code
func (o *PostUserkeyRotateNameConflict) IsClientError() bool {
	return true
}

// IsServerError returns true when this post userkey rotate name conflict response has a 5xx status code
func (o *PostUserkeyRotateNameConflict) IsServerError() bool {
	return false
}

// IsCode returns true when this post userkey rotate name conflict response a status code equal to that given
func (o *PostUserkeyRotateNameConflict) IsCode(code int) bool {
	return code == 409
}

// Code gets the status code for the post userkey rotate name conflict response
func (o *PostUserkeyRotateNameConflict) Code() int {
	return 409
}

func (o *PostUserkeyRotateNameConflict) Error() string {
	return fmt.Sprintf("[POST /userkey/rotate/{name}][%d] postUserkeyRotateNameConflict  %+v", 409, o.Payload)
}

func (o *PostUserkeyRotateNameConflict) String() string {
	return fmt.Sprintf("[POST /userkey/rotate/{name}][%d] postUserkeyRotateNameConflict  %+v", 409, o.Payload)
}

func (o *PostUserkeyRotateNameConflict) GetPayload() string {
	return o.Payload
}

func (o *PostUserkeyRotateNameConflict) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPostUserkeyRotateNamePreconditionFailed creates a PostUserkeyRotateNamePreconditionFailed with default headers values
func NewPostUserkeyRotateNamePreconditionFailed() *PostUserkeyRotateNamePreconditionFailed {
	return &PostUserkeyRotateNamePreconditionFailed{}
}

/*
PostUserkeyRotateNamePreconditionFailed describes a response with status code 412, with default header values.

Precondition Failed
*/
type PostUserkeyRotateNamePreconditionFailed struct {
	Payload string
}

// IsSuccess returns true when this post userkey rotate name precondition failed response has a 2xx status code
func (o *PostUserkeyRotateNamePreconditionFailed) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this post userkey rotate name precondition failed response has a 3xx status code
func (o *PostUserkeyRotateNamePreconditionFailed) IsRedirect() bool {
	return false
}

// IsClientError returns true when this post userkey rotate name precondition failed response has a 4xx status code
func (o *PostUserkeyRotateNamePreconditionFailed) IsClientError() bool {
	return true
}

// IsServerError returns true when this post userkey rotate name precondition failed response has a 5xx status code
func (o *PostUserkeyRotateNamePreconditionFailed) IsServerError() bool {
	return false
}

// IsCode returns true when this post userkey rotate name precondition failed response a status code equal to that given
func (o *PostUserkeyRotateNamePreconditionFailed) IsCode(code int) bool {
	return code == 412
}

// Code gets the status code for the post userkey rotate name precondition failed response
func (o *PostUserkeyRotateNamePreconditionFailed) Code() int {
	return 412
}

func (o *PostUserkeyRotateNamePreconditionFailed) Error() string {
	return fmt.Sprintf("[POST /userkey/rotate/{name}][%d] postUserkeyRotateNamePreconditionFailed  %+v", 412, o.Payload)
}

func (o *PostUserkeyRotateNamePreconditionFailed) String() string {
	return fmt.Sprintf("[POST /userkey/rotate/{name}][%d] postUserkeyRotateNamePreconditionFailed  %+v", 412, o.Payload)
}

func (o *PostUserkeyRotateNamePreconditionFailed) GetPayload() string {
	return o.Payload
}

func (o *PostUserkeyRotateNamePreconditionFailed) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPostUserkeyRotateNameInternalServerError creates a PostUserkeyRotateNameInternalServerError with default headers values
func NewPostUserkeyRotateNameInternalServerError() *PostUserkeyRotateNameInternalServerError {
	return &PostUserkeyRotateNameInternalServerError{}
}

/*
PostUserkeyRotateNameInternalServerError describes a response with status code 500, with default header values.

Internal Server Error
*/
type PostUserkeyRotateNameInternalServerError struct {
	Payload string
}

// IsSuccess returns true when this post userkey rotate name internal server error response has a 2xx status code
func (o *PostUserkeyRotateNameInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this post userkey rotate name internal server error response has a 3xx status code
func (o *PostUserkeyRotateNameInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this post userkey rotate name internal server error response has a 4xx status code
func (o *PostUserkeyRotateNameInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this post userkey rotate name internal server error response has a 5xx status code
func (o *PostUserkeyRotateNameInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this post userkey rotate name internal server error response a status code equal to that given
func (o *PostUserkeyRotateNameInternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the post userkey rotate name internal server error response
func (o *PostUserkeyRotateNameInternalServerError) Code() int {
	return 500
}

func (o *PostUserkeyRotateNameInternalServerError) Error() string {
	return fmt.Sprintf("[POST /userkey/rotate/{name}][%d] postUserkeyRotateNameInternalServerError  %+v", 500, o.Payload)
}

func (o *PostUserkeyRotateNameInternalServerError) String() string {
	return fmt.Sprintf("[POST /userkey/rotate/{name}][%d] postUserkeyRotateNameInternalServerError  %+v", 500, o.Payload)
}

func (o *PostUserkeyRotateNameInternalServerError) GetPayload() string {
	return o.Payload
}

func (o *PostUserkeyRotateNameInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
