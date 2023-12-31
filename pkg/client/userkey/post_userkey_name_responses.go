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

// PostUserkeyNameReader is a Reader for the PostUserkeyName structure.
type PostUserkeyNameReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *PostUserkeyNameReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewPostUserkeyNameOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewPostUserkeyNameBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewPostUserkeyNameUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewPostUserkeyNameNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 409:
		result := NewPostUserkeyNameConflict()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 412:
		result := NewPostUserkeyNamePreconditionFailed()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewPostUserkeyNameInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[POST /userkey/{name}] PostUserkeyName", response, response.Code())
	}
}

// NewPostUserkeyNameOK creates a PostUserkeyNameOK with default headers values
func NewPostUserkeyNameOK() *PostUserkeyNameOK {
	return &PostUserkeyNameOK{}
}

/*
PostUserkeyNameOK describes a response with status code 200, with default header values.

OK
*/
type PostUserkeyNameOK struct {
	Payload *models.ModelsUserKeyResponse
}

// IsSuccess returns true when this post userkey name o k response has a 2xx status code
func (o *PostUserkeyNameOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this post userkey name o k response has a 3xx status code
func (o *PostUserkeyNameOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this post userkey name o k response has a 4xx status code
func (o *PostUserkeyNameOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this post userkey name o k response has a 5xx status code
func (o *PostUserkeyNameOK) IsServerError() bool {
	return false
}

// IsCode returns true when this post userkey name o k response a status code equal to that given
func (o *PostUserkeyNameOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the post userkey name o k response
func (o *PostUserkeyNameOK) Code() int {
	return 200
}

func (o *PostUserkeyNameOK) Error() string {
	return fmt.Sprintf("[POST /userkey/{name}][%d] postUserkeyNameOK  %+v", 200, o.Payload)
}

func (o *PostUserkeyNameOK) String() string {
	return fmt.Sprintf("[POST /userkey/{name}][%d] postUserkeyNameOK  %+v", 200, o.Payload)
}

func (o *PostUserkeyNameOK) GetPayload() *models.ModelsUserKeyResponse {
	return o.Payload
}

func (o *PostUserkeyNameOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ModelsUserKeyResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPostUserkeyNameBadRequest creates a PostUserkeyNameBadRequest with default headers values
func NewPostUserkeyNameBadRequest() *PostUserkeyNameBadRequest {
	return &PostUserkeyNameBadRequest{}
}

/*
PostUserkeyNameBadRequest describes a response with status code 400, with default header values.

Bad Request
*/
type PostUserkeyNameBadRequest struct {
	Payload string
}

// IsSuccess returns true when this post userkey name bad request response has a 2xx status code
func (o *PostUserkeyNameBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this post userkey name bad request response has a 3xx status code
func (o *PostUserkeyNameBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this post userkey name bad request response has a 4xx status code
func (o *PostUserkeyNameBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this post userkey name bad request response has a 5xx status code
func (o *PostUserkeyNameBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this post userkey name bad request response a status code equal to that given
func (o *PostUserkeyNameBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the post userkey name bad request response
func (o *PostUserkeyNameBadRequest) Code() int {
	return 400
}

func (o *PostUserkeyNameBadRequest) Error() string {
	return fmt.Sprintf("[POST /userkey/{name}][%d] postUserkeyNameBadRequest  %+v", 400, o.Payload)
}

func (o *PostUserkeyNameBadRequest) String() string {
	return fmt.Sprintf("[POST /userkey/{name}][%d] postUserkeyNameBadRequest  %+v", 400, o.Payload)
}

func (o *PostUserkeyNameBadRequest) GetPayload() string {
	return o.Payload
}

func (o *PostUserkeyNameBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPostUserkeyNameUnauthorized creates a PostUserkeyNameUnauthorized with default headers values
func NewPostUserkeyNameUnauthorized() *PostUserkeyNameUnauthorized {
	return &PostUserkeyNameUnauthorized{}
}

/*
PostUserkeyNameUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type PostUserkeyNameUnauthorized struct {
	Payload string
}

// IsSuccess returns true when this post userkey name unauthorized response has a 2xx status code
func (o *PostUserkeyNameUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this post userkey name unauthorized response has a 3xx status code
func (o *PostUserkeyNameUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this post userkey name unauthorized response has a 4xx status code
func (o *PostUserkeyNameUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this post userkey name unauthorized response has a 5xx status code
func (o *PostUserkeyNameUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this post userkey name unauthorized response a status code equal to that given
func (o *PostUserkeyNameUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the post userkey name unauthorized response
func (o *PostUserkeyNameUnauthorized) Code() int {
	return 401
}

func (o *PostUserkeyNameUnauthorized) Error() string {
	return fmt.Sprintf("[POST /userkey/{name}][%d] postUserkeyNameUnauthorized  %+v", 401, o.Payload)
}

func (o *PostUserkeyNameUnauthorized) String() string {
	return fmt.Sprintf("[POST /userkey/{name}][%d] postUserkeyNameUnauthorized  %+v", 401, o.Payload)
}

func (o *PostUserkeyNameUnauthorized) GetPayload() string {
	return o.Payload
}

func (o *PostUserkeyNameUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPostUserkeyNameNotFound creates a PostUserkeyNameNotFound with default headers values
func NewPostUserkeyNameNotFound() *PostUserkeyNameNotFound {
	return &PostUserkeyNameNotFound{}
}

/*
PostUserkeyNameNotFound describes a response with status code 404, with default header values.

Not Found
*/
type PostUserkeyNameNotFound struct {
	Payload string
}

// IsSuccess returns true when this post userkey name not found response has a 2xx status code
func (o *PostUserkeyNameNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this post userkey name not found response has a 3xx status code
func (o *PostUserkeyNameNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this post userkey name not found response has a 4xx status code
func (o *PostUserkeyNameNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this post userkey name not found response has a 5xx status code
func (o *PostUserkeyNameNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this post userkey name not found response a status code equal to that given
func (o *PostUserkeyNameNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the post userkey name not found response
func (o *PostUserkeyNameNotFound) Code() int {
	return 404
}

func (o *PostUserkeyNameNotFound) Error() string {
	return fmt.Sprintf("[POST /userkey/{name}][%d] postUserkeyNameNotFound  %+v", 404, o.Payload)
}

func (o *PostUserkeyNameNotFound) String() string {
	return fmt.Sprintf("[POST /userkey/{name}][%d] postUserkeyNameNotFound  %+v", 404, o.Payload)
}

func (o *PostUserkeyNameNotFound) GetPayload() string {
	return o.Payload
}

func (o *PostUserkeyNameNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPostUserkeyNameConflict creates a PostUserkeyNameConflict with default headers values
func NewPostUserkeyNameConflict() *PostUserkeyNameConflict {
	return &PostUserkeyNameConflict{}
}

/*
PostUserkeyNameConflict describes a response with status code 409, with default header values.

Conflict
*/
type PostUserkeyNameConflict struct {
	Payload string
}

// IsSuccess returns true when this post userkey name conflict response has a 2xx status code
func (o *PostUserkeyNameConflict) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this post userkey name conflict response has a 3xx status code
func (o *PostUserkeyNameConflict) IsRedirect() bool {
	return false
}

// IsClientError returns true when this post userkey name conflict response has a 4xx status code
func (o *PostUserkeyNameConflict) IsClientError() bool {
	return true
}

// IsServerError returns true when this post userkey name conflict response has a 5xx status code
func (o *PostUserkeyNameConflict) IsServerError() bool {
	return false
}

// IsCode returns true when this post userkey name conflict response a status code equal to that given
func (o *PostUserkeyNameConflict) IsCode(code int) bool {
	return code == 409
}

// Code gets the status code for the post userkey name conflict response
func (o *PostUserkeyNameConflict) Code() int {
	return 409
}

func (o *PostUserkeyNameConflict) Error() string {
	return fmt.Sprintf("[POST /userkey/{name}][%d] postUserkeyNameConflict  %+v", 409, o.Payload)
}

func (o *PostUserkeyNameConflict) String() string {
	return fmt.Sprintf("[POST /userkey/{name}][%d] postUserkeyNameConflict  %+v", 409, o.Payload)
}

func (o *PostUserkeyNameConflict) GetPayload() string {
	return o.Payload
}

func (o *PostUserkeyNameConflict) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPostUserkeyNamePreconditionFailed creates a PostUserkeyNamePreconditionFailed with default headers values
func NewPostUserkeyNamePreconditionFailed() *PostUserkeyNamePreconditionFailed {
	return &PostUserkeyNamePreconditionFailed{}
}

/*
PostUserkeyNamePreconditionFailed describes a response with status code 412, with default header values.

Precondition Failed
*/
type PostUserkeyNamePreconditionFailed struct {
	Payload string
}

// IsSuccess returns true when this post userkey name precondition failed response has a 2xx status code
func (o *PostUserkeyNamePreconditionFailed) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this post userkey name precondition failed response has a 3xx status code
func (o *PostUserkeyNamePreconditionFailed) IsRedirect() bool {
	return false
}

// IsClientError returns true when this post userkey name precondition failed response has a 4xx status code
func (o *PostUserkeyNamePreconditionFailed) IsClientError() bool {
	return true
}

// IsServerError returns true when this post userkey name precondition failed response has a 5xx status code
func (o *PostUserkeyNamePreconditionFailed) IsServerError() bool {
	return false
}

// IsCode returns true when this post userkey name precondition failed response a status code equal to that given
func (o *PostUserkeyNamePreconditionFailed) IsCode(code int) bool {
	return code == 412
}

// Code gets the status code for the post userkey name precondition failed response
func (o *PostUserkeyNamePreconditionFailed) Code() int {
	return 412
}

func (o *PostUserkeyNamePreconditionFailed) Error() string {
	return fmt.Sprintf("[POST /userkey/{name}][%d] postUserkeyNamePreconditionFailed  %+v", 412, o.Payload)
}

func (o *PostUserkeyNamePreconditionFailed) String() string {
	return fmt.Sprintf("[POST /userkey/{name}][%d] postUserkeyNamePreconditionFailed  %+v", 412, o.Payload)
}

func (o *PostUserkeyNamePreconditionFailed) GetPayload() string {
	return o.Payload
}

func (o *PostUserkeyNamePreconditionFailed) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPostUserkeyNameInternalServerError creates a PostUserkeyNameInternalServerError with default headers values
func NewPostUserkeyNameInternalServerError() *PostUserkeyNameInternalServerError {
	return &PostUserkeyNameInternalServerError{}
}

/*
PostUserkeyNameInternalServerError describes a response with status code 500, with default header values.

Internal Server Error
*/
type PostUserkeyNameInternalServerError struct {
	Payload string
}

// IsSuccess returns true when this post userkey name internal server error response has a 2xx status code
func (o *PostUserkeyNameInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this post userkey name internal server error response has a 3xx status code
func (o *PostUserkeyNameInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this post userkey name internal server error response has a 4xx status code
func (o *PostUserkeyNameInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this post userkey name internal server error response has a 5xx status code
func (o *PostUserkeyNameInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this post userkey name internal server error response a status code equal to that given
func (o *PostUserkeyNameInternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the post userkey name internal server error response
func (o *PostUserkeyNameInternalServerError) Code() int {
	return 500
}

func (o *PostUserkeyNameInternalServerError) Error() string {
	return fmt.Sprintf("[POST /userkey/{name}][%d] postUserkeyNameInternalServerError  %+v", 500, o.Payload)
}

func (o *PostUserkeyNameInternalServerError) String() string {
	return fmt.Sprintf("[POST /userkey/{name}][%d] postUserkeyNameInternalServerError  %+v", 500, o.Payload)
}

func (o *PostUserkeyNameInternalServerError) GetPayload() string {
	return o.Payload
}

func (o *PostUserkeyNameInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
