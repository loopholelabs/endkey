// Code generated by go-swagger; DO NOT EDIT.

package certificate

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/loopholelabs/endkey/pkg/client/models"
)

// PostCertificateReader is a Reader for the PostCertificate structure.
type PostCertificateReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *PostCertificateReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewPostCertificateOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewPostCertificateBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewPostCertificateUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewPostCertificateNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 409:
		result := NewPostCertificateConflict()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 412:
		result := NewPostCertificatePreconditionFailed()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewPostCertificateInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[POST /certificate] PostCertificate", response, response.Code())
	}
}

// NewPostCertificateOK creates a PostCertificateOK with default headers values
func NewPostCertificateOK() *PostCertificateOK {
	return &PostCertificateOK{}
}

/*
PostCertificateOK describes a response with status code 200, with default header values.

OK
*/
type PostCertificateOK struct {
	Payload *models.ModelsCertificateResponse
}

// IsSuccess returns true when this post certificate o k response has a 2xx status code
func (o *PostCertificateOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this post certificate o k response has a 3xx status code
func (o *PostCertificateOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this post certificate o k response has a 4xx status code
func (o *PostCertificateOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this post certificate o k response has a 5xx status code
func (o *PostCertificateOK) IsServerError() bool {
	return false
}

// IsCode returns true when this post certificate o k response a status code equal to that given
func (o *PostCertificateOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the post certificate o k response
func (o *PostCertificateOK) Code() int {
	return 200
}

func (o *PostCertificateOK) Error() string {
	return fmt.Sprintf("[POST /certificate][%d] postCertificateOK  %+v", 200, o.Payload)
}

func (o *PostCertificateOK) String() string {
	return fmt.Sprintf("[POST /certificate][%d] postCertificateOK  %+v", 200, o.Payload)
}

func (o *PostCertificateOK) GetPayload() *models.ModelsCertificateResponse {
	return o.Payload
}

func (o *PostCertificateOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ModelsCertificateResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPostCertificateBadRequest creates a PostCertificateBadRequest with default headers values
func NewPostCertificateBadRequest() *PostCertificateBadRequest {
	return &PostCertificateBadRequest{}
}

/*
PostCertificateBadRequest describes a response with status code 400, with default header values.

Bad Request
*/
type PostCertificateBadRequest struct {
	Payload string
}

// IsSuccess returns true when this post certificate bad request response has a 2xx status code
func (o *PostCertificateBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this post certificate bad request response has a 3xx status code
func (o *PostCertificateBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this post certificate bad request response has a 4xx status code
func (o *PostCertificateBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this post certificate bad request response has a 5xx status code
func (o *PostCertificateBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this post certificate bad request response a status code equal to that given
func (o *PostCertificateBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the post certificate bad request response
func (o *PostCertificateBadRequest) Code() int {
	return 400
}

func (o *PostCertificateBadRequest) Error() string {
	return fmt.Sprintf("[POST /certificate][%d] postCertificateBadRequest  %+v", 400, o.Payload)
}

func (o *PostCertificateBadRequest) String() string {
	return fmt.Sprintf("[POST /certificate][%d] postCertificateBadRequest  %+v", 400, o.Payload)
}

func (o *PostCertificateBadRequest) GetPayload() string {
	return o.Payload
}

func (o *PostCertificateBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPostCertificateUnauthorized creates a PostCertificateUnauthorized with default headers values
func NewPostCertificateUnauthorized() *PostCertificateUnauthorized {
	return &PostCertificateUnauthorized{}
}

/*
PostCertificateUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type PostCertificateUnauthorized struct {
	Payload string
}

// IsSuccess returns true when this post certificate unauthorized response has a 2xx status code
func (o *PostCertificateUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this post certificate unauthorized response has a 3xx status code
func (o *PostCertificateUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this post certificate unauthorized response has a 4xx status code
func (o *PostCertificateUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this post certificate unauthorized response has a 5xx status code
func (o *PostCertificateUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this post certificate unauthorized response a status code equal to that given
func (o *PostCertificateUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the post certificate unauthorized response
func (o *PostCertificateUnauthorized) Code() int {
	return 401
}

func (o *PostCertificateUnauthorized) Error() string {
	return fmt.Sprintf("[POST /certificate][%d] postCertificateUnauthorized  %+v", 401, o.Payload)
}

func (o *PostCertificateUnauthorized) String() string {
	return fmt.Sprintf("[POST /certificate][%d] postCertificateUnauthorized  %+v", 401, o.Payload)
}

func (o *PostCertificateUnauthorized) GetPayload() string {
	return o.Payload
}

func (o *PostCertificateUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPostCertificateNotFound creates a PostCertificateNotFound with default headers values
func NewPostCertificateNotFound() *PostCertificateNotFound {
	return &PostCertificateNotFound{}
}

/*
PostCertificateNotFound describes a response with status code 404, with default header values.

Not Found
*/
type PostCertificateNotFound struct {
	Payload string
}

// IsSuccess returns true when this post certificate not found response has a 2xx status code
func (o *PostCertificateNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this post certificate not found response has a 3xx status code
func (o *PostCertificateNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this post certificate not found response has a 4xx status code
func (o *PostCertificateNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this post certificate not found response has a 5xx status code
func (o *PostCertificateNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this post certificate not found response a status code equal to that given
func (o *PostCertificateNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the post certificate not found response
func (o *PostCertificateNotFound) Code() int {
	return 404
}

func (o *PostCertificateNotFound) Error() string {
	return fmt.Sprintf("[POST /certificate][%d] postCertificateNotFound  %+v", 404, o.Payload)
}

func (o *PostCertificateNotFound) String() string {
	return fmt.Sprintf("[POST /certificate][%d] postCertificateNotFound  %+v", 404, o.Payload)
}

func (o *PostCertificateNotFound) GetPayload() string {
	return o.Payload
}

func (o *PostCertificateNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPostCertificateConflict creates a PostCertificateConflict with default headers values
func NewPostCertificateConflict() *PostCertificateConflict {
	return &PostCertificateConflict{}
}

/*
PostCertificateConflict describes a response with status code 409, with default header values.

Conflict
*/
type PostCertificateConflict struct {
	Payload string
}

// IsSuccess returns true when this post certificate conflict response has a 2xx status code
func (o *PostCertificateConflict) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this post certificate conflict response has a 3xx status code
func (o *PostCertificateConflict) IsRedirect() bool {
	return false
}

// IsClientError returns true when this post certificate conflict response has a 4xx status code
func (o *PostCertificateConflict) IsClientError() bool {
	return true
}

// IsServerError returns true when this post certificate conflict response has a 5xx status code
func (o *PostCertificateConflict) IsServerError() bool {
	return false
}

// IsCode returns true when this post certificate conflict response a status code equal to that given
func (o *PostCertificateConflict) IsCode(code int) bool {
	return code == 409
}

// Code gets the status code for the post certificate conflict response
func (o *PostCertificateConflict) Code() int {
	return 409
}

func (o *PostCertificateConflict) Error() string {
	return fmt.Sprintf("[POST /certificate][%d] postCertificateConflict  %+v", 409, o.Payload)
}

func (o *PostCertificateConflict) String() string {
	return fmt.Sprintf("[POST /certificate][%d] postCertificateConflict  %+v", 409, o.Payload)
}

func (o *PostCertificateConflict) GetPayload() string {
	return o.Payload
}

func (o *PostCertificateConflict) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPostCertificatePreconditionFailed creates a PostCertificatePreconditionFailed with default headers values
func NewPostCertificatePreconditionFailed() *PostCertificatePreconditionFailed {
	return &PostCertificatePreconditionFailed{}
}

/*
PostCertificatePreconditionFailed describes a response with status code 412, with default header values.

Precondition Failed
*/
type PostCertificatePreconditionFailed struct {
	Payload string
}

// IsSuccess returns true when this post certificate precondition failed response has a 2xx status code
func (o *PostCertificatePreconditionFailed) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this post certificate precondition failed response has a 3xx status code
func (o *PostCertificatePreconditionFailed) IsRedirect() bool {
	return false
}

// IsClientError returns true when this post certificate precondition failed response has a 4xx status code
func (o *PostCertificatePreconditionFailed) IsClientError() bool {
	return true
}

// IsServerError returns true when this post certificate precondition failed response has a 5xx status code
func (o *PostCertificatePreconditionFailed) IsServerError() bool {
	return false
}

// IsCode returns true when this post certificate precondition failed response a status code equal to that given
func (o *PostCertificatePreconditionFailed) IsCode(code int) bool {
	return code == 412
}

// Code gets the status code for the post certificate precondition failed response
func (o *PostCertificatePreconditionFailed) Code() int {
	return 412
}

func (o *PostCertificatePreconditionFailed) Error() string {
	return fmt.Sprintf("[POST /certificate][%d] postCertificatePreconditionFailed  %+v", 412, o.Payload)
}

func (o *PostCertificatePreconditionFailed) String() string {
	return fmt.Sprintf("[POST /certificate][%d] postCertificatePreconditionFailed  %+v", 412, o.Payload)
}

func (o *PostCertificatePreconditionFailed) GetPayload() string {
	return o.Payload
}

func (o *PostCertificatePreconditionFailed) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPostCertificateInternalServerError creates a PostCertificateInternalServerError with default headers values
func NewPostCertificateInternalServerError() *PostCertificateInternalServerError {
	return &PostCertificateInternalServerError{}
}

/*
PostCertificateInternalServerError describes a response with status code 500, with default header values.

Internal Server Error
*/
type PostCertificateInternalServerError struct {
	Payload string
}

// IsSuccess returns true when this post certificate internal server error response has a 2xx status code
func (o *PostCertificateInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this post certificate internal server error response has a 3xx status code
func (o *PostCertificateInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this post certificate internal server error response has a 4xx status code
func (o *PostCertificateInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this post certificate internal server error response has a 5xx status code
func (o *PostCertificateInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this post certificate internal server error response a status code equal to that given
func (o *PostCertificateInternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the post certificate internal server error response
func (o *PostCertificateInternalServerError) Code() int {
	return 500
}

func (o *PostCertificateInternalServerError) Error() string {
	return fmt.Sprintf("[POST /certificate][%d] postCertificateInternalServerError  %+v", 500, o.Payload)
}

func (o *PostCertificateInternalServerError) String() string {
	return fmt.Sprintf("[POST /certificate][%d] postCertificateInternalServerError  %+v", 500, o.Payload)
}

func (o *PostCertificateInternalServerError) GetPayload() string {
	return o.Payload
}

func (o *PostCertificateInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
