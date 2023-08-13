// Code generated by go-swagger; DO NOT EDIT.

package template

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
)

// DeleteTemplateReader is a Reader for the DeleteTemplate structure.
type DeleteTemplateReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *DeleteTemplateReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewDeleteTemplateOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewDeleteTemplateBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewDeleteTemplateUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewDeleteTemplateNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 409:
		result := NewDeleteTemplateConflict()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 412:
		result := NewDeleteTemplatePreconditionFailed()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewDeleteTemplateInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[DELETE /template] DeleteTemplate", response, response.Code())
	}
}

// NewDeleteTemplateOK creates a DeleteTemplateOK with default headers values
func NewDeleteTemplateOK() *DeleteTemplateOK {
	return &DeleteTemplateOK{}
}

/*
DeleteTemplateOK describes a response with status code 200, with default header values.

OK
*/
type DeleteTemplateOK struct {
	Payload string
}

// IsSuccess returns true when this delete template o k response has a 2xx status code
func (o *DeleteTemplateOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this delete template o k response has a 3xx status code
func (o *DeleteTemplateOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this delete template o k response has a 4xx status code
func (o *DeleteTemplateOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this delete template o k response has a 5xx status code
func (o *DeleteTemplateOK) IsServerError() bool {
	return false
}

// IsCode returns true when this delete template o k response a status code equal to that given
func (o *DeleteTemplateOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the delete template o k response
func (o *DeleteTemplateOK) Code() int {
	return 200
}

func (o *DeleteTemplateOK) Error() string {
	return fmt.Sprintf("[DELETE /template][%d] deleteTemplateOK  %+v", 200, o.Payload)
}

func (o *DeleteTemplateOK) String() string {
	return fmt.Sprintf("[DELETE /template][%d] deleteTemplateOK  %+v", 200, o.Payload)
}

func (o *DeleteTemplateOK) GetPayload() string {
	return o.Payload
}

func (o *DeleteTemplateOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDeleteTemplateBadRequest creates a DeleteTemplateBadRequest with default headers values
func NewDeleteTemplateBadRequest() *DeleteTemplateBadRequest {
	return &DeleteTemplateBadRequest{}
}

/*
DeleteTemplateBadRequest describes a response with status code 400, with default header values.

Bad Request
*/
type DeleteTemplateBadRequest struct {
	Payload string
}

// IsSuccess returns true when this delete template bad request response has a 2xx status code
func (o *DeleteTemplateBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this delete template bad request response has a 3xx status code
func (o *DeleteTemplateBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this delete template bad request response has a 4xx status code
func (o *DeleteTemplateBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this delete template bad request response has a 5xx status code
func (o *DeleteTemplateBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this delete template bad request response a status code equal to that given
func (o *DeleteTemplateBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the delete template bad request response
func (o *DeleteTemplateBadRequest) Code() int {
	return 400
}

func (o *DeleteTemplateBadRequest) Error() string {
	return fmt.Sprintf("[DELETE /template][%d] deleteTemplateBadRequest  %+v", 400, o.Payload)
}

func (o *DeleteTemplateBadRequest) String() string {
	return fmt.Sprintf("[DELETE /template][%d] deleteTemplateBadRequest  %+v", 400, o.Payload)
}

func (o *DeleteTemplateBadRequest) GetPayload() string {
	return o.Payload
}

func (o *DeleteTemplateBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDeleteTemplateUnauthorized creates a DeleteTemplateUnauthorized with default headers values
func NewDeleteTemplateUnauthorized() *DeleteTemplateUnauthorized {
	return &DeleteTemplateUnauthorized{}
}

/*
DeleteTemplateUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type DeleteTemplateUnauthorized struct {
	Payload string
}

// IsSuccess returns true when this delete template unauthorized response has a 2xx status code
func (o *DeleteTemplateUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this delete template unauthorized response has a 3xx status code
func (o *DeleteTemplateUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this delete template unauthorized response has a 4xx status code
func (o *DeleteTemplateUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this delete template unauthorized response has a 5xx status code
func (o *DeleteTemplateUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this delete template unauthorized response a status code equal to that given
func (o *DeleteTemplateUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the delete template unauthorized response
func (o *DeleteTemplateUnauthorized) Code() int {
	return 401
}

func (o *DeleteTemplateUnauthorized) Error() string {
	return fmt.Sprintf("[DELETE /template][%d] deleteTemplateUnauthorized  %+v", 401, o.Payload)
}

func (o *DeleteTemplateUnauthorized) String() string {
	return fmt.Sprintf("[DELETE /template][%d] deleteTemplateUnauthorized  %+v", 401, o.Payload)
}

func (o *DeleteTemplateUnauthorized) GetPayload() string {
	return o.Payload
}

func (o *DeleteTemplateUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDeleteTemplateNotFound creates a DeleteTemplateNotFound with default headers values
func NewDeleteTemplateNotFound() *DeleteTemplateNotFound {
	return &DeleteTemplateNotFound{}
}

/*
DeleteTemplateNotFound describes a response with status code 404, with default header values.

Not Found
*/
type DeleteTemplateNotFound struct {
	Payload string
}

// IsSuccess returns true when this delete template not found response has a 2xx status code
func (o *DeleteTemplateNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this delete template not found response has a 3xx status code
func (o *DeleteTemplateNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this delete template not found response has a 4xx status code
func (o *DeleteTemplateNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this delete template not found response has a 5xx status code
func (o *DeleteTemplateNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this delete template not found response a status code equal to that given
func (o *DeleteTemplateNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the delete template not found response
func (o *DeleteTemplateNotFound) Code() int {
	return 404
}

func (o *DeleteTemplateNotFound) Error() string {
	return fmt.Sprintf("[DELETE /template][%d] deleteTemplateNotFound  %+v", 404, o.Payload)
}

func (o *DeleteTemplateNotFound) String() string {
	return fmt.Sprintf("[DELETE /template][%d] deleteTemplateNotFound  %+v", 404, o.Payload)
}

func (o *DeleteTemplateNotFound) GetPayload() string {
	return o.Payload
}

func (o *DeleteTemplateNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDeleteTemplateConflict creates a DeleteTemplateConflict with default headers values
func NewDeleteTemplateConflict() *DeleteTemplateConflict {
	return &DeleteTemplateConflict{}
}

/*
DeleteTemplateConflict describes a response with status code 409, with default header values.

Conflict
*/
type DeleteTemplateConflict struct {
	Payload string
}

// IsSuccess returns true when this delete template conflict response has a 2xx status code
func (o *DeleteTemplateConflict) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this delete template conflict response has a 3xx status code
func (o *DeleteTemplateConflict) IsRedirect() bool {
	return false
}

// IsClientError returns true when this delete template conflict response has a 4xx status code
func (o *DeleteTemplateConflict) IsClientError() bool {
	return true
}

// IsServerError returns true when this delete template conflict response has a 5xx status code
func (o *DeleteTemplateConflict) IsServerError() bool {
	return false
}

// IsCode returns true when this delete template conflict response a status code equal to that given
func (o *DeleteTemplateConflict) IsCode(code int) bool {
	return code == 409
}

// Code gets the status code for the delete template conflict response
func (o *DeleteTemplateConflict) Code() int {
	return 409
}

func (o *DeleteTemplateConflict) Error() string {
	return fmt.Sprintf("[DELETE /template][%d] deleteTemplateConflict  %+v", 409, o.Payload)
}

func (o *DeleteTemplateConflict) String() string {
	return fmt.Sprintf("[DELETE /template][%d] deleteTemplateConflict  %+v", 409, o.Payload)
}

func (o *DeleteTemplateConflict) GetPayload() string {
	return o.Payload
}

func (o *DeleteTemplateConflict) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDeleteTemplatePreconditionFailed creates a DeleteTemplatePreconditionFailed with default headers values
func NewDeleteTemplatePreconditionFailed() *DeleteTemplatePreconditionFailed {
	return &DeleteTemplatePreconditionFailed{}
}

/*
DeleteTemplatePreconditionFailed describes a response with status code 412, with default header values.

Precondition Failed
*/
type DeleteTemplatePreconditionFailed struct {
	Payload string
}

// IsSuccess returns true when this delete template precondition failed response has a 2xx status code
func (o *DeleteTemplatePreconditionFailed) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this delete template precondition failed response has a 3xx status code
func (o *DeleteTemplatePreconditionFailed) IsRedirect() bool {
	return false
}

// IsClientError returns true when this delete template precondition failed response has a 4xx status code
func (o *DeleteTemplatePreconditionFailed) IsClientError() bool {
	return true
}

// IsServerError returns true when this delete template precondition failed response has a 5xx status code
func (o *DeleteTemplatePreconditionFailed) IsServerError() bool {
	return false
}

// IsCode returns true when this delete template precondition failed response a status code equal to that given
func (o *DeleteTemplatePreconditionFailed) IsCode(code int) bool {
	return code == 412
}

// Code gets the status code for the delete template precondition failed response
func (o *DeleteTemplatePreconditionFailed) Code() int {
	return 412
}

func (o *DeleteTemplatePreconditionFailed) Error() string {
	return fmt.Sprintf("[DELETE /template][%d] deleteTemplatePreconditionFailed  %+v", 412, o.Payload)
}

func (o *DeleteTemplatePreconditionFailed) String() string {
	return fmt.Sprintf("[DELETE /template][%d] deleteTemplatePreconditionFailed  %+v", 412, o.Payload)
}

func (o *DeleteTemplatePreconditionFailed) GetPayload() string {
	return o.Payload
}

func (o *DeleteTemplatePreconditionFailed) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDeleteTemplateInternalServerError creates a DeleteTemplateInternalServerError with default headers values
func NewDeleteTemplateInternalServerError() *DeleteTemplateInternalServerError {
	return &DeleteTemplateInternalServerError{}
}

/*
DeleteTemplateInternalServerError describes a response with status code 500, with default header values.

Internal Server Error
*/
type DeleteTemplateInternalServerError struct {
	Payload string
}

// IsSuccess returns true when this delete template internal server error response has a 2xx status code
func (o *DeleteTemplateInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this delete template internal server error response has a 3xx status code
func (o *DeleteTemplateInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this delete template internal server error response has a 4xx status code
func (o *DeleteTemplateInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this delete template internal server error response has a 5xx status code
func (o *DeleteTemplateInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this delete template internal server error response a status code equal to that given
func (o *DeleteTemplateInternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the delete template internal server error response
func (o *DeleteTemplateInternalServerError) Code() int {
	return 500
}

func (o *DeleteTemplateInternalServerError) Error() string {
	return fmt.Sprintf("[DELETE /template][%d] deleteTemplateInternalServerError  %+v", 500, o.Payload)
}

func (o *DeleteTemplateInternalServerError) String() string {
	return fmt.Sprintf("[DELETE /template][%d] deleteTemplateInternalServerError  %+v", 500, o.Payload)
}

func (o *DeleteTemplateInternalServerError) GetPayload() string {
	return o.Payload
}

func (o *DeleteTemplateInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}