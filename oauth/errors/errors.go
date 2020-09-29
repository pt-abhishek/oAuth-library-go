package errors

import "net/http"

//RestErr struct
type RestErr struct {
	Message string `json:"message"`
	Code    int    `json:"code"`
	Error   string `json:"error"`
}

//NewBadRequestError returns a 400
func NewBadRequestError(message string) *RestErr {
	return &RestErr{
		Code:    http.StatusBadRequest,
		Message: message,
		Error:   "bad_request",
	}
}

//NewResourceNotFoundError returns a 404
func NewResourceNotFoundError(message string) *RestErr {
	return &RestErr{
		Code:    http.StatusNotFound,
		Message: message,
		Error:   "resource_not_found",
	}
}

//NewInternalServerError returns 500
func NewInternalServerError(message string) *RestErr {
	return &RestErr{
		Code:    http.StatusInternalServerError,
		Message: message,
		Error:   "internal_server_error",
	}
}

//NewUnauthorizedError returns a 403
func NewUnauthorizedError(message string) *RestErr {
	return &RestErr{
		Code:    http.StatusUnauthorized,
		Message: message,
		Error:   "unauthorized",
	}
}
