package response

import (
	"fmt"
	"net/http"
	"strings"
)

// type Error struct {
// 	HttpStatus    int
// 	PublicMessage string
// }

// func (e Error) Error() string {
// 	return e.PublicMessage
// }

type ErrorResponse struct {
	Status      int    `json:"status,omitempty"`
	Err         string `json:"error"`
	Description string `json:"error_description"`
}

func (e ErrorResponse) IsError() bool {
	return e.Err != ""
}

func (e ErrorResponse) Error() string {
	buf := strings.Builder{}
	buf.WriteString(fmt.Sprintf("error: %s", e.Err))
	if e.Description != "" {
		buf.WriteString(",")
		buf.WriteString(fmt.Sprintf("description: %s", e.Description))
	}
	return buf.String()
}

func ErrJson(message string, err error) ErrorResponse {
	return ErrJsonWithStatus(http.StatusBadRequest, message, err)
}

func ErrJsonWithStatus(status int, message string, err error) ErrorResponse {
	if message == "" {
		message = http.StatusText(status)
	}
	res := ErrorResponse{
		Status: status,
		Err:    message,
	}
	if err != nil {
		res.Description = err.Error()
	}
	return res
}
