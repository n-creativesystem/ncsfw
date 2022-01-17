package handler

import "errors"

var (
	ErrEmailNotAllowed       = errors.New("required email domain not fulfilled")
	ErrInvalidCredentials    = errors.New("invalid username or password")
	ErrNoEmail               = errors.New("login provider didn't return an email address")
	ErrProviderDeniedRequest = errors.New("login provider denied login request")
	ErrTooManyLoginAttempts  = errors.New("too many consecutive incorrect login attempts for user - login for user temporarily blocked")
	ErrPasswordEmpty         = errors.New("no password provided")
	ErrUserDisabled          = errors.New("user is disabled")
	ErrAbsoluteRedirectTo    = errors.New("absolute URLs are not allowed for redirect_to cookie value")
	ErrInvalidRedirectTo     = errors.New("invalid redirect_to cookie value")
	ErrForbiddenRedirectTo   = errors.New("forbidden redirect_to cookie value")
)
