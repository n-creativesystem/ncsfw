package config

import "net/http"

type CookieConfig struct {
	RootURL                string
	CookieSecure           bool
	CookieSameSiteDisabled bool
	CookieSameSiteMode     http.SameSite
}
