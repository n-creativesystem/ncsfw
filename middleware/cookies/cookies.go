package cookies

import (
	"net/http"
	"net/url"
	"time"

	"github.com/n-creativesystem/ncsfw/config"
)

type CookieOptions struct {
	Path             string
	Secure           bool
	SameSiteDisabled bool
	SameSiteMode     http.SameSite
}

func NewCookieOptions(conf *config.CookieConfig) CookieOptions {
	path := "/"
	if len(conf.RootURL) > 0 {
		path = conf.RootURL
	}
	return CookieOptions{
		Path:             path,
		Secure:           conf.CookieSecure,
		SameSiteDisabled: conf.CookieSameSiteDisabled,
		SameSiteMode:     conf.CookieSameSiteMode,
	}
}

type getCookieOptionsFunc func(conf *config.CookieConfig) CookieOptions

func DeleteCookie(w http.ResponseWriter, name string, getCookieOptions getCookieOptionsFunc) {
	WriteCookie(w, name, "", -1, getCookieOptions)
}

func WriteCookie(w http.ResponseWriter, name string, value string, maxAge int, getCookieOptions getCookieOptionsFunc) {
	var cfg *config.CookieConfig
	if getCookieOptions == nil {
		getCookieOptions = NewCookieOptions
	}

	options := getCookieOptions(cfg)
	cookie := http.Cookie{
		Name:     name,
		MaxAge:   maxAge,
		Value:    value,
		HttpOnly: true,
		Path:     options.Path,
		Secure:   options.Secure,
	}
	if !options.SameSiteDisabled {
		cookie.SameSite = options.SameSiteMode
	}
	http.SetCookie(w, &cookie)
}

func WriteSessionCookie(w http.ResponseWriter, cookieName, value string, maxLifetime time.Duration) {
	var maxAge int
	if maxLifetime <= 0 {
		maxAge = -1
	} else {
		maxAge = int(maxLifetime.Seconds())
	}
	WriteCookie(w, cookieName, url.QueryEscape(value), maxAge, nil)
}
