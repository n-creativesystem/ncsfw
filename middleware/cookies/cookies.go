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

func NewCookieOptions(conf *config.Config) CookieOptions {
	path := "/"
	rootURL := conf.Setting.GetRootURL().String()
	if len(rootURL) > 0 {
		path = rootURL
	}
	return CookieOptions{
		Path:             path,
		Secure:           conf.Cookie.Secure,
		SameSiteDisabled: conf.Cookie.SameSiteDisabled,
		SameSiteMode:     conf.Cookie.SameSiteMode,
	}
}

type getCookieOptionsFunc func(conf *config.Config) CookieOptions

func DeleteCookie(w http.ResponseWriter, name string, getCookieOptions getCookieOptionsFunc) {
	WriteCookie(w, name, "", -1, getCookieOptions)
}

func WriteCookie(w http.ResponseWriter, name string, value string, maxAge int, getCookieOptions getCookieOptionsFunc) {
	var cfg *config.Config
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
