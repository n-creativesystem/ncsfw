package ncsfw

import (
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/n-creativesystem/ncsfw/binding"
	"github.com/n-creativesystem/ncsfw/logger"
	"github.com/n-creativesystem/ncsfw/models"
	"github.com/n-creativesystem/ncsfw/render"
)

var (
	ErrRedirect = errors.New("redirect")
	ErrIgnore   = errors.New("ignore")
	currentKey  = "contexts.rest"
)

type context struct {
	engine     *Engine
	writer     *responseWriter
	request    *http.Request
	tenant     models.Tenant
	loginUser  models.LoginUser
	isSignedIn bool
	log        logger.Logger
	fullPath   string
	params     *Params
	queryCache url.Values
}

var _ Context = (*context)(nil)

func (c *context) Reset(w http.ResponseWriter, r *http.Request, fullPath string, params *Params) {
	c.writer.reset(w)
	// c.writer = &responseWriter{ResponseWriter: w, log: c.log.WithSubModule("response writer")}
	c.request = r
	c.fullPath = fullPath
	*c.params = (*c.params)[:0]
	if params != nil {
		*c.params = *params
	}
	c.queryCache = nil
}

func (c *context) Value(key interface{}) interface{} {
	return c.request.Context().Value(key)
}

func (c *context) Request() *http.Request {
	return c.request
}

func (c *context) Writer() ResponseWriter {
	return c.writer
}

func (c *context) SetRequest(r *http.Request) {
	*c.request = *r
}

func (c *context) FullPath() string {
	return c.fullPath
}

func (c *context) Logger() logger.Logger {
	return c.log
}

func (c *context) File(filePath string) {
	http.ServeFile(c.writer, c.request, filePath)
}

func (c *context) Param(param string) string {
	return c.params.ByName(param)
}

func (c *context) Params() *Params {
	return c.params
}

func (c *context) SetParams(params *Params) {
	c.params = params
}

func (c *context) GetLoginUser() models.LoginUser {
	return c.loginUser
}

func (c *context) SetLoginUser(user models.LoginUser) {
	c.loginUser = user
}

func (c *context) GetTenant() models.Tenant {
	return c.tenant
}

func (c *context) SetTenant(tenant models.Tenant) {
	c.tenant = tenant
}

func (c *context) IsSignedIn() bool {
	return c.isSignedIn
}

func (c *context) SignedIn(isSigned bool) {
	c.isSignedIn = isSigned
}

func (c *context) BindJSON(obj interface{}) error {
	return c.MustBindWith(obj, binding.JSON)
}

func (c *context) MustBindWith(obj interface{}, b binding.Binding) error {
	if err := c.ShouldBindWith(obj, b); err != nil {
		return err
	}
	return nil
}

func (c *context) Render(code int, r render.Render) {
	c.Status(code)

	if !bodyAllowedForStatus(code) {
		r.WriteContentType(c.writer)
		c.writer.WriteHeaderNow()
		return
	}
	if err := r.Render(c.writer); err != nil {
		panic(err)
	}
}

func (c *context) Status(code int) {
	c.writer.WriteHeader(code)
}

func (c *context) HTML(code int, name string, obj interface{}) {
	instance := c.engine.HTMLRender.Instance(name, obj)
	c.Render(code, instance)
}

func (c *context) JSON(code int, obj interface{}) {
	c.Render(code, render.JSON{Data: obj})
}

func (c *context) Redirect(code int, url string) {
	c.Render(-1, render.Redirect{Code: code, Request: c.request, Location: url})
}

func (c *context) requestHeader(key string) string {
	return c.request.Header.Get(key)
}

func (c *context) contentType() string {
	return filterFlags(c.requestHeader("Content-Type"))
}

func (c *context) ShouldBind(obj interface{}) error {
	b := binding.Default(c.request.Method, c.contentType())
	return c.ShouldBindWith(obj, b)
}

func (c *context) RemoteIP() string {
	ip, _, err := net.SplitHostPort(strings.TrimSpace(c.request.RemoteAddr))
	if err != nil {
		return ""
	}
	return ip
}

func (c *context) ShouldBindWith(obj interface{}, b binding.Binding) error {
	return b.Bind(c.request, obj)
}

func bodyAllowedForStatus(status int) bool {
	switch {
	case status >= 100 && status <= 199:
		return false
	case status == http.StatusNoContent:
		return false
	case status == http.StatusNotModified:
		return false
	}
	return true
}

func filterFlags(content string) string {
	for i, char := range content {
		if char == ' ' || char == ';' {
			return content[:i]
		}
	}
	return content
}

func (c *context) Query(key string) (value string) {
	value, _ = c.GetQuery(key)
	return
}

func (c *context) GetQuery(key string) (string, bool) {
	if values, ok := c.GetQueryArray(key); ok {
		return values[0], ok
	}
	return "", false
}

func (c *context) initQueryCache() {
	if c.queryCache == nil {
		if c.request != nil {
			c.queryCache = c.request.URL.Query()
		} else {
			c.queryCache = url.Values{}
		}
	}
}

func (c *context) GetQueryArray(key string) (values []string, ok bool) {
	c.initQueryCache()
	values, ok = c.queryCache[key]
	return
}

func (c *context) GetHeader(key string) string {
	return c.requestHeader(key)
}

func (c *context) ClientIP() string {
	// if c.engine.TrustedPlatform != "" {
	// 	if addr := c.requestHeader(c.engine.TrustedPlatform); addr != "" {
	// 		return addr
	// 	}
	// }

	// // Legacy "AppEngine" flag
	// if c.engine.AppEngine {
	// 	if addr := c.requestHeader("X-Appengine-Remote-Addr"); addr != "" {
	// 		return addr
	// 	}
	// }

	// It also checks if the remoteIP is a trusted proxy or not.
	// In order to perform this validation, it will see if the IP is contained within at least one of the CIDR blocks
	// defined by Engine.SetTrustedProxies()
	remoteIP := net.ParseIP(c.RemoteIP())
	if remoteIP == nil {
		return ""
	}
	trusted := c.engine.isTrustedProxy(remoteIP)

	if trusted && c.engine.ForwardedByClientIP && c.engine.RemoteIPHeaders != nil {
		for _, headerName := range c.engine.RemoteIPHeaders {
			ip, valid := c.engine.validateHeader(c.requestHeader(headerName))
			if valid {
				return ip
			}
		}
	}
	return remoteIP.String()
}
