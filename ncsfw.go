package ncsfw

import (
	"html/template"
	"net"
	"net/http"
	"strings"
	"sync"

	"github.com/n-creativesystem/ncsfw/binding"
	"github.com/n-creativesystem/ncsfw/logger"
	"github.com/n-creativesystem/ncsfw/render"
)

const (
	MIMEJSON              = binding.MIMEJSON
	MIMEHTML              = binding.MIMEHTML
	MIMEXML               = binding.MIMEXML
	MIMEXML2              = binding.MIMEXML2
	MIMEPlain             = binding.MIMEPlain
	MIMEPOSTForm          = binding.MIMEPOSTForm
	MIMEMultipartPOSTForm = binding.MIMEMultipartPOSTForm
	MIMEYAML              = binding.MIMEYAML
)

type AllocateContextFunc func() Context

type engineConfig struct {
	allocateContextFunc AllocateContextFunc
}

type EnginOption interface {
	apply(cfg *engineConfig)
}

type allocateContextOption struct {
	allocateContextFunc AllocateContextFunc
}

func (a allocateContextOption) apply(cfg *engineConfig) {
	cfg.allocateContextFunc = a.allocateContextFunc
}

func WithAllocateContext(fn AllocateContextFunc) EnginOption {
	return allocateContextOption{fn}
}

var defaultTrustedCIDRs = []*net.IPNet{
	{ // 0.0.0.0/0 (IPv4)
		IP:   net.IP{0x0, 0x0, 0x0, 0x0},
		Mask: net.IPMask{0x0, 0x0, 0x0, 0x0},
	},
	{ // ::/0 (IPv6)
		IP:   net.IP{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
		Mask: net.IPMask{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
	},
}

type Engine struct {
	RouterGroup

	trees       methodTrees
	maxParams   uint16
	maxSections uint16

	noRoute         HandlerFunc
	noMethodHandler HandlerFunc

	delims     render.Delims
	TmplFunMap template.FuncMap
	HTMLRender render.HTMLRender

	pool sync.Pool

	TrustedPlatform     string
	AppEngine           bool
	ForwardedByClientIP bool
	RemoteIPHeaders     []string
	Logger              logger.Logger

	trustedCIDRs []*net.IPNet

	middleware []MiddlewareFunc
}

func New(opts ...EnginOption) *Engine {
	cfg := &engineConfig{}
	for _, opt := range opts {
		opt.apply(cfg)
	}

	e := &Engine{
		RouterGroup: RouterGroup{
			root:       true,
			basePath:   "/",
			middleware: nil,
		},
		Logger:              logger.New("ncs web framework"),
		TrustedPlatform:     "",
		trustedCIDRs:        defaultTrustedCIDRs,
		ForwardedByClientIP: true,
		RemoteIPHeaders:     []string{"X-Forwarded-For", "X-Real-IP"},
	}
	e.RouterGroup.engine = e
	if cfg.allocateContextFunc == nil {
		cfg.allocateContextFunc = e.allocateContext
	}
	e.pool.New = func() interface{} {
		return cfg.allocateContextFunc()
	}
	return e
}

func (e *Engine) allocateContext() Context {
	v := make(Params, 0, e.maxParams)
	c := &context{engine: e, params: &v, log: e.Logger, writer: &responseWriter{log: e.Logger}}
	return c
}

func (e *Engine) Use(middleware ...MiddlewareFunc) IRoutes {
	e.middleware = append(e.middleware, middleware...)
	return e
}

func (e *Engine) addRoute(method, path string, handler HandlerFunc) {
	// assert1(path[0] == '/', "path must begin with '/'")
	// assert1(method != "", "HTTP method can not be empty")
	// assert1(len(handlers) > 0, "there must be at least one handler")

	root := e.trees.get(method)
	if root == nil {
		root = new(node)
		root.fullPath = "/"
		e.trees = append(e.trees, methodTree{method: method, root: root})
	}
	root.addRoute(path, handler)

	if paramsCount := countParams(path); paramsCount > e.maxParams {
		e.maxParams = paramsCount
	}

	if sectionsCount := countSections(path); sectionsCount > e.maxSections {
		e.maxSections = sectionsCount
	}
}

func (e *Engine) Delims(left, right string) *Engine {
	e.delims = render.Delims{Left: left, Right: right}
	return e
}

func (e *Engine) LoadHTMLGlob(pattern string) {
	left := e.delims.Left
	right := e.delims.Right
	templ := template.Must(template.New("").Delims(left, right).Funcs(e.TmplFunMap).ParseGlob(pattern))
	e.SetHTMLTemplate(templ)
}

func (e *Engine) SetHTMLTemplate(templ *template.Template) {
	e.HTMLRender = render.HTMLProduction{Template: templ.Funcs(e.TmplFunMap)}
}

func (e *Engine) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h, c := e.handleHttpRequest(w, r)
	if err := h(c); err != nil {
		e.Logger.ErrorWithContext(r.Context(), err, "")
	}
	e.pool.Put(c)
}

func (e *Engine) NoRoute(handler HandlerFunc, middleware ...MiddlewareFunc) *Engine {
	e.noRoute = applyMiddleware(handler, middleware...)
	return e
}

func (e *Engine) NoMethod(handler HandlerFunc, middleware ...MiddlewareFunc) *Engine {
	e.noMethodHandler = applyMiddleware(handler, middleware...)
	return e
}

func (e *Engine) handleHttpRequest(w http.ResponseWriter, r *http.Request) (HandlerFunc, Context) {
	c := e.pool.Get().(Context)
	httpMethod := r.Method
	rPath := r.URL.Path
	params := make(Params, 0, e.maxParams)
	skippedNodes := make([]skippedNode, 0, e.maxSections)

	h := e.noRoute
	t := e.trees
	for i, tl := 0, len(t); i < tl; i++ {
		if t[i].method != httpMethod {
			continue
		}
		root := t[i].root
		value := root.getValue(rPath, &params, &skippedNodes, false)
		if value.handler != nil {
			c.Reset(w, r, value.fullPath, value.params)
			return applyMiddleware(value.handler, e.middleware...), c
		}
	}

	for _, tree := range e.trees {
		if tree.method == r.Method {
			continue
		}
		if value := tree.root.getValue(rPath, &params, &skippedNodes, false); value.handler != nil {
			c.Reset(w, r, "", value.params)
			h := e.noMethodHandler
			return e.serveError(h, c, http.StatusMethodNotAllowed, http.StatusText(http.StatusMethodNotAllowed))
		}
	}

	c.Reset(w, r, "", nil)
	return e.serveError(h, c, http.StatusNotFound, http.StatusText(http.StatusNotFound))
}

func (e *Engine) serveError(h HandlerFunc, c Context, code int, defaultMessage string) (HandlerFunc, Context) {
	c.Writer().setCode(code)
	handler := applyMiddleware(func(c Context) error {
		var err error
		if h != nil {
			err = h(c)
		}
		if c.Writer().Written() {
			return err
		}
		if c.Writer().Status() == code {
			c.Writer().Header()["Content-Type"] = []string{MIMEPlain}
			_, _ = c.Writer().WriteString(defaultMessage)
			return nil
		}
		c.Writer().WriteHeaderNow()
		return nil
	}, e.middleware...)
	return handler, c
}

func (e *Engine) isTrustedProxy(ip net.IP) bool {
	if e.trustedCIDRs == nil {
		return false
	}
	for _, cidr := range e.trustedCIDRs {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

func (engine *Engine) validateHeader(header string) (clientIP string, valid bool) {
	if header == "" {
		return "", false
	}
	items := strings.Split(header, ",")
	for i := len(items) - 1; i >= 0; i-- {
		ipStr := strings.TrimSpace(items[i])
		ip := net.ParseIP(ipStr)
		if ip == nil {
			break
		}

		// X-Forwarded-For is appended by proxy
		// Check IPs in reverse order and stop when find untrusted proxy
		if (i == 0) || (!engine.isTrustedProxy(ip)) {
			return ipStr, true
		}
	}
	return "", false
}
