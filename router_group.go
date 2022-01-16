package ncsfw

import (
	"net/http"
	"path"
	"strings"
)

var (
	anyMethods = []string{
		http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch,
		http.MethodHead, http.MethodOptions, http.MethodDelete, http.MethodConnect,
		http.MethodTrace,
	}
)

type IRoutes interface {
	Use(middleware ...MiddlewareFunc) IRoutes
	Handle(method, path string, handler HandlerFunc, middleware ...MiddlewareFunc) IRoutes
	Get(path string, handler HandlerFunc, middleware ...MiddlewareFunc) IRoutes
	Post(path string, handler HandlerFunc, middleware ...MiddlewareFunc) IRoutes
	Put(path string, handler HandlerFunc, middleware ...MiddlewareFunc) IRoutes
	Delete(path string, handler HandlerFunc, middleware ...MiddlewareFunc) IRoutes
	Patch(path string, handler HandlerFunc, middleware ...MiddlewareFunc) IRoutes
	Options(path string, handler HandlerFunc, middleware ...MiddlewareFunc) IRoutes
	Head(path string, handler HandlerFunc, middleware ...MiddlewareFunc) IRoutes
	Any(path string, handler HandlerFunc, middleware ...MiddlewareFunc) IRoutes
	StaticFile(path, filepath string, middleware ...MiddlewareFunc) IRoutes
	Static(path, root string, middleware ...MiddlewareFunc) IRoutes
	StaticFS(path string, fs http.FileSystem, middleware ...MiddlewareFunc) IRoutes
	Group(prefix string, middleware ...MiddlewareFunc) IRoutes
}

type RouterGroup struct {
	middleware []MiddlewareFunc
	basePath   string
	root       bool

	engine *Engine
}

// Use ルーターレベルでのミドルウェアの追加
func (r *RouterGroup) Use(middleware ...MiddlewareFunc) IRoutes {
	r.middleware = append(r.middleware, middleware...)

	return r.returnObj()
}

// handle handlerの登録
func (r *RouterGroup) handle(method, path string, handler HandlerFunc, middleware ...MiddlewareFunc) IRoutes {
	m := make([]MiddlewareFunc, 0, len(r.middleware)+len(middleware))
	m = append(m, r.middleware...)
	m = append(m, middleware...)
	handler = applyMiddleware(handler, m...)
	absolutePath := r.calculateAbsolutePath(path)
	r.engine.addRoute(method, absolutePath, handler)
	return r.returnObj()
}

// Handle handlerの登録
func (r *RouterGroup) Handle(method, path string, handler HandlerFunc, middleware ...MiddlewareFunc) IRoutes {
	return r.handle(method, path, handler, middleware...)
}

// Get GET
func (r *RouterGroup) Get(path string, handler HandlerFunc, middleware ...MiddlewareFunc) IRoutes {
	return r.handle(http.MethodGet, path, handler, middleware...)
}

// Post POST
func (r *RouterGroup) Post(path string, handler HandlerFunc, middleware ...MiddlewareFunc) IRoutes {
	return r.handle(http.MethodPost, path, handler, middleware...)
}

// Put PUT
func (r *RouterGroup) Put(path string, handler HandlerFunc, middleware ...MiddlewareFunc) IRoutes {
	return r.handle(http.MethodPut, path, handler, middleware...)
}

// Delete DELETE
func (r *RouterGroup) Delete(path string, handler HandlerFunc, middleware ...MiddlewareFunc) IRoutes {
	return r.handle(http.MethodDelete, path, handler, middleware...)
}

// Patch PATCH
func (r *RouterGroup) Patch(path string, handler HandlerFunc, middleware ...MiddlewareFunc) IRoutes {
	return r.handle(http.MethodPatch, path, handler, middleware...)
}

// Options OPTIONS
func (r *RouterGroup) Options(path string, handler HandlerFunc, middleware ...MiddlewareFunc) IRoutes {
	return r.handle(http.MethodOptions, path, handler, middleware...)
}

// Head HEAD
func (r *RouterGroup) Head(path string, handler HandlerFunc, middleware ...MiddlewareFunc) IRoutes {
	return r.handle(http.MethodHead, path, handler, middleware...)
}

// Any anyMethodsに登録されているメソッドを登録
func (r *RouterGroup) Any(path string, handler HandlerFunc, middleware ...MiddlewareFunc) IRoutes {
	for _, method := range anyMethods {
		r.handle(method, path, handler, middleware...)
	}
	return r.returnObj()
}

// StaticFile 単一ファイルを配信するhandlerを登録
func (r *RouterGroup) StaticFile(path, filepath string, middleware ...MiddlewareFunc) IRoutes {
	if strings.Contains(path, ":") || strings.Contains(path, "*") {
		panic("URL parameters can not be used when serving a static file")
	}
	handler := func(c Context) error {
		c.File(filepath)
		return nil
	}
	r.Get(path, handler, middleware...)
	r.Head(path, handler, middleware...)
	return r.returnObj()
}

// Static 静的ファイルがあるディレクトリをhandlerに登録
func (r *RouterGroup) Static(path, root string, middleware ...MiddlewareFunc) IRoutes {
	return r.StaticFS(path, Dir(root, false), middleware...)
}

// StaticFS 静的ファイルを配信するhandlerを登録
func (r *RouterGroup) StaticFS(relativePath string, fs http.FileSystem, middleware ...MiddlewareFunc) IRoutes {
	if strings.Contains(relativePath, ":") || strings.Contains(relativePath, "*") {
		panic("URL parameters can not be used when serving a static folder")
	}
	handler := r.createStaticHandler(relativePath, fs)
	urlPattern := path.Join(relativePath, "/*filepath")

	// Register GET and HEAD handlers
	r.Get(urlPattern, handler, middleware...)
	r.Head(urlPattern, handler, middleware...)
	return r.returnObj()
}

// createStaticHandler 静的ファイルを返却するhandlerの作成
func (r *RouterGroup) createStaticHandler(relativePath string, fs http.FileSystem) HandlerFunc {
	absolutePath := r.calculateAbsolutePath(relativePath)
	fileServer := http.StripPrefix(absolutePath, http.FileServer(fs))

	return func(c Context) error {
		if _, noListing := fs.(*onlyFilesFS); noListing {
			c.Writer().WriteHeader(http.StatusNotFound)
		}

		file := c.Param("filepath")
		// Check if file exists and/or if we have permission to access it
		f, err := fs.Open(file)
		if err != nil {
			c.Writer().WriteHeader(http.StatusNotFound)
			return r.engine.noRoute(c)
		}
		f.Close()

		fileServer.ServeHTTP(c.Writer(), c.Request())

		return nil
	}
}

func (r *RouterGroup) returnObj() IRoutes {
	if r.root {
		return r.engine
	}
	return r
}

// calculateAbsolutePath 絶対パスの計算
func (r *RouterGroup) calculateAbsolutePath(relativePath string) string {
	return joinPaths(r.basePath, relativePath)
}

// Group ルーターグループ
func (r *RouterGroup) Group(prefix string, middleware ...MiddlewareFunc) IRoutes {
	m := make([]MiddlewareFunc, 0, len(r.middleware)+len(middleware))
	m = append(m, r.middleware...)
	m = append(m, middleware...)
	return &RouterGroup{
		middleware: m,
		basePath:   r.calculateAbsolutePath(prefix),
		engine:     r.engine,
	}
}

// applyMiddleware handlerにミドルウェアをラップして一つのhandlerへ変換する
func applyMiddleware(h HandlerFunc, middleware ...MiddlewareFunc) HandlerFunc {
	for i := len(middleware) - 1; i >= 0; i-- {
		h = middleware[i](h)
	}
	return h
}

// AddMethods anyMethodsに無いメソッドを追加する場合に使用
func AddMethods(method string) {
	for _, m := range anyMethods {
		if strings.EqualFold(m, method) {
			return
		}
	}
	anyMethods = append(anyMethods, method)
}
