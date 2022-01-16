package render

import (
	"html/template"
	"net/http"
)

type HTMLRender interface {
	// Instance returns an HTML instance.
	Instance(string, interface{}) Render
}

type HTMLProduction struct {
	Template *template.Template
	Delims   Delims
}

type Delims struct {
	// Left delimiter, defaults to {{.
	Left string
	// Right delimiter, defaults to }}.
	Right string
}

type HTML struct {
	Template *template.Template
	Name     string
	Data     interface{}
}

var htmlContentType = []string{"text/html; charset=utf-8"}

func (r HTMLProduction) Instance(name string, data interface{}) Render {
	return HTML{
		Template: r.Template,
		Name:     name,
		Data:     data,
	}
}

// Render (HTML) executes template and writes its result with custom ContentType for response.
func (r HTML) Render(w http.ResponseWriter) error {
	r.WriteContentType(w)

	if r.Name == "" {
		return r.Template.Execute(w, r.Data)
	}
	return r.Template.ExecuteTemplate(w, r.Name, r.Data)
}

// WriteContentType (HTML) writes HTML ContentType.
func (r HTML) WriteContentType(w http.ResponseWriter) {
	writeContentType(w, htmlContentType)
}
