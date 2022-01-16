package ncsfw

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNCSFramework(t *testing.T) {
	r := New()
	r.Any("/any", func(c Context) error {
		_, _ = c.Writer().WriteString(c.Request().Method)
		return nil
	})
	r.Get("/aa", func(c Context) error {
		_, _ = c.Writer().WriteString("get")
		return nil
	})
	r.Any("/middleware", func(c Context) error {
		_, _ = c.Writer().WriteString(fmt.Sprintf("%s - %s", c.GetTenant(), c.Request().Method))
		return nil
	}, func(next HandlerFunc) HandlerFunc {
		return func(c Context) error {
			c.SetTenant("test")
			return next(c)
		}
	})

	type jsonBody struct {
		Data string `json:"data"`
	}
	r.Post("/json", func(c Context) error {
		var body jsonBody
		err := c.BindJSON(&body)
		if err != nil {
			return err
		}
		c.JSON(http.StatusOK, &body)
		return nil
	})

	t.Run("any", func(t *testing.T) {
		for _, method := range anyMethods {
			t.Run(method, func(t *testing.T) {
				buf := bytes.Buffer{}
				record := httptest.NewRecorder()
				req := httptest.NewRequest(method, "/any", nil)
				r.ServeHTTP(record, req)
				_, _ = io.Copy(&buf, record.Result().Body)
				assert.Equal(t, method, buf.String())
			})
		}
	})

	t.Run("middleware", func(t *testing.T) {
		for _, method := range anyMethods {
			t.Run(method, func(t *testing.T) {
				buf := bytes.Buffer{}
				record := httptest.NewRecorder()
				req := httptest.NewRequest(method, "/middleware", nil)
				r.ServeHTTP(record, req)
				_, _ = io.Copy(&buf, record.Result().Body)
				assert.Equal(t, fmt.Sprintf("%s - %s", "test", method), buf.String())
			})
		}
	})

	t.Run("send json body", func(t *testing.T) {
		body := jsonBody{
			Data: "test",
		}
		buf, err := json.Marshal(&body)
		assert.NoError(t, err)
		buffer := bytes.Buffer{}
		record := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/json", bytes.NewBuffer(buf))
		r.ServeHTTP(record, req)
		_, _ = io.Copy(&buffer, record.Result().Body)
		assert.Equal(t, string(buf), buffer.String())
	})

	t.Run("method not allowed", func(t *testing.T) {
		buf := bytes.Buffer{}
		record := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/aa", nil)
		r.ServeHTTP(record, req)
		_, _ = io.Copy(&buf, record.Result().Body)
		assert.Equal(t, http.StatusText(http.StatusMethodNotAllowed), buf.String())
	})

	t.Run("not found", func(t *testing.T) {
		buf := bytes.Buffer{}
		record := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/bb", nil)
		r.ServeHTTP(record, req)
		_, _ = io.Copy(&buf, record.Result().Body)
		assert.Equal(t, http.StatusText(http.StatusNotFound), buf.String())
	})
}
