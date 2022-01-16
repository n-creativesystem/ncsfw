package render

import (
	"fmt"
	"net/http"

	"github.com/n-creativesystem/ncsfw/logger"
)

type Redirect struct {
	Code     int
	Request  *http.Request
	Location string
}

func (r Redirect) Render(w http.ResponseWriter) error {
	if (r.Code < http.StatusMultipleChoices || r.Code > http.StatusPermanentRedirect) && r.Code != http.StatusCreated {
		logger.Panic(fmt.Errorf(""), "render redirect")
	}

	http.Redirect(w, r.Request, r.Location, r.Code)
	return nil
}

func (r Redirect) WriteContentType(w http.ResponseWriter) {}
