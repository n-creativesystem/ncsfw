// Copyright 2018 Gin Core Team.  All rights reserved.
// Use of this source code is governed by a MIT style
// at https://github.com/gin-gonic/gin/blob/master/LICENSE

package binding

type uriBinding struct{}

func (uriBinding) Name() string {
	return "uri"
}

func (uriBinding) BindUri(m map[string][]string, obj interface{}) error {
	if err := mapURI(obj, m); err != nil {
		return err
	}
	return validate(obj)
}
