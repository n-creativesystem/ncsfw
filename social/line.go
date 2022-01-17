package social

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/n-creativesystem/ncsfw/models"
	"golang.org/x/oauth2"
)

type SocialLine struct {
	*SocialBase
	apiUrl string
}

func (s *SocialLine) Type() int {
	return int(models.LINE)
}

func (s *SocialLine) UserInfo(client *http.Client, token *oauth2.Token) (*BasicUserInfo, error) {
	var data struct {
		Id         string `json:"userId"`
		Name       string `json:"displayName"`
		Email      string `json:"email"`
		PictureUrl string `json:"pictureUrl"`
	}

	response, err := s.httpGet(client, s.apiUrl)
	if err != nil {
		return nil, fmt.Errorf("Error getting user info: %s", err)
	}

	err = json.Unmarshal(response.Body, &data)
	if err != nil {
		return nil, fmt.Errorf("Error getting user info: %s", err)
	}
	var login string
	switch {
	case data.Email != "":
		login = data.Email
	default:
		login = data.Id
	}
	return &BasicUserInfo{
		Id:         data.Id,
		Name:       data.Name,
		Email:      data.Email,
		Login:      login,
		PictureUrl: data.PictureUrl,
	}, nil
}
