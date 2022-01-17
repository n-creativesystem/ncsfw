package social

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/n-creativesystem/ncsfw/models"
	"golang.org/x/oauth2"
)

type SocialAuth0 struct {
	*SocialBase
	apiUrl string
}

var (
	_ SocialConnector = (*SocialAuth0)(nil)
)

func (s *SocialAuth0) Type() int {
	return int(models.Auth0)
}

func (s *SocialAuth0) UserInfo(client *http.Client, token *oauth2.Token) (*BasicUserInfo, error) {
	var data struct {
		Id         string `json:"sub"`
		Name       string `json:"name"`
		Email      string `json:"email"`
		PictureUrl string `json:"picture"`
	}

	response, err := s.httpGet(client, s.apiUrl)
	if err != nil {
		return nil, fmt.Errorf("Error getting user info: %s", err)
	}

	err = json.Unmarshal(response.Body, &data)
	if err != nil {
		return nil, fmt.Errorf("Error getting user info: %s", err)
	}

	return &BasicUserInfo{
		Id:         data.Id,
		Name:       data.Name,
		Email:      data.Email,
		Login:      data.Email,
		PictureUrl: data.PictureUrl,
	}, nil
}
