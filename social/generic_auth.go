package social

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/mail"
	"regexp"

	"golang.org/x/oauth2"
)

type SocialGenericOAuth struct {
	*SocialBase
	apiUrl               string
	emailAttributeName   string
	emailAttributePath   string
	loginAttributePath   string
	nameAttributePath    string
	idTokenAttributeName string
}

func (s *SocialGenericOAuth) Type() int {
	return 0
}

func (s *SocialGenericOAuth) UserInfo(client *http.Client, token *oauth2.Token) (*BasicUserInfo, error) {
	s.log.Debug("Getting user info")
	tokenData := s.extractFromToken(token)
	apiData := s.extractFromAPI(client)

	userInfo := &BasicUserInfo{}
	for _, data := range []*UserInfoJson{tokenData, apiData} {
		if data == nil {
			continue
		}

		s.log.Debug("Processing external user info", "source", data.source, "data", data)

		if userInfo.Id == "" {
			userInfo.Id = s.extractId(data)
		}

		if userInfo.Name == "" {
			userInfo.Name = s.extractUserName(data)
		}

		if userInfo.Login == "" {
			if data.Login != "" {
				s.log.Debug("Setting user info login from login field", "login", data.Login)
				userInfo.Login = data.Login
			} else {
				if s.loginAttributePath != "" {
					s.log.Debug("Searching for login among JSON", "loginAttributePath", s.loginAttributePath)
					login, err := s.searchJSONForStringAttr(s.loginAttributePath, data.rawJSON)
					if err != nil {
						s.log.Error(err, "Failed to search JSON for login attribute")
					} else if login != "" {
						userInfo.Login = login
						s.log.Debug("Setting user info login from login field", "login", login)
					}
				}

				if userInfo.Login == "" && data.Username != "" {
					s.log.Debug("Setting user info login from username field", "username", data.Username)
					userInfo.Login = data.Username
				}
			}
		}

		if userInfo.Email == "" {
			userInfo.Email = s.extractEmail(data)
			if userInfo.Email != "" {
				s.log.Debug("Set user info email from extracted email", "email", userInfo.Email)
			}
		}
	}

	if userInfo.Login == "" {
		s.log.Debug("Defaulting to using email for user info login", "email", userInfo.Email)
		userInfo.Login = userInfo.Email
	}

	s.log.Debug("User info result", "result", userInfo)
	return userInfo, nil
}

type UserInfoJson struct {
	Name        string              `json:"name"`
	DisplayName string              `json:"display_name"`
	Login       string              `json:"login"`
	Username    string              `json:"username"`
	Email       string              `json:"email"`
	Upn         string              `json:"upn"`
	Attributes  map[string][]string `json:"attributes"`
	rawJSON     []byte
	source      string
}

func (info *UserInfoJson) String() string {
	return fmt.Sprintf(
		"Name: %s, Displayname: %s, Login: %s, Username: %s, Email: %s, Upn: %s, Attributes: %v",
		info.Name, info.DisplayName, info.Login, info.Username, info.Email, info.Upn, info.Attributes)
}

func (s *SocialGenericOAuth) extractFromToken(token *oauth2.Token) *UserInfoJson {
	s.log.Debug("Extracting user info from OAuth token")

	idTokenAttribute := "id_token"
	if s.idTokenAttributeName != "" {
		idTokenAttribute = s.idTokenAttributeName
		s.log.Debug("Using custom id_token attribute name", "attribute_name", idTokenAttribute)
	}

	idToken := token.Extra(idTokenAttribute)
	if idToken == nil {
		s.log.Debug("No id_token found", "token", token)
		return nil
	}

	jwtRegexp := regexp.MustCompile("^([-_a-zA-Z0-9=]+)[.]([-_a-zA-Z0-9=]+)[.]([-_a-zA-Z0-9=]+)$")
	matched := jwtRegexp.FindStringSubmatch(idToken.(string))
	if matched == nil {
		s.log.Debug("id_token is not in JWT format", "id_token", idToken.(string))
		return nil
	}

	rawJSON, err := base64.RawURLEncoding.DecodeString(matched[2])
	if err != nil {
		s.log.Error(err, "Error base64 decoding id_token", "raw_payload", matched[2])
		return nil
	}

	headerBytes, err := base64.RawURLEncoding.DecodeString(matched[1])
	if err != nil {
		s.log.Error(err, "Error base64 decoding header", "header", matched[1])
		return nil
	}

	var header map[string]string
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		s.log.Error(err, "Error deserializing header")
		return nil
	}

	if compression, ok := header["zip"]; ok {
		if compression != "DEF" {
			s.log.Warning("Unknown compression algorithm", "algorithm", compression)
			return nil
		}

		fr, err := zlib.NewReader(bytes.NewReader(rawJSON))
		if err != nil {
			s.log.Error(err, "Error creating zlib reader")
			return nil
		}
		defer func() {
			if err := fr.Close(); err != nil {
				s.log.Warning("Failed closing zlib reader", "error", err)
			}
		}()
		rawJSON, err = io.ReadAll(fr)
		if err != nil {
			s.log.Error(err, "Error decompressing payload")
			return nil
		}
	}

	var data UserInfoJson
	if err := json.Unmarshal(rawJSON, &data); err != nil {
		s.log.Error(err, "Error decoding id_token JSON", "raw_json", string(data.rawJSON))
		return nil
	}

	data.rawJSON = rawJSON
	data.source = "token"
	s.log.Debug("Received id_token", "raw_json", string(data.rawJSON), "data", data.String())
	return &data
}

func (s *SocialGenericOAuth) extractFromAPI(client *http.Client) *UserInfoJson {
	s.log.Debug("Getting user info from API")
	rawUserInfoResponse, err := s.httpGet(client, s.apiUrl)
	if err != nil {
		s.log.Debug("Error getting user info from API", "url", s.apiUrl, "error", err)
		return nil
	}

	rawJSON := rawUserInfoResponse.Body

	var data UserInfoJson
	if err := json.Unmarshal(rawJSON, &data); err != nil {
		s.log.Error(err, "Error decoding user info response", "raw_json", rawJSON)
		return nil
	}

	data.rawJSON = rawJSON
	data.source = "API"
	s.log.Debug("Received user info response from API", "raw_json", string(rawJSON), "data", data.String())
	return &data
}

func (s *SocialGenericOAuth) extractId(data *UserInfoJson) string {
	id, err := s.searchJSONForStringAttr("sub", data.rawJSON)
	if err == nil {
		return id
	}
	return ""
}

func (s *SocialGenericOAuth) extractEmail(data *UserInfoJson) string {
	if data.Email != "" {
		return data.Email
	}

	if s.emailAttributePath != "" {
		email, err := s.searchJSONForStringAttr(s.emailAttributePath, data.rawJSON)
		if err != nil {
			s.log.Error(err, "Failed to search JSON for attribute")
		} else if email != "" {
			return email
		}
	}

	emails, ok := data.Attributes[s.emailAttributeName]
	if ok && len(emails) != 0 {
		return emails[0]
	}

	if data.Upn != "" {
		emailAddr, emailErr := mail.ParseAddress(data.Upn)
		if emailErr == nil {
			return emailAddr.Address
		}
		s.log.Debug("Failed to parse e-mail address", "error", emailErr.Error())
	}

	return ""
}

func (s *SocialGenericOAuth) extractUserName(data *UserInfoJson) string {
	if s.nameAttributePath != "" {
		name, err := s.searchJSONForStringAttr(s.nameAttributePath, data.rawJSON)
		if err != nil {
			s.log.Error(err, "Failed to search JSON for attribute")
		} else if name != "" {
			s.log.Debug("Setting user info name from nameAttributePath", "nameAttributePath", s.nameAttributePath)
			return name
		}
	}

	if data.Name != "" {
		s.log.Debug("Setting user info name from name field")
		return data.Name
	}

	if data.DisplayName != "" {
		s.log.Debug("Setting user info name from display name field")
		return data.DisplayName
	}

	s.log.Debug("Unable to find user info name")
	return ""
}
