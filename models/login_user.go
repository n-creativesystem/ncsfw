package models

import (
	"bytes"
	"encoding/json"

	"github.com/n-creativesystem/ncsfw/utils"
	"golang.org/x/oauth2"
)

type LoginUser interface {
	Serialize() string
	Deserialize(token string) error
}

type loginUserImpl struct {
	Id           string
	Name         string
	Email        string
	ProviderName string
	Token        *oauth2.Token
}

func NewLoginUser(id, name, email, providerName string, token *oauth2.Token) LoginUser {
	return &loginUserImpl{
		Id:           id,
		Name:         name,
		Email:        email,
		ProviderName: providerName,
		Token:        token,
	}
}

func (user *loginUserImpl) Serialize() string {
	buf, _ := json.Marshal(user)
	return utils.BytesToString(buf)
}

func (user *loginUserImpl) Deserialize(token string) error {
	return json.NewDecoder(bytes.NewBufferString(token)).Decode(&user)
}
