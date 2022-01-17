package storage

import (
	"io"

	"github.com/gorilla/sessions"
	"github.com/n-creativesystem/ncsfw/config"
)

type FactorySet struct {
	Factory  Factory
	Settings *Setting
}

type Setting struct {
	*config.Section
}

type KeyPairs []byte

type Factory interface {
	Initialize(settings *Setting) error
	SessionStore(keyPairs ...KeyPairs) sessions.Store
	io.Closer
}

func Initialize(set *FactorySet) (Factory, error) {
	factory := set.Factory
	settings := set.Settings
	if err := factory.Initialize(settings); err != nil {
		return nil, err
	}
	return factory, nil
}

func NewKeyPairs(conf *config.Config) []KeyPairs {
	pairs := []KeyPairs{}
	for _, keyPair := range conf.Cookie.KeyPairs {
		pairs = append(pairs, []byte(keyPair))
	}
	return pairs
}

func NewSessionStore(set *FactorySet, keyPairs []KeyPairs) sessions.Store {
	return set.Factory.SessionStore(keyPairs...)
}
