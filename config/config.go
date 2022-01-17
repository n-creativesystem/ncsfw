package config

import (
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"

	"github.com/spf13/viper"
)

var (
	configFile  = os.Getenv("NCS_FW_CONFIG")
	configViper *viper.Viper
)

type Setting struct {
	// RootURL アプリケーションの完全URL
	RootURL string `mapstructure:"root_url"`
	rootURL *url.URL
}

func (setting Setting) GetRootURL() *url.URL {
	return setting.rootURL
}

type Cookie struct {
	// SecretKey Cookieシークレットキー
	SecretKey string `mapstructure:"secret_key"`
	// Secure セキュアクッキー
	Secure bool `mapstructure:"secure"`
	// SameSiteDisabled
	SameSiteDisabled bool          `mapstructure:"same_site_disabled"`
	SameSiteMode     http.SameSite `mapstructure:"same_site_mode"`
	KeyPairs         []string      `mapstructure:"key_pairs"`
}

type Config struct {
	Setting Setting `mapstructure:"setting"`
	Cookie  Cookie  `mapstructure:"cookie"`

	// OAuthRaw oauth setting
	OAuthRaw *Section `mapstructure:"-"`
}

func NewConfig() *Config {
	const envPrefix = "NCS_FW"
	configViper = viper.GetViper()
	if configFile != "" {
		configViper.SetConfigFile(configFile)
	} else {
		home, _ := os.UserHomeDir()
		configViper.AddConfigPath(".")
		configViper.AddConfigPath(path.Join("/etc", "ncsfw"))
		configViper.AddConfigPath(path.Join(home, ".ncsfw"))
		configViper.SetConfigName("config")
	}
	configViper.SetEnvPrefix(envPrefix)
	configViper.AutomaticEnv()
	configViper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	if err := configViper.ReadInConfig(); err != nil {
		switch err.(type) {
		case viper.ConfigFileNotFoundError:
			// config file does not found in search path
		default:
			_, _ = fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
	var cfg Config
	if err := configViper.Unmarshal(&cfg); err != nil {
		panic(err)
	}

	rootUrl := cfg.Setting.RootURL
	u, err := url.Parse(rootUrl)
	if err != nil {
		panic(err)
	}
	cfg.Setting.rootURL = u
	cfg.OAuthRaw = NewSection("oauth")
	return &cfg
}
