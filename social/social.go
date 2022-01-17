package social

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/jmespath/go-jmespath"
	"github.com/n-creativesystem/ncsfw/config"
	"github.com/n-creativesystem/ncsfw/logger"
	"github.com/n-creativesystem/ncsfw/utils"
	"golang.org/x/oauth2"
)

func ProvideService(cfg *config.Config) *SocialService {
	ss := SocialService{
		cfg:           cfg,
		oAuthProvider: make(map[string]*OAuthInfo),
		socialMap:     make(map[string]SocialConnector),
		log:           logger.New("social service"),
	}
	oauth := cfg.OAuthRaw.Get()
	for name := range oauth {
		sec := cfg.OAuthRaw.Section(name)
		if sec == nil {
			continue
		}
		info := &OAuthInfo{
			ClientId:           sec.Key("client_id").String(),
			ClientSecret:       sec.Key("client_secret").String(),
			Scopes:             sec.Key("scopes").StringSlice(),
			AuthUrl:            sec.Key("auth_url").String(),
			TokenUrl:           sec.Key("token_url").String(),
			ApiUrl:             sec.Key("api_url").String(),
			Enabled:            sec.Key("enabled").MustBool(),
			EmailAttributeName: sec.Key("email_attribute_name").String(),
			EmailAttributePath: sec.Key("email_attribute_path").String(),
			AllowedDomains:     sec.Key("allowed_domains").StringSlice(),
			HostedDomain:       sec.Key("hosted_domain").String(),
			AllowSignup:        sec.Key("allow_sign_up").MustBool(),
			Name:               sec.Key("name").MustString(name),
			TlsClientCert:      sec.Key("tls_client_cert").String(),
			TlsClientKey:       sec.Key("tls_client_key").String(),
			TlsClientCa:        sec.Key("tls_client_ca").String(),
			TlsSkipVerify:      sec.Key("tls_skip_verify_insecure").MustBool(),
			UsePKCE:            sec.Key("use_pkce").MustBool(),
		}

		// when empty_scopes parameter exists and is true, overwrite scope with empty value
		if sec.Key("empty_scopes").MustBool() {
			info.Scopes = []string{}
		}

		if !info.Enabled {
			continue
		}

		ss.oAuthProvider[name] = info

		config := oauth2.Config{
			ClientID:     info.ClientId,
			ClientSecret: info.ClientSecret,
			Endpoint: oauth2.Endpoint{
				AuthURL:   info.AuthUrl,
				TokenURL:  info.TokenUrl,
				AuthStyle: oauth2.AuthStyleAutoDetect,
			},
			RedirectURL: strings.TrimSuffix(cfg.Setting.GetRootURL().String(), "/") + SocialBaseUrl + name,
			Scopes:      info.Scopes,
		}

		switch name {
		case "google":
			ss.socialMap[name] = &SocialGoogle{
				SocialBase:   newSocialBase(name, &config, info),
				hostedDomain: info.HostedDomain,
				apiUrl:       info.ApiUrl,
			}
		case "line":
			ss.socialMap[name] = &SocialLine{
				SocialBase: newSocialBase(name, &config, info),
				apiUrl:     info.ApiUrl,
			}
		case "auth0":
			ss.socialMap[name] = &SocialAuth0{
				SocialBase: newSocialBase(name, &config, info),
				apiUrl:     info.ApiUrl,
			}
		default:
			ss.socialMap[name] = &SocialGenericOAuth{
				SocialBase:           newSocialBase(name, &config, info),
				apiUrl:               info.ApiUrl,
				emailAttributeName:   info.EmailAttributeName,
				emailAttributePath:   info.EmailAttributePath,
				nameAttributePath:    sec.Key("name_attribute_path").String(),
				loginAttributePath:   sec.Key("login_attribute_path").String(),
				idTokenAttributeName: sec.Key("id_token_attribute_name").String(),
			}
		}
	}
	return &ss
}

type SocialService struct {
	cfg *config.Config

	socialMap     map[string]SocialConnector
	oAuthProvider map[string]*OAuthInfo

	log logger.Logger
}

var (
	_ Service = (*SocialService)(nil)
)

type OAuthInfo struct {
	ClientId, ClientSecret string
	Scopes                 []string
	AuthUrl, TokenUrl      string
	Enabled                bool
	EmailAttributeName     string
	EmailAttributePath     string
	AllowedDomains         []string
	HostedDomain           string
	ApiUrl                 string
	AllowSignup            bool
	Name                   string
	TlsClientCert          string
	TlsClientKey           string
	TlsClientCa            string
	TlsSkipVerify          bool
	UsePKCE                bool
}

type SocialBase struct {
	*oauth2.Config
	log            logger.Logger
	allowSignup    bool
	allowedDomains []string
}

func isEmailAllowed(email string, allowedDomains []string) bool {
	if len(allowedDomains) == 0 {
		return true
	}

	valid := false
	for _, domain := range allowedDomains {
		emailSuffix := fmt.Sprintf("@%s", domain)
		valid = valid || strings.HasSuffix(email, emailSuffix)
	}

	return valid
}

func (s *SocialBase) IsEmailAllowed(email string) bool {
	return isEmailAllowed(email, s.allowedDomains)
}

func (s *SocialBase) IsSignUpAllowed() bool {
	return s.allowSignup
}

type BasicUserInfo struct {
	Id         string
	Name       string
	Email      string
	Login      string
	PictureUrl string
}

type SocialConnector interface {
	Type() int
	UserInfo(client *http.Client, token *oauth2.Token) (*BasicUserInfo, error)
	IsEmailAllowed(email string) bool
	IsSignUpAllowed() bool

	AuthCodeURL(state string, opts ...oauth2.AuthCodeOption) string
	Exchange(ctx context.Context, code string, authOptions ...oauth2.AuthCodeOption) (*oauth2.Token, error)
	Client(ctx context.Context, t *oauth2.Token) *http.Client
	TokenSource(ctx context.Context, t *oauth2.Token) oauth2.TokenSource
}

type Service interface {
	GetOAuthProviders() map[string]bool
	GetOAuthHttpClient(string) (*http.Client, error)
	GetConnector(string) (SocialConnector, error)
	GetOAuthInfoProvider(string) *OAuthInfo
	GetOAuthInfoProviders() map[string]*OAuthInfo
}

var (
	SocialBaseUrl = utils.Getenv("OAUTH_LOGIN_URL", "/login/")
	SocialMap     = make(map[string]SocialConnector)
)

type httpGetResponse struct {
	Body    []byte
	Headers http.Header
}

func newSocialBase(name string, config *oauth2.Config, info *OAuthInfo) *SocialBase {
	return &SocialBase{
		Config:         config,
		log:            logger.New("oauth." + name),
		allowSignup:    info.AllowSignup,
		allowedDomains: info.AllowedDomains,
	}
}

func (s *SocialBase) httpGet(client *http.Client, url string) (response httpGetResponse, err error) {
	r, err := client.Get(url)
	if err != nil {
		return
	}

	defer func() {
		if err := r.Body.Close(); err != nil {
			s.log.Warning("Failed to close response body", "err", err)
		}
	}()

	body, err := io.ReadAll(r.Body)
	if err != nil {
		return
	}

	response = httpGetResponse{body, r.Header}

	if r.StatusCode >= 300 {
		err = fmt.Errorf(string(response.Body))
		return
	}
	s.log.DebugWithContext(r.Request.Context(), fmt.Sprintf("response_body %s", string(response.Body)), "method", r.Request.Method, "url", url, "status", r.Status)
	err = nil
	return
}

func (s *SocialBase) searchJSONForAttr(attributePath string, data []byte) (interface{}, error) {
	if attributePath == "" {
		return "", errors.New("no attribute path specified")
	}

	if len(data) == 0 {
		return "", errors.New("empty user info JSON response provided")
	}

	var buf interface{}
	if err := json.Unmarshal(data, &buf); err != nil {
		return "", utils.Wrap("failed to unmarshal user info JSON response", err)
	}

	val, err := jmespath.Search(attributePath, buf)
	if err != nil {
		return "", utils.Wrapf(err, "failed to search user info JSON response with provided path: %q", attributePath)
	}

	return val, nil
}

func (s *SocialBase) searchJSONForStringAttr(attributePath string, data []byte) (string, error) {
	val, err := s.searchJSONForAttr(attributePath, data)
	if err != nil {
		return "", err
	}

	strVal, ok := val.(string)
	if ok {
		return strVal, nil
	}

	return "", nil
}

func (s *SocialBase) searchJSONForStringArrayAttr(attributePath string, data []byte) ([]string, error) {
	val, err := s.searchJSONForAttr(attributePath, data)
	if err != nil {
		return []string{}, err
	}

	ifArr, ok := val.([]interface{})
	if !ok {
		return []string{}, nil
	}

	result := []string{}
	for _, v := range ifArr {
		if strVal, ok := v.(string); ok {
			result = append(result, strVal)
		}
	}

	return result, nil
}

func (ss *SocialService) GetOAuthProviders() map[string]bool {
	result := map[string]bool{}

	if ss.cfg == nil || ss.cfg.OAuthRaw == nil {
		return result
	}
	oauth := ss.cfg.OAuthRaw.Get()
	for name := range oauth {
		sec := ss.cfg.OAuthRaw.Section(name)
		if sec == nil {
			continue
		}
		result[name] = sec.Key("enabled").MustBool()
	}

	return result
}

func (ss *SocialService) GetOAuthHttpClient(name string) (*http.Client, error) {
	name = strings.TrimPrefix(name, "oauth_")
	info, ok := ss.oAuthProvider[name]
	if !ok {
		return nil, fmt.Errorf("could not find %q in OAuth Settings", name)
	}

	tr := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: info.TlsSkipVerify,
		},
	}
	oauthClient := &http.Client{
		Transport: tr,
	}

	if info.TlsClientCert != "" || info.TlsClientKey != "" {
		cert, err := tls.LoadX509KeyPair(info.TlsClientCert, info.TlsClientKey)
		if err != nil {
			ss.log.Error(err, "Failed to setup TlsClientCert", "oauth", name)
			return nil, fmt.Errorf("failed to setup TlsClientCert: %w", err)
		}

		tr.TLSClientConfig.Certificates = append(tr.TLSClientConfig.Certificates, cert)
	}

	if info.TlsClientCa != "" {
		caCert, err := os.ReadFile(info.TlsClientCa)
		if err != nil {
			ss.log.Error(err, "Failed to setup TlsClientCa", "oauth", name)
			return nil, fmt.Errorf("failed to setup TlsClientCa: %w", err)
		}
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)
		tr.TLSClientConfig.RootCAs = caCertPool
	}
	return oauthClient, nil
}

func (ss *SocialService) GetConnector(name string) (SocialConnector, error) {
	provider := strings.TrimPrefix(name, "oauth_")
	connector, ok := ss.socialMap[provider]
	if !ok {
		return nil, fmt.Errorf("failed to find oauth provider for %q", name)
	}
	return connector, nil
}

func (ss *SocialService) GetOAuthInfoProvider(name string) *OAuthInfo {
	return ss.oAuthProvider[name]
}

func (ss *SocialService) GetOAuthInfoProviders() map[string]*OAuthInfo {
	return ss.oAuthProvider
}
