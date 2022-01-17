package handler

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"strings"

	"github.com/gorilla/sessions"
	"github.com/n-creativesystem/ncsfw"
	"github.com/n-creativesystem/ncsfw/config"
	"github.com/n-creativesystem/ncsfw/handler/response"
	"github.com/n-creativesystem/ncsfw/logger"
	"github.com/n-creativesystem/ncsfw/models"
	"github.com/n-creativesystem/ncsfw/social"
	"github.com/n-creativesystem/ncsfw/tracer/metrics"
	"golang.org/x/oauth2"
)

const (
	loginKey             = "loginUser"
	OauthSessionName     = "oauth_session"
	OauthStateCookieName = "oauth_state"
	OauthPKCECookieName  = "oauth_code_verifier"
)

type SocialLogin interface {
	Validate(connector social.SocialConnector, userInfo *social.BasicUserInfo) error
	BuildExternalUserInfo(ctx context.Context, token *oauth2.Token, socialUser *social.BasicUserInfo, providerName string) models.LoginUser
	LoginComplete(loginUser models.LoginUser, isSignUpAllowed bool) error
}

type SocialLoginImpl struct {
}

func (s *SocialLoginImpl) Validate(connector social.SocialConnector, userInfo *social.BasicUserInfo) error {
	return nil
}

func (s *SocialLoginImpl) BuildExternalUserInfo(ctx context.Context, token *oauth2.Token, socialUser *social.BasicUserInfo, providerName string) models.LoginUser {
	return models.NewLoginUser(socialUser.Id, socialUser.Name, socialUser.Email, providerName, token)
}

func (s *SocialLoginImpl) LoginComplete(loginUser models.LoginUser, isSignUpAllowed bool) error {
	return nil
}

func NewSocialLogin() *SocialLoginImpl {
	return &SocialLoginImpl{}
}

type SocialHandle interface {
	GetOAuthProvider(c ncsfw.Context) error
	OAuthLogin(c ncsfw.Context) error
	Logout(c ncsfw.Context) error
}

type SocailHandler struct {
	cfg           *config.Config
	socialService social.Service
	store         sessions.Store
	log           logger.Logger
	socilaLogin   SocialLogin
}

var _ SocialHandle = (*SocailHandler)(nil)

func NewSocialHandler(cfg *config.Config, socialService social.Service, store sessions.Store, socilaLogin SocialLogin) *SocailHandler {
	if store == nil {
		store = sessions.NewCookieStore([]byte("session-default"))
	}
	if socilaLogin == nil {
		socilaLogin = &SocialLoginImpl{}
	}
	return &SocailHandler{
		cfg:           cfg,
		socialService: socialService,
		store:         store,
		log:           logger.New("social login handler"),
		socilaLogin:   socilaLogin,
	}
}

func (s *SocailHandler) GetOAuthProvider(c ncsfw.Context) error {
	result := make(map[string]interface{})
	mp := s.socialService.GetOAuthInfoProviders()
	for key, value := range mp {
		if value.Enabled {
			result[key] = map[string]interface{}{
				"name": value.Name,
			}
		}
	}
	c.JSON(http.StatusOK, ncsfw.Map{
		"data": result,
	})
	return nil
}

func (s *SocailHandler) OAuthLogin(c ncsfw.Context) error {
	r := c.Request()
	ctx := r.Context()
	session, err := s.store.Get(r, OauthSessionName)
	if err != nil {
		return err
	}
	name := c.Param("name")
	provider := s.socialService.GetOAuthInfoProvider(name)
	connector, err := s.socialService.GetConnector(name)
	if err != nil {
		s.log.ErrorWithContext(ctx, err, "social service connector")
		s.handleOAuthLoginError(c, response.ErrJson("social service connector", err))
		return nil
	}
	errorParam := c.Query("error")
	if errorParam != "" {
		errorDesc := errors.New(c.Query("error_description"))
		s.log.ErrorWithContext(ctx, errorDesc, errorParam)
		s.handleOAuthLoginError(c, response.ErrJson(errorParam, errorDesc))
		return nil
	}

	code := c.Query("code")
	if code == "" {
		opts := []oauth2.AuthCodeOption{oauth2.AccessTypeOnline}
		if provider.UsePKCE {
			ascii, pkce, err := generateCodeChallenge()
			if err != nil {
				s.log.ErrorWithContext(ctx, err, "Generating PKCE failed")
				s.handleOAuthLoginError(c, response.ErrJsonWithStatus(http.StatusInternalServerError, "An internal error occurred", err))
				return nil
			}
			session.Values[OauthPKCECookieName] = ascii
			// cookies.WriteSessionCookie(c.Writer, OauthPKCECookieName, ascii, s.Cfg.OAuthCookieMaxAge)

			opts = append(opts,
				oauth2.SetAuthURLParam("code_challenge", pkce),
				oauth2.SetAuthURLParam("code_challenge_method", "S256"),
			)
		}
		state, err := genStateString()
		if err != nil {
			s.log.ErrorWithContext(ctx, err, "Generating state string failed")
			s.handleOAuthLoginError(c, response.ErrJsonWithStatus(http.StatusInternalServerError, "An internal error occurred", err))
			return nil
		}
		hashedState := hashStatecode(state, s.cfg.Cookie.SecretKey, provider.ClientSecret)
		session.Values[OauthStateCookieName] = hashedState
		if err := session.Save(r, c.Writer()); err != nil {
			s.log.ErrorWithContext(ctx, err, "session save error")
			s.handleOAuthLoginError(c, response.ErrJsonWithStatus(http.StatusInternalServerError, "session save error", err))
		}
		if provider.HostedDomain != "" {
			opts = append(opts, oauth2.SetAuthURLParam("hd", provider.HostedDomain))
		}
		c.Redirect(http.StatusFound, connector.AuthCodeURL(state, opts...))
		return nil
	}
	cookieState, ok := session.Values[OauthStateCookieName].(string)
	if !ok {
		s.log.ErrorWithContext(ctx, err, "login.OAuthLogin(missing saved state)")
		s.handleOAuthLoginError(c, response.ErrJsonWithStatus(http.StatusInternalServerError, "login.OAuthLogin(missing saved state)", err))
		return nil
	}
	delete(session.Values, OauthStateCookieName)
	if err := session.Save(r, c.Writer()); err != nil {
		s.log.ErrorWithContext(ctx, err, "session save error")
		s.handleOAuthLoginError(c, response.ErrJsonWithStatus(http.StatusInternalServerError, "session save error", err))
		return nil
	}
	queryState := hashStatecode(c.Query("state"), s.cfg.Cookie.SecretKey, provider.ClientSecret)
	if cookieState != queryState {
		s.handleOAuthLoginError(c, response.ErrJsonWithStatus(http.StatusInternalServerError, "login.OAuthLogin(state mismatch)", nil))
		return nil
	}

	oauthClient, err := s.socialService.GetOAuthHttpClient(name)
	if err != nil {
		s.log.ErrorWithContext(ctx, err, "Failed to create OAuth http client")
		s.handleOAuthLoginError(c, response.ErrJsonWithStatus(http.StatusInternalServerError, "login.OAuthLogin("+err.Error()+")", err))
		return nil
	}

	oauthCtx := context.WithValue(context.Background(), oauth2.HTTPClient, oauthClient)
	opts := []oauth2.AuthCodeOption{}

	if codeVerifier, ok := session.Values[OauthPKCECookieName].(string); ok {
		delete(session.Values, OauthPKCECookieName)
		if codeVerifier != "" {
			opts = append(opts,
				oauth2.SetAuthURLParam("code_verifier", codeVerifier),
			)
		}
	}

	// get token from provider
	token, err := connector.Exchange(oauthCtx, code, opts...)
	if err != nil {
		s.log.ErrorWithContext(ctx, err, "login.OAuthLogin(NewTransportWithCode)")
		s.handleOAuthLoginError(c, response.ErrJsonWithStatus(http.StatusInternalServerError, "login.OAuthLogin(NewTransportWithCode)", err))
		return nil
	}
	token.TokenType = "Bearer"

	// set up oauth2 client
	client := connector.Client(oauthCtx, token)

	// get user info
	userInfo, err := connector.UserInfo(client, token)
	if err != nil {
		s.log.ErrorWithContext(ctx, err, fmt.Sprintf("login.OAuthLogin(get info from %s)", name))
		s.handleOAuthLoginError(c, response.ErrJsonWithStatus(http.StatusInternalServerError, fmt.Sprintf("login.OAuthLogin(get info from %s)", name), err))
		return nil
	}

	if err := s.socilaLogin.Validate(connector, userInfo); err != nil {
		s.handleOAuthLoginError(c, response.ErrJsonWithStatus(http.StatusUnauthorized, "login provider didn't return an email address", nil))
		return nil
	}

	// validate that we got at least an email address
	// if userInfo.Email == "" {
	// 	s.handleOAuthLoginError(c, response.ErrJsonWithStatus(http.StatusUnauthorized, "login provider didn't return an email address", nil))
	// 	return nil
	// }

	// validate that the email is allowed to login to grafana
	// if !connector.IsEmailAllowed(userInfo.Email) {
	// 	s.handleOAuthLoginError(c, response.ErrJsonWithStatus(http.StatusUnauthorized, "required email domain not fulfilled", nil))
	// 	return nil
	// }

	loginUser := s.socilaLogin.BuildExternalUserInfo(ctx, token, userInfo, name)
	session.Values[loginKey] = loginUser.Serialize()
	if err := s.socilaLogin.LoginComplete(loginUser, connector.IsSignUpAllowed()); err != nil {
		s.log.ErrorWithContext(ctx, err, "login complete error")
		u := path.Join(s.cfg.Setting.GetRootURL().Path, "/logout")
		redirect(c, u)
		return err
	}
	metrics.MApiLoginOAuth.Inc()
	if redirectTo, ok := session.Values["redirect_to"].(string); ok {
		if redirectTo, err := url.QueryUnescape(redirectTo); err == nil && len(redirectTo) > 0 {
			if err := s.ValidateRedirectTo(redirectTo); err == nil {
				delete(session.Values, "redirect_to")
				redirect(c, redirectTo)
				return nil
			}
			s.log.DebugWithContext(ctx, "Ignored invalid redirect_to cookie value", "redirect_to", redirectTo)
		}
	}
	if err := session.Save(r, c.Writer()); err != nil {
		s.log.ErrorWithContext(ctx, err, "session save error")
		s.handleOAuthLoginError(c, response.ErrJsonWithStatus(http.StatusInternalServerError, "session save error", err))
	}
	if err != nil {
		return err
	}
	redirect(c, s.cfg.Setting.GetRootURL().String())
	return nil
}

func (s *SocailHandler) handleOAuthLoginError(c ncsfw.Context, err response.ErrorResponse) {
	s.log.ErrorWithContext(c.Request().Context(), err, "login")
	u := path.Join(s.cfg.Setting.GetRootURL().Path, "/login")
	redirect(c, u)
}

func (s *SocailHandler) Logout(c ncsfw.Context) error {
	r := c.Request()
	session, err := s.store.Get(r, OauthSessionName)
	if err != nil {
		return err
	}
	session.Options.MaxAge = -1
	_ = session.Save(r, c.Writer())
	s.log.InfoWithContext(r.Context(), "Successful Logout")
	redirect(c, s.cfg.Setting.GetRootURL().String())
	return nil
}

func (hs *SocailHandler) ValidateRedirectTo(redirectTo string) error {
	to, err := url.Parse(redirectTo)
	if err != nil {
		return ErrInvalidRedirectTo
	}
	if to.IsAbs() {
		return ErrAbsoluteRedirectTo
	}

	if to.Host != "" {
		return ErrForbiddenRedirectTo
	}

	if !strings.HasPrefix(to.Path, "/") {
		return ErrForbiddenRedirectTo
	}
	if strings.HasPrefix(to.Path, "//") {
		return ErrForbiddenRedirectTo
	}

	rootURL := hs.cfg.Setting.GetRootURL().String()
	if rootURL != "" && !strings.HasPrefix(to.Path, rootURL+"/") {
		return ErrInvalidRedirectTo
	}

	return nil
}

type Redirect interface {
	Redirect(code int, url string)
}

func redirect(r Redirect, url string) {
	r.Redirect(http.StatusFound, url)
}

func genStateString() (string, error) {
	rnd := make([]byte, 32)
	if _, err := rand.Read(rnd); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(rnd), nil
}

func hashStatecode(code, secretKey, seed string) string {
	hashBytes := sha256.Sum256([]byte(code + secretKey + seed))
	return hex.EncodeToString(hashBytes[:])
}

func generateCodeVerifier() (codeVerifier []byte, err error) {
	raw := make([]byte, 96)
	_, err = rand.Read(raw)
	if err != nil {
		return nil, err
	}
	ascii := make([]byte, 128)
	base64.RawURLEncoding.Encode(ascii, raw)
	return ascii, nil
}

func generateCodeChallenge() (string, string, error) {
	codeVerifier, err := generateCodeVerifier()
	if err != nil {
		return "", "", err
	}
	sum := sha256.Sum256(codeVerifier)
	codeChallenge := base64.RawURLEncoding.EncodeToString(sum[:])
	return string(codeVerifier), codeChallenge, nil
}
