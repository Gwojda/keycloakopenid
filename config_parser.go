package keycloakopenid

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
)

type Config struct {
	KeycloakURL        string `json:"url"`
	ClientID           string `json:"client_id"`
	ClientSecret       string `json:"client_secret"`
	KeycloakRealm      string `json:"keycloak_realm"`
	Scope              string `json:"scope"`
	KcIdpHint          string `json:"kc_idp_hint"`
	TokenCookieName    string `json:"token_cookie_name"`
	UseAuthHeader      bool   `json:"use_auth_header"`
	UserClaimName      string `json:"user_claim_name"`
	UserHeaderName     string `json:"user_header_name"`
	IgnorePathPrefixes string `json:"ignore_path_prefixes"`

	ClientIDFile          string `json:"client_id_file"`
	ClientSecretFile      string `json:"client_secret_file"`
	KeycloakURLEnv        string `json:"url_env"`
	ClientIDEnv           string `json:"client_id_env"`
	ClientSecretEnv       string `json:"client_secret_env"`
	KeycloakRealmEnv      string `json:"keycloak_realm_env"`
	ScopeEnv              string `json:"scope_env"`
	TokenCookieNameEnv    string `json:"token_cookie_name_env"`
	UseAuthHeaderEnv      string `json:"use_auth_header_env"`
	IgnorePathPrefixesEnv string `json:"ignore_path_prefixes_env"`
}

type keycloakAuth struct {
	next               http.Handler
	KeycloakURL        *url.URL
	ClientID           string
	ClientSecret       string
	KeycloakRealm      string
	Scope              string
	KcIdpHint          string
	TokenCookieName    string
	UseAuthHeader      bool
	UserClaimName      string
	UserHeaderName     string
	IgnorePathPrefixes []string
}

type KeycloakTokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
}

type state struct {
	RedirectURL string `json:"redirect_url"`
}

func CreateConfig() *Config {
	return &Config{}
}

func parseUrl(rawUrl string) (*url.URL, error) {
	if rawUrl == "" {
		return nil, errors.New("invalid empty url")
	}
	if !strings.Contains(rawUrl, "://") {
		rawUrl = "https://" + rawUrl
	}
	u, err := url.Parse(rawUrl)
	if err != nil {
		return nil, err
	}
	if !strings.HasPrefix(u.Scheme, "http") {
		return nil, fmt.Errorf("%v is not a valid scheme", u.Scheme)
	}
	return u, nil
}

func readSecretFiles(config *Config) error {
	if config.ClientIDFile != "" {
		id, err := os.ReadFile(config.ClientIDFile)
		if err != nil {
			return err
		}
		clientId := string(id)
		clientId = strings.TrimSpace(clientId)
		clientId = strings.TrimSuffix(clientId, "\n")
		config.ClientID = clientId
	}
	if config.ClientSecretFile != "" {
		secret, err := os.ReadFile(config.ClientSecretFile)
		if err != nil {
			return err
		}
		clientSecret := string(secret)
		clientSecret = strings.TrimSpace(clientSecret)
		clientSecret = strings.TrimSuffix(clientSecret, "\n")
		config.ClientSecret = clientSecret
	}
	return nil
}

func readConfigEnv(config *Config) error {
	if config.KeycloakURLEnv != "" {
		keycloakUrl := os.Getenv(config.KeycloakURLEnv)
		if keycloakUrl == "" {
			return errors.New("KeycloakURLEnv referenced but NOT set")
		}
		config.KeycloakURL = strings.TrimSpace(keycloakUrl)
	}
	if config.ClientIDEnv != "" {
		clientId := os.Getenv(config.ClientIDEnv)
		if clientId == "" {
			return errors.New("ClientIDEnv referenced but NOT set")
		}
		config.ClientID = strings.TrimSpace(clientId)
	}
	if config.ClientSecretEnv != "" {
		clientSecret := os.Getenv(config.ClientSecretEnv)
		if clientSecret == "" {
			return errors.New("ClientSecretEnv referenced but NOT set")
		}
		config.ClientSecret = strings.TrimSpace(clientSecret)
	}
	if config.KeycloakRealmEnv != "" {
		keycloakRealm := os.Getenv(config.KeycloakRealmEnv)
		if keycloakRealm == "" {
			return errors.New("KeycloakRealmEnv referenced but NOT set")
		}
		config.KeycloakRealm = strings.TrimSpace(keycloakRealm)
	}
	if config.ScopeEnv != "" {
		scope := os.Getenv(config.ScopeEnv)
		if scope == "" {
			return errors.New("ScopeEnv referenced but NOT set")
		}
		config.Scope = scope //Do not trim space here as it is common to use space as a separator and should be properly escaped when encoded
	}
	if config.TokenCookieNameEnv != "" {
		tokenCookieName := os.Getenv(config.TokenCookieNameEnv)
		if tokenCookieName == "" {
			return errors.New("TokenCookieNameEnv referenced but NOT set")
		}
		config.TokenCookieName = strings.TrimSpace(tokenCookieName)
	}
	if config.UseAuthHeaderEnv != "" {
		useAuthHeader, exists := os.LookupEnv(config.UseAuthHeaderEnv)
		if !exists {
			useAuthHeader = "false"
		}
		useAuthHeader = strings.ToLower(useAuthHeader)
		config.UseAuthHeader = useAuthHeader == "true" || useAuthHeader == "1"
	}
	if config.IgnorePathPrefixesEnv != "" {
		ignorePathPrefixes := os.Getenv(config.IgnorePathPrefixesEnv)
		if ignorePathPrefixes == "" {
			return errors.New("IgnorePathPrefixesEnv referenced but NOT set")
		}
		config.IgnorePathPrefixes = strings.TrimSpace(ignorePathPrefixes)
	}
	return nil
}

func New(uctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	err := readSecretFiles(config)
	if err != nil {
		return nil, err
	}
	err = readConfigEnv(config)
	if err != nil {
		return nil, err
	}

	if config.ClientID == "" || config.KeycloakRealm == "" {
		return nil, errors.New("invalid configuration")
	}

	parsedURL, err := parseUrl(config.KeycloakURL)
	if err != nil {
		return nil, err
	}

	if config.Scope == "" {
		config.Scope = "openid"
	}

	tokenCookieName := "AUTH_TOKEN"
	if config.TokenCookieName != "" {
		tokenCookieName = config.TokenCookieName
	}

	useAuthHeader := false
	if config.UseAuthHeader {
		useAuthHeader = true
	}

	userClaimName := "preferred_username"
	if config.UserClaimName != "" {
		userClaimName = config.UserClaimName
	}

	userHeaderName := "X-Forwarded-User"
	if config.UserHeaderName != "" {
		userHeaderName = config.UserHeaderName
	}

	ignorePathPrefixes := []string{}
	if config.IgnorePathPrefixes != "" {
		ignorePathPrefixes = strings.Split(config.IgnorePathPrefixes, ",")
	}

	return &keycloakAuth{
		next:               next,
		KeycloakURL:        parsedURL,
		ClientID:           config.ClientID,
		ClientSecret:       config.ClientSecret,
		KeycloakRealm:      config.KeycloakRealm,
		Scope:              config.Scope,
		KcIdpHint:          config.KcIdpHint,
		TokenCookieName:    tokenCookieName,
		UseAuthHeader:      useAuthHeader,
		UserClaimName:      userClaimName,
		UserHeaderName:     userHeaderName,
		IgnorePathPrefixes: ignorePathPrefixes,
	}, nil
}
