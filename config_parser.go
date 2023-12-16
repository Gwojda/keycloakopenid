package traefik_oidc_relying_party

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
	ProviderURL    string `json:"url"`
	ClientID       string `json:"client_id"`
	ClientSecret   string `json:"client_secret"`
	UserClaimName  string `json:"user_claim_name"`
	UserHeaderName string `json:"user_header_name"`

	ClientIDFile     string `json:"client_id_file"`
	ClientSecretFile string `json:"client_secret_file"`
	ProviderURLEnv   string `json:"url_env"`
	ClientIDEnv      string `json:"client_id_env"`
	ClientSecretEnv  string `json:"client_secret_env"`
}

type ProviderAuth struct {
	next           http.Handler
	ProviderURL    *url.URL
	ClientID       string
	ClientSecret   string
	UserClaimName  string
	UserHeaderName string
}

type ProviderTokenResponse struct {
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
	if config.ProviderURLEnv != "" {
		ProviderURL := os.Getenv(config.ProviderURLEnv)
		if ProviderURL == "" {
			return errors.New("ProviderURLEnv referenced but NOT set")
		}
		config.ProviderURL = strings.TrimSpace(ProviderURL)
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

	parsedURL, err := parseUrl(config.ProviderURL)
	if err != nil {
		return nil, err
	}

	userClaimName := "preferred_username"
	if config.UserClaimName != "" {
		userClaimName = config.UserClaimName
	}

	userHeaderName := "X-Forwarded-User"
	if config.UserHeaderName != "" {
		userHeaderName = config.UserHeaderName
	}

	return &ProviderAuth{
		next:           next,
		ProviderURL:    parsedURL,
		ClientID:       config.ClientID,
		ClientSecret:   config.ClientSecret,
		UserClaimName:  userClaimName,
		UserHeaderName: userHeaderName,
	}, nil
}
