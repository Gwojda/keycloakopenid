package keycloakopenid

import (
	"context"
	"errors"
	"net/http"
	"net/url"
)

type Config struct {
	KeycloakURL string `json:"url"`
	ClientID    string `json:"client_id"`
}

type keycloakAuth struct {
	next   http.Handler
	config *Config
}

func CreateConfig() *Config {
	return &Config{}
}

func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	if config.KeycloakURL == "" || config.ClientID == "" {
		return nil, errors.New("invalid configuration")
	}

	return &keycloakAuth{
		next:   next,
		config: config,
	}, nil
}

func (k *keycloakAuth) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	// Redirect all requests to the Keycloak login page
	redirectURI := req.URL.String()
	http.Redirect(rw, req, k.getLoginURL(redirectURI), http.StatusFound)
}

func (k *keycloakAuth) getLoginURL(redirectURI string) string {
	// This method returns the URL of the Keycloak login page
	// The parameters should match your Keycloak setup
	return k.config.KeycloakURL + "/protocol/openid-connect/auth?" +
		"client_id=" + k.config.ClientID +
		"&redirect_uri=" + url.QueryEscape(redirectURI) +
		"&response_type=code"
}
