package keycloakopenid

import (
	"context"
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
	"net/url"
)

type Config struct {
	KeycloakURL  string `json:"url"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

type KeycloakTokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
}

type keycloakAuth struct {
	next   http.Handler
	config *Config
}

func CreateConfig() *Config {
	return &Config{}
}

func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	if config.KeycloakURL == "" || config.ClientID == "" || config.ClientSecret == "" {
		return nil, errors.New("invalid configuration")
	}

	return &keycloakAuth{
		next:   next,
		config: config,
	}, nil
}

func (k *keycloakAuth) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	token, err := k.getAccessToken()
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}

	req.Header.Set("Authorization", "Bearer "+token)
	k.next.ServeHTTP(rw, req)
}

func (k *keycloakAuth) getAccessToken() (string, error) {
	resp, err := http.PostForm(k.config.KeycloakURL+"/protocol/openid-connect/token",
		url.Values{
			"grant_type":    {"client_credentials"},
			"client_id":     {k.config.ClientID},
			"client_secret": {k.config.ClientSecret},
		})

	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := ioutil.ReadAll(resp.Body)
		return "", errors.New("received bad response from Keycloak: " + string(body))
	}

	var tokenResponse KeycloakTokenResponse
	err = json.NewDecoder(resp.Body).Decode(&tokenResponse)
	if err != nil {
		return "", err
	}

	return tokenResponse.AccessToken, nil
}
