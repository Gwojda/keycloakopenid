package keycloakopenid

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
)

type Config struct {
	KeycloakURL   string `json:"url"`
	ClientID      string `json:"client_id"`
	ClientSecret  string `json:"client_secret"`
	KeycloakReaml string `json:"keycloak_reaml"`
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
	authHeader := req.Header.Get("Authorization")

	if authHeader != "" {
		token := strings.TrimPrefix(authHeader, "Bearer ")

		valid, err := k.verifyToken(token)
		if err != nil {
			http.Error(rw, err.Error(), http.StatusInternalServerError)
			return
		}

		if valid {
			k.next.ServeHTTP(rw, req)
			return
		}
	}

	k.redirectToKeycloak(rw, req)
}

func (k *keycloakAuth) redirectToKeycloak(rw http.ResponseWriter, req *http.Request) {
	redirectURL := url.URL{
		Scheme: "https",
		Host:   k.config.KeycloakURL,
		Path:   "/realms/" + k.config.KeycloakReaml + "/protocol/openid-connect/auth",
		RawQuery: url.Values{
			"response_type": {"code"},
			"client_id":     {k.config.ClientID},
			"redirect_uri":  {req.URL.String()},
			"state":         {randomString()},
		}.Encode(),
	}

	http.Redirect(rw, req, redirectURL.String(), http.StatusFound)
}

func randomString() string {
	bytes := make([]byte, 32)
	rand.Read(bytes)
	return base64.URLEncoding.EncodeToString(bytes)
}

func (k *keycloakAuth) verifyToken(token string) (bool, error) {
	client := &http.Client{}

	data := url.Values{
		"token": {token},
	}

	req, err := http.NewRequest(http.MethodPost, k.config.KeycloakURL+"/protocol/openid-connect/token/introspect", strings.NewReader(data.Encode()))
	if err != nil {
		return false, err
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(k.config.ClientID, k.config.ClientSecret)

	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, nil
	}

	var introspectResponse map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&introspectResponse)
	if err != nil {
		return false, err
	}

	return introspectResponse["active"].(bool), nil
}
