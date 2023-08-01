package keycloakopenid

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
	if authHeader != "" && strings.HasPrefix(authHeader, "Bearer ") {
		token := strings.TrimPrefix(authHeader, "Bearer ")

		ok, err := k.verifyToken(token)
		if err != nil {
			http.Error(rw, err.Error(), http.StatusInternalServerError)
			return
		}
		if !ok {
			http.Error(rw, "Invalid token", http.StatusUnauthorized)
			return
		}
	} else {
		authCode := req.URL.Query().Get("code")
		if authCode == "" {
			k.redirectToKeycloak(rw, req)
			return
		}

		stateBase64 := req.URL.Query().Get("state")
		if stateBase64 == "" {
			k.redirectToKeycloak(rw, req)
			return
		}

		fmt.Printf("==>%+v\n", req.URL.Query())
		token, err := k.exchangeAuthCode(req, authCode, stateBase64)
		if err != nil {
			http.Error(rw, err.Error(), http.StatusInternalServerError)
			return
		}

		fmt.Printf("==>%+v\n", token)
		req.Header.Set("Authorization", "Bearer "+token)
	}

	req.URL.RawQuery = ""

	k.next.ServeHTTP(rw, req)
}

func (k *keycloakAuth) exchangeAuthCode(req *http.Request, authCode string, stateBase64 string) (string, error) {
	stateBytes, _ := base64.StdEncoding.DecodeString(stateBase64)
	var state state
	json.Unmarshal(stateBytes, &state)

	resp, err := http.PostForm("https://"+k.config.KeycloakURL+"/realms/"+k.config.KeycloakReaml+"/protocol/openid-connect/token",
		url.Values{
			"grant_type":    {"authorization_code"},
			"client_id":     {k.config.ClientID},
			"client_secret": {k.config.ClientSecret},
			"code":          {authCode},
			"redirect_uri":  {state.RedirectURL},
		})

	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", errors.New("received bad response from Keycloak: " + string(body))
	}

	var tokenResponse KeycloakTokenResponse
	err = json.NewDecoder(resp.Body).Decode(&tokenResponse)
	if err != nil {
		return "", err
	}

	return tokenResponse.AccessToken, nil
}

func (k *keycloakAuth) redirectToKeycloak(rw http.ResponseWriter, req *http.Request) {
	scheme := req.Header.Get("X-Forwarded-Proto")
	host := req.Header.Get("X-Forwarded-Host")
	originalURL := fmt.Sprintf("%s://%s%s", scheme, host, req.RequestURI)

	state := state{
		RedirectURL: originalURL,
	}

	stateBytes, _ := json.Marshal(state)
	stateBase64 := base64.StdEncoding.EncodeToString(stateBytes)

	redirectURL := url.URL{
		Scheme: "https",
		Host:   k.config.KeycloakURL,
		Path:   "/realms/" + k.config.KeycloakReaml + "/protocol/openid-connect/auth",
		RawQuery: url.Values{
			"response_type": {"code"},
			"client_id":     {k.config.ClientID},
			"redirect_uri":  {originalURL},
			"state":         {stateBase64},
		}.Encode(),
	}

	fmt.Printf("==>%+v\n", redirectURL.String())
	http.Redirect(rw, req, redirectURL.String(), http.StatusFound)
}

func (k *keycloakAuth) verifyToken(token string) (bool, error) {
	client := &http.Client{}

	data := url.Values{
		"token": {token},
	}

	req, err := http.NewRequest(http.MethodPost, "https://"+k.config.KeycloakURL+"/realms/"+k.config.KeycloakReaml+"/protocol/openid-connect/token/introspect", strings.NewReader(data.Encode()))
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
