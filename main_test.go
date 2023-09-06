package keycloakopenid

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestParseURL(t *testing.T) {
	var u *url.URL
	var err error

	u, err = parseUrl("")
	if err == nil {
		t.Fatal("should not accept empty url")
	}

	u, err = parseUrl("auth.bochslerfinance.com")
	if err != nil {
		t.Fatal("should not fail here, error was: ", err)
	} else if u.Scheme != "https" {
		t.Fatal("url without scheme should be auto-prefixed with 'https'")
	} else if u.Host != "auth.bochslerfinance.com" {
		t.Fatal("Host part should have been right parsed")
	}

	u, err = parseUrl("172.17.0.1:8443")
	if err != nil {
		t.Fatal("should not fail here. error was: ", err)
	} else if u.Scheme != "https" {
		t.Fatal("url without scheme should be auto-prefixed with 'https'")
	} else if u.Host != "172.17.0.1:8443" {
		t.Fatal("Host part should have been right parsed")
	}

	u, err = parseUrl("http://auth.bochslerfinance.com")
	if err != nil {
		t.Fatal("should not fail here. error was: ", err)
	} else if u.Scheme != "http" {
		t.Fatal("Scheme part should have been right parsed")
	} else if u.Host != "auth.bochslerfinance.com" {
		t.Fatal("Host part should have been right parsed")
	}

	u, err = parseUrl("https://auth.bochslerfinance.com")
	if err != nil {
		t.Fatal("should not fail here. error was: ", err)
	} else if u.Scheme != "https" {
		t.Fatal("Scheme part should have been right parsed")
	} else if u.Host != "auth.bochslerfinance.com" {
		t.Fatal("Host part should have been right parsed")
	}

	u, err = parseUrl("ftp://auth.bochslerfinance.com")
	if !(err != nil && u == nil) {
		t.Fatal("should not accept scheme other than http and https")
	}

	u, err = parseUrl("bochslerfinance.com/auth")
	if err != nil {
		t.Fatal("should not fail here. error was: ", err)
	} else if u.Scheme != "https" {
		t.Fatal("Scheme part should have been right parsed")
	} else if u.Host != "bochslerfinance.com" {
		t.Fatal("Host part should have been right parsed")
	} else if u.Path != "/auth" {
		t.Fatal("Path part should have been right parsed")
	}

	// special case wherekeycloak is hosted locally
	// url will be https:///auth (no host part)
	u, err = parseUrl("/auth")
	if err != nil {
		t.Fatal("should not fail here. error was: ", err)
	} else if u.Scheme != "https" {
		t.Fatal("Scheme part should have been right parsed")
	} else if u.Host != "" {
		t.Fatal("Host part should have been right parsed")
	} else if u.Path != "/auth" {
		t.Fatal("Path part should have been right parsed")
	}
}

func TestSetup(t *testing.T) {
	handlerFunc := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusOK)
	})

	// Setup
	config := CreateConfig()
	config.KeycloakURL = "auth.bochslerfinance.com"
	config.KeycloakRealm = "bochsler"
	config.ClientID = "keycloakMiddleware"
	config.ClientSecret = "uc0yKKpQsOqhggsG4eK7mDU3glT81chn"
	_, err := New(context.TODO(), handlerFunc, config, "keycloak-openid")
	if err != nil {
		t.Fatal("Can't create middleware", err)
	}

	config = CreateConfig()
	config.KeycloakRealm = "bochsler"
	config.ClientID = "keycloakMiddleware"
	config.ClientSecret = "uc0yKKpQsOqhggsG4eK7mDU3glT81chn"
	_, err = New(context.TODO(), handlerFunc, config, "keycloak-openid")
	if err == nil {
		t.Fatal("should fail because no KeycloakURL")
	}

	config = CreateConfig()
	config.KeycloakURL = "ftp://test.com"
	config.KeycloakRealm = "bochsler"
	config.ClientID = "keycloakMiddleware"
	config.ClientSecret = "uc0yKKpQsOqhggsG4eK7mDU3glT81chn"
	_, err = New(context.TODO(), handlerFunc, config, "keycloak-openid")
	if err == nil {
		t.Fatal("should fail because invalid KeycloakURL")
	}

	config = CreateConfig()
	config.KeycloakURL = "auth.bochslerfinance.com"
	config.ClientID = "keycloakMiddleware"
	config.ClientSecret = "uc0yKKpQsOqhggsG4eK7mDU3glT81chn"
	_, err = New(context.TODO(), handlerFunc, config, "keycloak-openid")
	if err == nil {
		t.Fatal("should fail because no realm")
	}

	config = CreateConfig()
	config.KeycloakURL = "auth.bochslerfinance.com"
	config.KeycloakRealm = "bochsler"
	config.ClientSecret = "uc0yKKpQsOqhggsG4eK7mDU3glT81chn"
	_, err = New(context.TODO(), handlerFunc, config, "keycloak-openid")
	if err == nil {
		t.Fatal("should fail beacause no ClientID")
	}
}

func TestServeHTTP(t *testing.T) {
	// Setup
	config := CreateConfig()
	config.KeycloakURL = "auth.bochslerfinance.com"
	config.KeycloakRealm = "bochsler"
	config.ClientID = "keycloakMiddleware"
	config.ClientSecret = "uc0yKKpQsOqhggsG4eK7mDU3glT81chn"

	// Create a new instance of our middleware
	keycloakMiddleware, err := New(context.TODO(), http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusOK)
	}), config, "keycloak-openid")
	if err != nil {
		t.Fatal("Expected no error while creating keycloak middleware, got:", err)
	}

	fmt.Printf("%+v\n", keycloakMiddleware)
	req, err := http.NewRequest("GET", "http://guidelines.bochslerfinance.com/", nil)
	if err != nil {
		t.Fatal("Expected no error while creating http request, got:", err)
	}

	rw := httptest.NewRecorder()

	// Test
	keycloakMiddleware.ServeHTTP(rw, req)

	fmt.Printf("%+v\n", rw)
	fmt.Printf("==>>>%+v\n", req)
}
