package traefikkeycloak

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestServeHTTP(t *testing.T) {
	// Setup
	config := CreateConfig()
	config.KeycloakURL = "<URL>"
	config.ClientID = "<CLIENTID>"
	config.ClientSecret = "<CLIENT_SECRET>"

	// Create a new instance of our middleware
	keycloakMiddleware, err := New(context.TODO(), http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusOK)
	}), config, "keycloak-openid")
	if err != nil {
		t.Fatal("Expected no error while creating keycloak middleware, got:", err)
	}

	fmt.Printf("%+v\n", keycloakMiddleware)
	req, err := http.NewRequest("GET", "http://example.com/foo", nil)
	if err != nil {
		t.Fatal("Expected no error while creating http request, got:", err)
	}

	rw := httptest.NewRecorder()

	// Test
	keycloakMiddleware.ServeHTTP(rw, req)

	// Verify
	// Add your verification logic here. It might include checking response code, response headers etc.
	// For instance, if you expect a forbidden response in this scenario, you would do:
	if rw.Code != http.StatusForbidden {
		t.Error("Expected status forbidden, got:", rw.Code)
	}
}
