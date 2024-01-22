package keycloakopenid

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
	config.KeycloakURL = "auth.bochslerfinance.com"
	config.KeycloakRealm = "bochsler"
	config.ClientID = "keycloakMiddleware"
	config.ClientSecret = "uc0yKKpQsOqhggsG4eK7mDU3glT81chn"
	config.Scope = "openid profile email"

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
