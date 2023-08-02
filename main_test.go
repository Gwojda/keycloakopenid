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
	config.KeycloakReaml = "bochsler"
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
	req, err := http.NewRequest("GET", "https://guidelines.bochslerfinance.com/?state=eyJyZWRpcmVjdF91cmwiOiJodHRwczovL2d1aWRlbGluZXMuYm9jaHNsZXJmaW5hbmNlLmNvbS8ifQ%3D%3D&session_state=da5e569c-aca9-4ea4-a7d7-35eda0fbd3e6&code=24674ca1-f454-4d3a-87cf-2d3b44a73a88.da5e569c-aca9-4ea4-a7d7-35eda0fbd3e6.c54dbe59-cadf-479e-a940-5f58513ee61e", nil)
	if err != nil {
		t.Fatal("Expected no error while creating http request, got:", err)
	}

	rw := httptest.NewRecorder()

	// Test
	keycloakMiddleware.ServeHTTP(rw, req)

	fmt.Printf("%+v\n", rw)
	fmt.Printf("==>>>%+v\n", req)
}
