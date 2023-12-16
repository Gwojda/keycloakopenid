package traefik_oidc_relying_party

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
	config.ProviderURL = "auth.bochslerfinance.com"
	config.ClientID = "ProviderMiddleware"
	config.ClientSecret = "uc0yKKpQsOqhggsG4eK7mDU3glT81chn"

	// Create a new instance of our middleware
	ProviderMiddleware, err := New(context.TODO(), http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusOK)
	}), config, "provider-openid")
	if err != nil {
		t.Fatal("Expected no error while creating OpenID Provider middleware, got:", err)
	}

	fmt.Printf("%+v\n", ProviderMiddleware)
	req, err := http.NewRequest("GET", "http://guidelines.bochslerfinance.com/", nil)
	if err != nil {
		t.Fatal("Expected no error while creating http request, got:", err)
	}

	rw := httptest.NewRecorder()

	// Test
	ProviderMiddleware.ServeHTTP(rw, req)

	fmt.Printf("%+v\n", rw)
	fmt.Printf("==>>>%+v\n", req)
}
