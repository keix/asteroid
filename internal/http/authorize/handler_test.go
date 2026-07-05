package authorize

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"asteroid/internal/clock"
	"asteroid/internal/store/entity"
	"asteroid/internal/store/memory"
	"asteroid/internal/userinfo/source"
	"github.com/gin-gonic/gin"
)

func setupTestAuthorizeHandler() (*Handler, *memory.ClientStore, *memory.AuthCodeStore, *memory.NonceStore) {
	// Create test stores
	clk := clock.RealClock{}
	clientStore := memory.NewClientStore()
	authCodeStore := memory.NewAuthCodeStore(context.Background(), clk)
	nonceStore := memory.NewNonceStore(context.Background(), clk)

	// Add test client
	testClient := &entity.Client{
		ID:                      "test-client",
		Secret:                  "test-secret",
		RedirectURIs:            []string{"http://localhost:3000/callback"},
		Name:                    "Test Client",
		TokenEndpointAuthMethod: "client_secret_post",
		ClientType:              "confidential",
	}
	clientStore.SaveClient(context.Background(), testClient)

	// Add public client
	publicClient := &entity.Client{
		ID:           "public-client",
		RedirectURIs: []string{"http://localhost:3000/callback"},
		Name:         "Public Client",
		ClientType:   "public",
	}
	clientStore.SaveClient(context.Background(), publicClient)

	// Create userinfo provider
	userinfoProvider := source.NewYAMLProvider("../../../data/users.yaml")

	// Create handler
	handler := NewHandler(clientStore, authCodeStore, nonceStore, userinfoProvider)

	return handler, clientStore, authCodeStore, nonceStore
}

func TestAuthorizeHandler_MissingRequiredParams(t *testing.T) {
	handler, _, _, _ := setupTestAuthorizeHandler()

	// Set up Gin
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/authorize", handler.Handle)

	tests := []struct {
		name           string
		params         url.Values
		expectRedirect bool
	}{
		{
			name: "missing client_id",
			params: url.Values{
				"redirect_uri":  []string{"http://localhost:3000/callback"},
				"response_type": []string{"code"},
				"scope":         []string{"openid"},
				"state":         []string{"test-state"},
			},
			expectRedirect: false,
		},
		{
			name: "missing redirect_uri",
			params: url.Values{
				"client_id":     []string{"test-client"},
				"response_type": []string{"code"},
				"scope":         []string{"openid"},
				"state":         []string{"test-state"},
			},
			expectRedirect: false,
		},
		{
			name: "missing state",
			params: url.Values{
				"client_id":     []string{"test-client"},
				"redirect_uri":  []string{"http://localhost:3000/callback"},
				"response_type": []string{"code"},
				"scope":         []string{"openid"},
			},
			expectRedirect: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/authorize?"+tt.params.Encode(), nil)
			req.Header.Set("X-Authenticated-User", "user-123")
			w := httptest.NewRecorder()

			r.ServeHTTP(w, req)

			if tt.expectRedirect {
				// RFC 6749: redirect with error if redirect_uri is valid
				if w.Code != http.StatusFound {
					t.Errorf("Expected status 302 (redirect), got %d", w.Code)
				}
				location := w.Header().Get("Location")
				if !strings.Contains(location, "error=invalid_request") {
					t.Errorf("Expected error=invalid_request in redirect URL: %s", location)
				}
			} else {
				// No valid redirect_uri, return direct error
				if w.Code != http.StatusBadRequest {
					t.Errorf("Expected status 400, got %d", w.Code)
				}
				if !strings.Contains(w.Body.String(), "invalid_request") {
					t.Errorf("Expected invalid_request error in response body")
				}
			}
		})
	}
}

func TestAuthorizeHandler_InvalidClient(t *testing.T) {
	handler, _, _, _ := setupTestAuthorizeHandler()

	// Set up Gin
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/authorize", handler.Handle)

	params := url.Values{
		"client_id":     []string{"invalid-client"},
		"redirect_uri":  []string{"http://localhost:3000/callback"},
		"response_type": []string{"code"},
		"scope":         []string{"openid"},
		"state":         []string{"test-state"},
		"nonce":         []string{"test-nonce"},
	}

	req := httptest.NewRequest("GET", "/authorize?"+params.Encode(), nil)
	req.Header.Set("X-Authenticated-User", "user-123")
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	// An untrusted redirect URI must never be used when the client is invalid.
	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401, got %d", w.Code)
	}
	if location := w.Header().Get("Location"); location != "" {
		t.Errorf("Expected no redirect, got %s", location)
	}
	if !strings.Contains(w.Body.String(), "unauthorized_client") {
		t.Errorf("Expected unauthorized_client response: %s", w.Body.String())
	}
}

func TestAuthorizeHandler_PostRequest(t *testing.T) {
	handler, _, _, _ := setupTestAuthorizeHandler()

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.POST("/authorize", handler.Handle)

	params := url.Values{
		"client_id":     {"test-client"},
		"redirect_uri":  {"http://localhost:3000/callback"},
		"response_type": {"code"},
		"scope":         {"openid"},
		"state":         {"post-state"},
	}
	req := httptest.NewRequest(http.MethodPost, "/authorize", strings.NewReader(params.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Authenticated-User", "user-123")
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	if w.Code != http.StatusFound {
		t.Fatalf("Expected status 302, got %d: %s", w.Code, w.Body.String())
	}
	location, err := url.Parse(w.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if location.Query().Get("code") == "" || location.Query().Get("state") != "post-state" {
		t.Fatalf("Unexpected authorization response: %s", location.String())
	}
}

func TestAuthorizeHandler_PublicClientRequiresPKCE(t *testing.T) {
	handler, _, _, _ := setupTestAuthorizeHandler()

	// Set up Gin
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/authorize", handler.Handle)

	// Public client without PKCE should fail
	params := url.Values{
		"client_id":     []string{"public-client"},
		"redirect_uri":  []string{"http://localhost:3000/callback"},
		"response_type": []string{"code"},
		"scope":         []string{"openid"},
		"state":         []string{"test-state"},
		"nonce":         []string{"test-nonce"},
	}

	req := httptest.NewRequest("GET", "/authorize?"+params.Encode(), nil)
	req.Header.Set("X-Authenticated-User", "user-123")
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	// RFC 6749: redirect with error since redirect_uri is provided
	if w.Code != http.StatusFound {
		t.Errorf("Expected status 302 (redirect), got %d", w.Code)
	}
	location := w.Header().Get("Location")
	if !strings.Contains(location, "error=invalid_request") {
		t.Errorf("Expected error=invalid_request in redirect URL: %s", location)
	}
}

func TestAuthorizeHandler_ValidAuthorizeRequest(t *testing.T) {
	handler, _, _, _ := setupTestAuthorizeHandler()

	// Set up Gin
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/authorize", handler.Handle)

	params := url.Values{
		"client_id":     []string{"test-client"},
		"redirect_uri":  []string{"http://localhost:3000/callback"},
		"response_type": []string{"code"},
		"scope":         []string{"openid"},
		"state":         []string{"test-state"},
		"nonce":         []string{"test-nonce"},
	}

	req := httptest.NewRequest("GET", "/authorize?"+params.Encode(), nil)
	req.Header.Set("X-Authenticated-User", "user-123")
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	if w.Code != http.StatusFound {
		t.Errorf("Expected status 302, got %d. Response: %s", w.Code, w.Body.String())
	}

	location := w.Header().Get("Location")
	if !strings.Contains(location, "http://localhost:3000/callback") {
		t.Errorf("Expected redirect to callback URL, got %s", location)
	}

	if !strings.Contains(location, "code=") {
		t.Error("Expected code parameter in redirect URL")
	}

	if !strings.Contains(location, "state=test-state") {
		t.Error("Expected state parameter in redirect URL")
	}
}

func TestAuthorizeHandler_NoAuthenticationHeader(t *testing.T) {
	handler, _, _, _ := setupTestAuthorizeHandler()

	// Set up Gin
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/authorize", handler.Handle)

	params := url.Values{
		"client_id":     []string{"test-client"},
		"redirect_uri":  []string{"http://localhost:3000/callback"},
		"response_type": []string{"code"},
		"scope":         []string{"openid"},
		"state":         []string{"test-state"},
		"nonce":         []string{"test-nonce"},
	}

	req := httptest.NewRequest("GET", "/authorize?"+params.Encode(), nil)
	// No X-Authenticated-User header
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	// RFC 6749: redirect with error since redirect_uri is provided
	if w.Code != http.StatusFound {
		t.Errorf("Expected status 302 (redirect), got %d", w.Code)
	}
	location := w.Header().Get("Location")
	if !strings.Contains(location, "error=access_denied") {
		t.Errorf("Expected error=access_denied in redirect URL: %s", location)
	}
}
