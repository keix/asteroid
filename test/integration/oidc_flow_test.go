package test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"asteroid/internal/config"
	"asteroid/internal/crypto/persister"
	httpx "asteroid/internal/http"
	"asteroid/internal/loader/data"
	"asteroid/internal/oidc/signing"
	"asteroid/internal/store"
	"asteroid/internal/store/memory"
	"asteroid/internal/userinfo/source"
	"github.com/gin-gonic/gin"
)

// IntegrationTest tests the complete OIDC flow
func TestOIDCIntegrationFlow(t *testing.T) {
	// Setup test server
	server := setupTestServer(t)

	// Test complete OIDC authorization code flow
	t.Run("Complete_OIDC_Authorization_Code_Flow", func(t *testing.T) {
		// Step 1: Authorize request
		authCode := testAuthorizeEndpoint(t, server)

		// Step 2: Token exchange
		tokenResponse := testTokenEndpoint(t, server, authCode)

		// Step 3: Verify JWKS endpoint
		testJWKSEndpoint(t, server)

		// Step 4: Verify well-known endpoint
		testWellKnownEndpoint(t, server)

		// Step 5: Refresh token flow
		testRefreshTokenFlow(t, server, tokenResponse.RefreshToken)
	})
}

type TestServer struct {
	Router *gin.Engine
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	Scope        string `json:"scope"`
}

func setupTestServer(t *testing.T) *TestServer {
	gin.SetMode(gin.TestMode)

	// Create memory stores
	ctx := context.Background()
	stores := &store.Stores{
		Client:   memory.NewClientStore(),
		AuthCode: memory.NewAuthCodeStore(),
		Token:    memory.NewTokenStore(ctx),
		Nonce:    memory.NewNonceStore(ctx),
	}

	// Load test data
	loader := data.NewLoader("../../data")
	if err := loader.LoadAll(ctx, stores); err != nil {
		t.Fatalf("Failed to load test data: %v", err)
	}

	// Create userinfo provider
	userinfoProvider := source.NewYAMLProvider("../../data/users.yaml")

	// Create signing service
	filePersister := persister.New("/tmp/test-keys-integration")
	signingService := signing.NewService(ctx, filePersister, 15*time.Minute, 1*time.Hour)

	// Create test config
	cfg := config.Config{
		Issuer: "http://localhost:8880",
	}

	// Setup router
	r := gin.New()
	r.Use(gin.Recovery())
	httpx.RegisterRoutes(r, cfg, stores, userinfoProvider, signingService)

	return &TestServer{Router: r}
}

func testAuthorizeEndpoint(t *testing.T, server *TestServer) string {
	// Create authorize request
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

	server.Router.ServeHTTP(w, req)

	if w.Code != http.StatusFound {
		t.Fatalf("Authorize request failed. Status: %d, Body: %s", w.Code, w.Body.String())
	}

	// Extract auth code from redirect URL
	location := w.Header().Get("Location")
	redirectURL, err := url.Parse(location)
	if err != nil {
		t.Fatalf("Failed to parse redirect URL: %v", err)
	}

	authCode := redirectURL.Query().Get("code")
	if authCode == "" {
		t.Fatal("Auth code not found in redirect URL")
	}

	state := redirectURL.Query().Get("state")
	if state != "test-state" {
		t.Errorf("Expected state 'test-state', got '%s'", state)
	}

	return authCode
}

func testTokenEndpoint(t *testing.T, server *TestServer, authCode string) *TokenResponse {
	// Create token exchange request
	data := url.Values{
		"grant_type":    []string{"authorization_code"},
		"code":          []string{authCode},
		"client_id":     []string{"test-client"},
		"client_secret": []string{"test-secret"},
		"redirect_uri":  []string{"http://localhost:3000/callback"},
	}

	req := httptest.NewRequest("POST", "/token", strings.NewReader(data.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	server.Router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Token exchange failed. Status: %d, Body: %s", w.Code, w.Body.String())
	}

	var tokenResponse TokenResponse
	if err := json.Unmarshal(w.Body.Bytes(), &tokenResponse); err != nil {
		t.Fatalf("Failed to parse token response: %v", err)
	}

	// Verify token response structure
	if tokenResponse.AccessToken == "" {
		t.Error("Access token is empty")
	}
	if tokenResponse.TokenType != "Bearer" {
		t.Errorf("Expected token type 'Bearer', got '%s'", tokenResponse.TokenType)
	}
	if tokenResponse.RefreshToken == "" {
		t.Error("Refresh token is empty")
	}
	if tokenResponse.IDToken == "" {
		t.Error("ID token is empty")
	}

	return &tokenResponse
}

func testJWKSEndpoint(t *testing.T, server *TestServer) {
	req := httptest.NewRequest("GET", "/jwks.json", nil)
	w := httptest.NewRecorder()

	server.Router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("JWKS request failed. Status: %d, Body: %s", w.Code, w.Body.String())
	}

	var jwks map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &jwks); err != nil {
		t.Fatalf("Failed to parse JWKS response: %v", err)
	}

	keys, ok := jwks["keys"].([]interface{})
	if !ok || len(keys) == 0 {
		t.Error("JWKS should contain at least one key")
	}
}

func testWellKnownEndpoint(t *testing.T, server *TestServer) {
	req := httptest.NewRequest("GET", "/.well-known/openid-configuration", nil)
	w := httptest.NewRecorder()

	server.Router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Well-known request failed. Status: %d, Body: %s", w.Code, w.Body.String())
	}

	var config map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &config); err != nil {
		t.Fatalf("Failed to parse well-known response: %v", err)
	}

	// Verify required OpenID Connect configuration
	requiredFields := []string{
		"issuer",
		"authorization_endpoint",
		"token_endpoint",
		"jwks_uri",
		"response_types_supported",
		"subject_types_supported",
		"id_token_signing_alg_values_supported",
	}

	for _, field := range requiredFields {
		if _, exists := config[field]; !exists {
			t.Errorf("Missing required field in well-known config: %s", field)
		}
	}
}

func testRefreshTokenFlow(t *testing.T, server *TestServer, refreshToken string) {
	// Create refresh token request
	data := url.Values{
		"grant_type":    []string{"refresh_token"},
		"refresh_token": []string{refreshToken},
		"client_id":     []string{"test-client"},
		"client_secret": []string{"test-secret"},
	}

	req := httptest.NewRequest("POST", "/token", strings.NewReader(data.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	server.Router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Refresh token request failed. Status: %d, Body: %s", w.Code, w.Body.String())
	}

	var tokenResponse TokenResponse
	if err := json.Unmarshal(w.Body.Bytes(), &tokenResponse); err != nil {
		t.Fatalf("Failed to parse refresh token response: %v", err)
	}

	// Verify new token response
	if tokenResponse.AccessToken == "" {
		t.Error("New access token is empty")
	}
	if tokenResponse.RefreshToken == "" {
		t.Error("New refresh token is empty")
	}
}
