package token

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"asteroid/internal/clock"
	"asteroid/internal/crypto/persister"
	"asteroid/internal/oidc/signing"
	"asteroid/internal/store/entity"
	"asteroid/internal/store/memory"
	"asteroid/internal/userinfo/source"
	"github.com/gin-gonic/gin"
)

func setupTestHandler(t *testing.T) (*Handler, *memory.ClientStore, *memory.AuthCodeStore, *memory.TokenStore, *memory.NonceStore) {
	// Create test stores
	clk := clock.RealClock{}
	clientStore := memory.NewClientStore()
	authCodeStore := memory.NewAuthCodeStore(context.Background(), clk)
	tokenStore := memory.NewTokenStore(context.Background(), clk)
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

	// Create userinfo provider
	userinfoProvider := source.NewYAMLProvider("../../../data/users.yaml")

	// Create signing service backed by a per-test temp dir to avoid cross-test pollution
	filePersister := persister.New(t.TempDir())
	signingService := signing.NewService(context.Background(), filePersister, 15*time.Minute, 1*time.Hour, clk)

	// Create handler
	handler := NewHandler(
		"http://localhost:8880",
		clientStore,
		authCodeStore,
		tokenStore,
		userinfoProvider,
		signingService,
	)

	return handler, clientStore, authCodeStore, tokenStore, nonceStore
}

func TestTokenHandler_MissingGrantType(t *testing.T) {
	handler, _, _, _, _ := setupTestHandler(t)

	// Set up Gin
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.POST("/token", handler.Handle)

	// Create request without grant_type
	data := url.Values{}
	data.Set("code", "test-code")
	data.Set("client_id", "test-client")

	req := httptest.NewRequest("POST", "/token", strings.NewReader(data.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", w.Code)
	}

	// Empty grant_type returns unsupported_grant_type as per current implementation
	if !strings.Contains(w.Body.String(), "unsupported_grant_type") {
		t.Errorf("Expected unsupported_grant_type error in response body, got: %s", w.Body.String())
	}
}

func TestTokenHandler_InvalidClient(t *testing.T) {
	handler, _, _, _, _ := setupTestHandler(t)

	// Set up Gin
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.POST("/token", handler.Handle)

	// Create request with invalid client (missing redirect_uri causes invalid_request)
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", "test-code")
	data.Set("client_id", "invalid-client")
	data.Set("client_secret", "wrong-secret")
	data.Set("redirect_uri", "http://localhost:3000/callback") // Add required parameter

	req := httptest.NewRequest("POST", "/token", strings.NewReader(data.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	// With all required params present, invalid client should return 401
	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401, got %d, Response: %s", w.Code, w.Body.String())
	}

	if !strings.Contains(w.Body.String(), "invalid_client") {
		t.Errorf("Expected invalid_client error in response body, got: %s", w.Body.String())
	}
}

func TestTokenHandler_InvalidBasicClientIncludesChallenge(t *testing.T) {
	handler, _, _, _, _ := setupTestHandler(t)

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.POST("/token", handler.Handle)

	data := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {"test-code"},
		"redirect_uri": {"http://localhost:3000/callback"},
	}
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(data.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("invalid-client", "wrong-secret")
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("Expected status 401, got %d", w.Code)
	}
	if got := w.Header().Get("WWW-Authenticate"); got != `Basic realm="token"` {
		t.Fatalf("Unexpected WWW-Authenticate header: %q", got)
	}
}

func TestTokenRequest_DecodesBasicCredentials(t *testing.T) {
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	req := httptest.NewRequest(http.MethodPost, "/token", nil)
	req.SetBasicAuth(url.QueryEscape("client:id"), url.QueryEscape("secret value"))
	c.Request = req

	parsed := NewRequest(c)

	if parsed.ClientID != "client:id" || parsed.ClientSecret != "secret value" {
		t.Fatalf("Basic credentials were not decoded: %#v", parsed)
	}
}

func TestTokenHandler_ValidTokenExchange(t *testing.T) {
	handler, _, authCodeStore, _, _ := setupTestHandler(t)

	// Add test auth code
	authCode := &entity.AuthCode{
		Code:                "test-auth-code",
		ClientID:            "test-client",
		UserID:              "user-123",
		RedirectURI:         "http://localhost:3000/callback",
		CodeChallenge:       "",
		CodeChallengeMethod: "",
		Scope:               "openid",
		State:               "test-state",
		Nonce:               "test-nonce",
		ExpiresAt:           time.Now().Add(5 * time.Minute),
	}
	authCodeStore.SaveAuthCode(context.Background(), authCode)

	// Set up Gin
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.POST("/token", handler.Handle)

	// Create valid token exchange request
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", "test-auth-code")
	data.Set("client_id", "test-client")
	data.Set("client_secret", "test-secret")
	data.Set("redirect_uri", "http://localhost:3000/callback")

	req := httptest.NewRequest("POST", "/token", strings.NewReader(data.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d. Response: %s", w.Code, w.Body.String())
	}

	responseBody := w.Body.String()
	if !strings.Contains(responseBody, "access_token") {
		t.Error("Expected access_token in response")
	}
	if !strings.Contains(responseBody, "token_type") {
		t.Error("Expected token_type in response")
	}
	if !strings.Contains(responseBody, "expires_in") {
		t.Error("Expected expires_in in response")
	}
	if got := w.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Expected Cache-Control no-store, got %q", got)
	}
	if got := w.Header().Get("Pragma"); got != "no-cache" {
		t.Errorf("Expected Pragma no-cache, got %q", got)
	}
}

func TestTokenHandler_RefreshTokenFlow(t *testing.T) {
	handler, _, _, tokenStore, _ := setupTestHandler(t)

	// Add test refresh token
	refreshToken := &entity.RefreshToken{
		Token:     "test-refresh-token",
		ClientID:  "test-client",
		UserID:    "user-123",
		Scope:     "openid",
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}
	tokenStore.SaveRefreshToken(context.Background(), refreshToken)

	// Set up Gin
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.POST("/token", handler.Handle)

	// Create refresh token request
	data := url.Values{}
	data.Set("grant_type", "refresh_token")
	data.Set("refresh_token", "test-refresh-token")
	data.Set("client_id", "test-client")
	data.Set("client_secret", "test-secret")

	req := httptest.NewRequest("POST", "/token", strings.NewReader(data.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d. Response: %s", w.Code, w.Body.String())
	}

	responseBody := w.Body.String()
	if !strings.Contains(responseBody, "access_token") {
		t.Error("Expected access_token in response")
	}
}
