package data

import (
	"testing"

	"asteroid/internal/store/entity"
)

func TestClientSecretEnvName(t *testing.T) {
	cases := map[string]string{
		"lady-glass":  "ASTEROID_CLIENT_SECRET_LADY_GLASS",
		"test-client": "ASTEROID_CLIENT_SECRET_TEST_CLIENT",
		"example.com": "ASTEROID_CLIENT_SECRET_EXAMPLE_COM",
		"CLIENT_1":    "ASTEROID_CLIENT_SECRET_CLIENT_1",
		"mixed.Case":  "ASTEROID_CLIENT_SECRET_MIXED_CASE",
	}
	for in, want := range cases {
		if got := clientSecretEnvName(in); got != want {
			t.Errorf("clientSecretEnvName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestResolveClientSecret_LiteralSecret_LeftUnchanged(t *testing.T) {
	c := &entity.Client{ID: "svc", ClientType: "confidential", Secret: "literal-secret"}
	if err := resolveClientSecret(c); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.Secret != "literal-secret" {
		t.Errorf("Secret was mutated: %q", c.Secret)
	}
}

func TestResolveClientSecret_EmptySecret_ResolvesFromEnv(t *testing.T) {
	t.Setenv("ASTEROID_CLIENT_SECRET_LADY_GLASS", "from-env")
	c := &entity.Client{ID: "lady-glass", ClientType: "confidential"}

	if err := resolveClientSecret(c); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.Secret != "from-env" {
		t.Errorf("Secret was not populated from env: %q", c.Secret)
	}
}

func TestResolveClientSecret_EmptySecret_EnvUnset_ReturnsError(t *testing.T) {
	t.Setenv("ASTEROID_CLIENT_SECRET_LADY_GLASS", "")
	c := &entity.Client{ID: "lady-glass", ClientType: "confidential"}

	if err := resolveClientSecret(c); err == nil {
		t.Fatal("expected error when env var is empty")
	}
}

func TestResolveClientSecret_PublicClient_NoSecretRequired(t *testing.T) {
	// Public clients (PKCE-only) legitimately have no secret; the loader
	// must not demand an env var for them.
	c := &entity.Client{ID: "mobile-app", ClientType: "public"}
	if err := resolveClientSecret(c); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.Secret != "" {
		t.Errorf("public client should have no secret, got %q", c.Secret)
	}
}

func TestResolveClientSecret_ConfidentialByDefault_RequiresSecret(t *testing.T) {
	// Client type omitted → treated as confidential; empty secret with
	// unset env must be fatal.
	c := &entity.Client{ID: "svc"}
	if err := resolveClientSecret(c); err == nil {
		t.Fatal("expected error for confidential-by-default client with no secret")
	}
}
