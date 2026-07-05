package data

import (
	"context"
	"fmt"
	"os"
	"strings"

	"asteroid/internal/store"
	"asteroid/internal/store/entity"
	"gopkg.in/yaml.v3"
)

// clientSecretEnvPrefix is the prefix used when deriving the env var
// that holds a confidential client's secret from its ID. See
// resolveClientSecret for the derivation rules.
const clientSecretEnvPrefix = "ASTEROID_CLIENT_SECRET_"

// ClientData represents the structure of clients.yaml
type ClientData struct {
	Clients []entity.Client `yaml:"clients"`
}

// ClientLoader handles loading clients from YAML files
type ClientLoader struct {
	filepath string
}

// NewClientLoader creates a new client loader
func NewClientLoader(filepath string) *ClientLoader {
	return &ClientLoader{
		filepath: filepath,
	}
}

// Load reads clients from YAML file and saves to store
func (l *ClientLoader) Load(ctx context.Context, stores *store.Stores) error {
	data, err := os.ReadFile(l.filepath)
	if err != nil {
		return err
	}

	var clientData ClientData
	if err := yaml.Unmarshal(data, &clientData); err != nil {
		return err
	}

	for i := range clientData.Clients {
		if err := resolveClientSecret(&clientData.Clients[i]); err != nil {
			return err
		}
	}

	// Type assert to access SaveClient method
	if clientStore, ok := stores.Client.(interface {
		SaveClient(context.Context, *entity.Client) error
	}); ok {
		for i := range clientData.Clients {
			client := &clientData.Clients[i]
			if err := clientStore.SaveClient(ctx, client); err != nil {
				return err
			}
		}
	}

	return nil
}

// resolveClientSecret fills in a confidential client's Secret from an
// environment variable when the YAML file does not carry a literal
// value. The derived env var name is ASTEROID_CLIENT_SECRET_<ID>, where
// <ID> is the client ID upper-cased with every non-alphanumeric byte
// replaced by an underscore. Missing or empty env vars are a fatal
// load-time error so the server never starts with a silently
// unauthenticated client.
//
// This keeps deployment configuration (clients.yaml) free of secret
// material or references to it. The env var itself is provisioned
// out-of-band, typically by a systemd ExecStartPre that fetches from a
// secret store into a tmpfs EnvironmentFile.
func resolveClientSecret(c *entity.Client) error {
	if !c.IsConfidentialClient() {
		return nil
	}
	if c.Secret != "" {
		return nil
	}
	envName := clientSecretEnvName(c.ID)
	v := os.Getenv(envName)
	if v == "" {
		return fmt.Errorf("client %q: env var %q is unset or empty", c.ID, envName)
	}
	c.Secret = v
	return nil
}

// clientSecretEnvName derives the env var name that holds the secret
// for the given client ID. The mapping is stable: upper-case, and any
// byte outside [A-Z0-9] becomes '_'. Callers stay in sync with
// deployment tooling by using this same helper.
func clientSecretEnvName(clientID string) string {
	var b strings.Builder
	b.Grow(len(clientSecretEnvPrefix) + len(clientID))
	b.WriteString(clientSecretEnvPrefix)
	for _, r := range clientID {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r - 'a' + 'A')
		case r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	return b.String()
}
