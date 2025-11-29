package source

import (
	"context"
	"maps"
	"os"
	"sync"

	"asteroid/internal/userinfo"

	"gopkg.in/yaml.v3"
)

// YAMLUser represents user data structure in YAML files
type YAMLUser struct {
	ID           string         `yaml:"id"`
	Email        string         `yaml:"email"`
	PasswordHash string         `yaml:"password_hash"`
	CreatedAt    string         `yaml:"created_at"`
	Claims       map[string]any `yaml:"claims,omitempty"` // Additional OIDC claims
}

// YAMLProvider loads user information from YAML files with lazy loading
type YAMLProvider struct {
	filepath string
	users    map[string]*YAMLUser // sub -> user mapping
	mu       sync.RWMutex
	loaded   bool
}

// NewYAMLProvider creates a new YAML-based userinfo provider
func NewYAMLProvider(filepath string) *YAMLProvider {
	return &YAMLProvider{
		filepath: filepath,
		users:    make(map[string]*YAMLUser),
	}
}

// Fetch retrieves user information by subject identifier
func (y *YAMLProvider) Fetch(ctx context.Context, sub string) (map[string]any, error) {
	if err := y.ensureLoaded(); err != nil {
		return nil, err
	}

	y.mu.RLock()
	user, exists := y.users[sub]
	y.mu.RUnlock()

	if !exists {
		return nil, userinfo.ErrUserNotFound
	}

	return y.buildUserInfo(user), nil
}

// ensureLoaded loads YAML data if not already loaded (lazy loading)
func (y *YAMLProvider) ensureLoaded() error {
	y.mu.Lock()
	defer y.mu.Unlock()

	if y.loaded {
		return nil
	}

	data, err := os.ReadFile(y.filepath)
	if err != nil {
		return err
	}

	var userList struct {
		Users []YAMLUser `yaml:"users"`
	}

	if err := yaml.Unmarshal(data, &userList); err != nil {
		return err
	}

	// Build subject -> user mapping
	for i := range userList.Users {
		user := userList.Users[i] // Copy value
		y.users[user.ID] = &user
	}

	y.loaded = true
	return nil
}

// buildUserInfo constructs userinfo response from YAML user data
func (y *YAMLProvider) buildUserInfo(user *YAMLUser) map[string]any {
	result := map[string]any{
		"sub":   user.ID,
		"email": user.Email,
	}

	// Merge additional claims if present
	if user.Claims != nil {
		maps.Copy(result, user.Claims)
	}

	return result
}

// Reload forces reload of YAML data (useful for development)
func (y *YAMLProvider) Reload() error {
	y.mu.Lock()
	defer y.mu.Unlock()

	y.loaded = false
	y.users = make(map[string]*YAMLUser)

	return y.ensureLoaded()
}
