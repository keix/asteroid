package store

import (
	"context"
	"errors"
	"sync"
	"time"
)

var (
	ErrUserNotFound     = errors.New("user not found")
	ErrClientNotFound   = errors.New("client not found")
	ErrAuthCodeNotFound = errors.New("auth code not found")
)

type MemoryUserStore struct {
	mu    sync.RWMutex
	users map[string]*User
	byEmail map[string]*User
}

func NewMemoryUserStore() *MemoryUserStore {
	return &MemoryUserStore{
		users:   make(map[string]*User),
		byEmail: make(map[string]*User),
	}
}

func (s *MemoryUserStore) GetUserByID(ctx context.Context, id string) (*User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	
	user, exists := s.users[id]
	if !exists {
		return nil, ErrUserNotFound
	}
	return user, nil
}

func (s *MemoryUserStore) GetUserByEmail(ctx context.Context, email string) (*User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	
	user, exists := s.byEmail[email]
	if !exists {
		return nil, ErrUserNotFound
	}
	return user, nil
}

func (s *MemoryUserStore) SaveUser(user *User) {
	s.mu.Lock()
	defer s.mu.Unlock()
	
	s.users[user.ID] = user
	s.byEmail[user.Email] = user
}

type MemoryClientStore struct {
	mu      sync.RWMutex
	clients map[string]*Client
}

func NewMemoryClientStore() *MemoryClientStore {
	return &MemoryClientStore{
		clients: make(map[string]*Client),
	}
}

func (s *MemoryClientStore) GetClient(ctx context.Context, id string) (*Client, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	
	client, exists := s.clients[id]
	if !exists {
		return nil, ErrClientNotFound
	}
	return client, nil
}

func (s *MemoryClientStore) SaveClient(client *Client) {
	s.mu.Lock()
	defer s.mu.Unlock()
	
	s.clients[client.ID] = client
}

type MemoryAuthCodeStore struct {
	mu    sync.RWMutex
	codes map[string]*AuthCode
}

func NewMemoryAuthCodeStore() *MemoryAuthCodeStore {
	store := &MemoryAuthCodeStore{
		codes: make(map[string]*AuthCode),
	}
	
	go store.cleanup()
	return store
}

func (s *MemoryAuthCodeStore) SaveAuthCode(ctx context.Context, code *AuthCode) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	
	s.codes[code.Code] = code
	return nil
}

func (s *MemoryAuthCodeStore) GetAuthCode(ctx context.Context, code string) (*AuthCode, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	
	authCode, exists := s.codes[code]
	if !exists {
		return nil, ErrAuthCodeNotFound
	}
	
	if time.Now().After(authCode.ExpiresAt) {
		return nil, ErrAuthCodeNotFound
	}
	
	return authCode, nil
}

func (s *MemoryAuthCodeStore) DeleteAuthCode(ctx context.Context, code string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	
	delete(s.codes, code)
	return nil
}

func (s *MemoryAuthCodeStore) cleanup() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	
	for range ticker.C {
		s.mu.Lock()
		now := time.Now()
		for code, authCode := range s.codes {
			if now.After(authCode.ExpiresAt) {
				delete(s.codes, code)
			}
		}
		s.mu.Unlock()
	}
}