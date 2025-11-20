package memory

import (
	"context"
	"sync"

	"asteroid/internal/store/entity"
)

type UserStore struct {
	mu      sync.RWMutex
	users   map[string]*entity.User
	byEmail map[string]*entity.User
}

func NewUserStore() *UserStore {
	return &UserStore{
		users:   make(map[string]*entity.User),
		byEmail: make(map[string]*entity.User),
	}
}

func (s *UserStore) GetUserByID(ctx context.Context, id string) (*entity.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	user, exists := s.users[id]
	if !exists {
		return nil, entity.ErrUserNotFound
	}
	return user, nil
}

func (s *UserStore) GetUserByEmail(ctx context.Context, email string) (*entity.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	user, exists := s.byEmail[email]
	if !exists {
		return nil, entity.ErrUserNotFound
	}
	return user, nil
}

func (s *UserStore) SaveUser(user *entity.User) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.users[user.ID] = user
	s.byEmail[user.Email] = user
}