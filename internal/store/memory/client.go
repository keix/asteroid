package memory

import (
	"context"
	"sync"

	"asteroid/internal/store/entity"
)

type ClientStore struct {
	mu      sync.RWMutex
	clients map[string]*entity.Client
}

func NewClientStore() *ClientStore {
	return &ClientStore{
		clients: make(map[string]*entity.Client),
	}
}

func (s *ClientStore) GetClient(ctx context.Context, id string) (*entity.Client, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	client, exists := s.clients[id]
	if !exists {
		return nil, entity.ErrClientNotFound
	}
	return client, nil
}

func (s *ClientStore) SaveClient(client *entity.Client) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.clients[client.ID] = client
}
