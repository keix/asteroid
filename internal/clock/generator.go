package clock

import "github.com/google/uuid"

// Generator provides ID generation for deterministic testing
type Generator interface {
	NewCode() string
	NewToken() string
}

// UUIDGenerator generates UUIDs for production use
type UUIDGenerator struct{}

func (UUIDGenerator) NewCode() string {
	return uuid.NewString()
}

func (UUIDGenerator) NewToken() string {
	return uuid.NewString()
}

// FixedGenerator returns fixed values for testing
type FixedGenerator struct {
	Code  string
	Token string
	index int
}

func (g *FixedGenerator) NewCode() string {
	return g.Code
}

func (g *FixedGenerator) NewToken() string {
	if g.index == 0 {
		g.index++
		return g.Token
	}
	return g.Token + "-refresh"
}
