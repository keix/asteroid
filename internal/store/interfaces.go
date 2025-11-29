package store

import (
	"context"

	"asteroid/internal/store/entity"
)

type ClientStore interface {
	GetClient(ctx context.Context, id string) (*entity.Client, error)
}

type AuthCodeStore interface {
	SaveAuthCode(ctx context.Context, code *entity.AuthCode) error
	GetAuthCode(ctx context.Context, code string) (*entity.AuthCode, error)
	DeleteAuthCode(ctx context.Context, code string) error
}

type TokenStore interface {
	SaveAccessToken(ctx context.Context, token *entity.AccessToken) error
	SaveRefreshToken(ctx context.Context, token *entity.RefreshToken) error
	GetRefreshToken(ctx context.Context, token string) (*entity.RefreshToken, error)
	DeleteRefreshToken(ctx context.Context, token string) error
}

type JWTStore interface {
	GenerateIDToken(ctx context.Context, userID, clientID, nonce string) (string, error)
}

type NonceStore interface {
	MarkNonceSeen(ctx context.Context, nonce string, clientID string) error
}

type Stores struct {
	Client   ClientStore
	AuthCode AuthCodeStore
	Token    TokenStore
	Nonce    NonceStore
	// Key and JWT stores removed - using signing.Manager instead
}
