package store

import (
	"context"
	"crypto/rsa"
)

type UserStore interface {
	GetUserByID(ctx context.Context, id string) (*User, error)
	GetUserByEmail(ctx context.Context, email string) (*User, error)
}

type ClientStore interface {
	GetClient(ctx context.Context, id string) (*Client, error)
}

type KeyStore interface {
	GetSigningKey(ctx context.Context) (*rsa.PrivateKey, error)
	GetKid(ctx context.Context) (string, error)
}

type AuthCodeStore interface {
	SaveAuthCode(ctx context.Context, code *AuthCode) error
	GetAuthCode(ctx context.Context, code string) (*AuthCode, error)
	DeleteAuthCode(ctx context.Context, code string) error
}