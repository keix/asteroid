package store

import (
	"context"
	"crypto/rsa"

	"asteroid/internal/store/entity"
)

type UserStore interface {
	GetUserByID(ctx context.Context, id string) (*entity.User, error)
	GetUserByEmail(ctx context.Context, email string) (*entity.User, error)
}

type ClientStore interface {
	GetClient(ctx context.Context, id string) (*entity.Client, error)
}

type KeyStore interface {
	GetSigningKey(ctx context.Context) (*rsa.PrivateKey, error)
	GetKid(ctx context.Context) (string, error)
}

type AuthCodeStore interface {
	SaveAuthCode(ctx context.Context, code *entity.AuthCode) error
	GetAuthCode(ctx context.Context, code string) (*entity.AuthCode, error)
	DeleteAuthCode(ctx context.Context, code string) error
}
