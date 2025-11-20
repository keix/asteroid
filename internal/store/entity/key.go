package entity

import "crypto/rsa"

type Key struct {
	PrivateKey *rsa.PrivateKey
	KID        string
}