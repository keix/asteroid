package key

import "crypto/rsa"

type KeyProvider interface {
	PublicKey() *rsa.PublicKey
	Kid() string
	Sign(payload []byte) ([]byte, error)
}
