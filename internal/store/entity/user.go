package entity

import "time"

// User represents a user entity in the system
type User struct {
	ID           string    `json:"id" yaml:"id"`
	Email        string    `json:"email" yaml:"email"`
	PasswordHash string    `json:"password_hash" yaml:"password_hash"`
	CreatedAt    time.Time `json:"created_at" yaml:"created_at"`
}
