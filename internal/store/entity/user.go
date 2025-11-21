package entity

import "time"

// User represents a user entity in the system
type User struct {
	ID           string    `json:"id" dynamodbav:"id"`
	Email        string    `json:"email" dynamodbav:"email"`
	PasswordHash string    `json:"password_hash" dynamodbav:"password_hash"`
	CreatedAt    time.Time `json:"created_at" dynamodbav:"created_at"`
}
