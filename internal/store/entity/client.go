package entity

// Client represents an OAuth 2.0 client entity
type Client struct {
	ID           string   `json:"id" dynamodbav:"id"`
	Secret       string   `json:"secret" dynamodbav:"secret"`
	RedirectURIs []string `json:"redirect_uris" dynamodbav:"redirect_uris"`
	Name         string   `json:"name" dynamodbav:"name"`
}
