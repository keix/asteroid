package entity

// Client represents an OAuth 2.0 client entity
type Client struct {
	ID           string   `json:"id"`
	Secret       string   `json:"secret"`
	RedirectURIs []string `json:"redirect_uris"`
	Name         string   `json:"name"`
}