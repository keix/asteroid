package authorize

// ErrorType defines types of domain errors (HTTP-agnostic)
type ErrorType int

const (
	ErrorInvalidRequest ErrorType = iota
	ErrorInvalidClient
	ErrorInvalidRedirectURI
	ErrorUnsupportedResponse
	ErrorInvalidScope
	ErrorAccessDenied
	ErrorServerError
)

// String returns string representation of error type
func (e ErrorType) String() string {
	switch e {
	case ErrorInvalidRequest:
		return "invalid_request"
	case ErrorInvalidClient:
		return "invalid_client"
	case ErrorInvalidRedirectURI:
		return "invalid_redirect_uri"
	case ErrorUnsupportedResponse:
		return "unsupported_response_type"
	case ErrorInvalidScope:
		return "invalid_scope"
	case ErrorAccessDenied:
		return "access_denied"
	case ErrorServerError:
		return "server_error"
	default:
		return "server_error"
	}
}
