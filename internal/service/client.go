package service

import (
	"crypto/subtle"

	"github.com/cruxstack/generic-oidc-broker/internal/config"
)

// ClientService handles OIDC client validation.
type ClientService struct {
	cfg *config.Config
}

// NewClientService creates a new client service.
func NewClientService(cfg *config.Config) *ClientService {
	return &ClientService{cfg: cfg}
}

// GetClient returns a client by ID, or nil if not found.
func (s *ClientService) GetClient(clientID string) *config.Client {
	for i := range s.cfg.OIDCClients {
		if s.cfg.OIDCClients[i].ClientID == clientID {
			return &s.cfg.OIDCClients[i]
		}
	}
	return nil
}

// ValidateClient validates client credentials.
// Returns true if the client exists and the secret matches.
// Uses constant-time comparison to prevent timing attacks.
func (s *ClientService) ValidateClient(clientID, clientSecret string) bool {
	client := s.GetClient(clientID)
	if client == nil {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(client.ClientSecret), []byte(clientSecret)) == 1
}

// ValidateRedirectURI checks if a redirect URI is registered for the client.
func (s *ClientService) ValidateRedirectURI(clientID, redirectURI string) bool {
	client := s.GetClient(clientID)
	if client == nil {
		return false
	}

	for _, uri := range client.RedirectURIs {
		if uri == redirectURI {
			return true
		}
	}
	return false
}
