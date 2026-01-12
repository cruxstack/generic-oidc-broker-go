package store

import (
	"sync"
	"time"

	"github.com/cruxstack/generic-oidc-broker/internal/provider"
)

// AuthCodeTTL is the time-to-live for authorization codes (10 minutes per OAuth 2.0 spec recommendation).
const AuthCodeTTL = 10 * time.Minute

// AuthCodeCleanupInterval is how often expired codes are cleaned up from memory.
const AuthCodeCleanupInterval = 1 * time.Minute

// AuthCodeData holds the data associated with an authorization code.
type AuthCodeData struct {
	ClientID    string
	RedirectURI string
	Nonce       string
	UserData    *provider.UserData
	Scope       string
	Issuer      string // Optional: provider-scoped issuer override
	ExpiresAt   time.Time
}

// AuthCodeStore defines the interface for authorization code storage.
type AuthCodeStore interface {
	// Store saves an authorization code with its associated data.
	Store(code string, data *AuthCodeData) error

	// Get retrieves and deletes the data for an authorization code.
	// Returns nil if the code doesn't exist or has expired.
	Get(code string) (*AuthCodeData, error)
}

// MemoryAuthCodeStore is an in-memory implementation of AuthCodeStore.
type MemoryAuthCodeStore struct {
	mu     sync.RWMutex
	codes  map[string]*AuthCodeData
	stopCh chan struct{}
}

// NewMemoryAuthCodeStore creates a new in-memory auth code store.
func NewMemoryAuthCodeStore() *MemoryAuthCodeStore {
	store := &MemoryAuthCodeStore{
		codes:  make(map[string]*AuthCodeData),
		stopCh: make(chan struct{}),
	}

	// Start cleanup goroutine
	go store.cleanup()

	return store
}

// Close stops the cleanup goroutine.
func (s *MemoryAuthCodeStore) Close() error {
	close(s.stopCh)
	return nil
}

// Store saves an authorization code with its associated data.
func (s *MemoryAuthCodeStore) Store(code string, data *AuthCodeData) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	data.ExpiresAt = time.Now().Add(AuthCodeTTL)
	s.codes[code] = data

	return nil
}

// Get retrieves and deletes the data for an authorization code.
// Returns nil if the code doesn't exist or has expired.
func (s *MemoryAuthCodeStore) Get(code string) (*AuthCodeData, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, exists := s.codes[code]
	if !exists {
		return nil, nil
	}

	// Delete the code (single use)
	delete(s.codes, code)

	// Check if expired
	if time.Now().After(data.ExpiresAt) {
		return nil, nil
	}

	return data, nil
}

// cleanup periodically removes expired codes.
func (s *MemoryAuthCodeStore) cleanup() {
	ticker := time.NewTicker(AuthCodeCleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-s.stopCh:
			return
		case <-ticker.C:
			s.mu.Lock()
			now := time.Now()
			for code, data := range s.codes {
				if now.After(data.ExpiresAt) {
					delete(s.codes, code)
				}
			}
			s.mu.Unlock()
		}
	}
}
