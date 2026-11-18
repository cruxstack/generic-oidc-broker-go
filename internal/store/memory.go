package store

import (
	"context"
	"sync"
	"time"
)

// sweepInterval is how often Save removes expired codes from memory.
const sweepInterval = time.Minute

// Memory keeps authorization codes in process memory. Use it only when a
// single broker instance serves all requests.
type Memory struct {
	mu        sync.Mutex
	codes     map[string]memoryEntry
	nextSweep time.Time
	now       func() time.Time
}

type memoryEntry struct {
	data      AuthCode
	expiresAt time.Time
}

// NewMemory returns an empty in-memory store.
func NewMemory() *Memory {
	return &Memory{codes: map[string]memoryEntry{}, now: time.Now}
}

// Save stores data under code for AuthCodeTTL.
func (m *Memory) Save(_ context.Context, code string, data AuthCode) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := m.now()
	m.sweepExpired(now)
	m.codes[code] = memoryEntry{data: data, expiresAt: now.Add(AuthCodeTTL)}
	return nil
}

// Consume removes the code and returns its data, or ErrNotFound.
func (m *Memory) Consume(_ context.Context, code string) (AuthCode, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	entry, ok := m.codes[code]
	delete(m.codes, code)
	if !ok || m.now().After(entry.expiresAt) {
		return AuthCode{}, ErrNotFound
	}
	return entry.data, nil
}

// Close implements AuthCodes. It has nothing to release.
func (m *Memory) Close() error { return nil }

// sweepExpired drops expired codes at most once per sweepInterval, so that
// codes which are never redeemed don't accumulate.
func (m *Memory) sweepExpired(now time.Time) {
	if now.Before(m.nextSweep) {
		return
	}
	for code, entry := range m.codes {
		if now.After(entry.expiresAt) {
			delete(m.codes, code)
		}
	}
	m.nextSweep = now.Add(sweepInterval)
}
