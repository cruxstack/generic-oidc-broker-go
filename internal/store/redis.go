package store

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// Redis connection timeout.
const redisConnectTimeout = 10 * time.Second

// RedisAuthCodeStore is a Redis-backed implementation of AuthCodeStore.
type RedisAuthCodeStore struct {
	client *redis.Client
	prefix string
	ttl    time.Duration
}

// RedisConfig holds Redis connection configuration.
type RedisConfig struct {
	Host   string
	Port   int
	Proto  string // "redis" or "rediss" (TLS)
	Pass   string
	Prefix string
}

// NewRedisAuthCodeStore creates a new Redis-backed auth code store.
func NewRedisAuthCodeStore(cfg *RedisConfig) (*RedisAuthCodeStore, error) {
	addr := fmt.Sprintf("%s:%d", cfg.Host, cfg.Port)

	opts := &redis.Options{
		Addr:     addr,
		Password: cfg.Pass,
		DB:       1, // Use DB 1 for auth codes (same as Node.js implementation)
	}

	// Enable TLS for rediss:// protocol
	if cfg.Proto == "rediss" {
		opts.TLSConfig = &tls.Config{
			MinVersion: tls.VersionTLS12,
		}
	}

	client := redis.NewClient(opts)

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), redisConnectTimeout)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("connecting to Redis: %w", err)
	}

	prefix := cfg.Prefix
	if prefix == "" {
		prefix = "authcode:"
	}

	return &RedisAuthCodeStore{
		client: client,
		prefix: prefix,
		ttl:    AuthCodeTTL,
	}, nil
}

// Store saves an authorization code with its associated data.
func (s *RedisAuthCodeStore) Store(code string, data *AuthCodeData) error {
	ctx := context.Background()

	// Serialize data to JSON
	jsonData, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("marshaling auth code data: %w", err)
	}

	key := s.prefix + code
	if err := s.client.Set(ctx, key, jsonData, s.ttl).Err(); err != nil {
		return fmt.Errorf("storing auth code: %w", err)
	}

	return nil
}

// Get retrieves and deletes the data for an authorization code.
// Returns nil if the code doesn't exist or has expired.
func (s *RedisAuthCodeStore) Get(code string) (*AuthCodeData, error) {
	ctx := context.Background()
	key := s.prefix + code

	// Get and delete atomically using GETDEL (Redis 6.2+)
	jsonData, err := s.client.GetDel(ctx, key).Bytes()
	if err == redis.Nil {
		return nil, nil // Code doesn't exist
	}
	if err != nil {
		return nil, fmt.Errorf("getting auth code: %w", err)
	}

	var data AuthCodeData
	if err := json.Unmarshal(jsonData, &data); err != nil {
		return nil, fmt.Errorf("unmarshaling auth code data: %w", err)
	}

	return &data, nil
}

// Close closes the Redis connection.
func (s *RedisAuthCodeStore) Close() error {
	return s.client.Close()
}
