package store

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/cruxstack/generic-oidc-broker/internal/config"
)

// Redis keeps authorization codes in Redis, so any broker instance can
// redeem a code issued by another. It requires Redis 6.2 or later (GETDEL).
type Redis struct {
	client *redis.Client
	prefix string
}

// NewRedis connects to Redis and verifies the connection.
func NewRedis(ctx context.Context, cfg config.Redis, keyPrefix string) (*Redis, error) {
	opts := &redis.Options{
		Addr:         cfg.Addr(),
		Username:     cfg.Username,
		Password:     cfg.Password,
		DB:           cfg.DB,
		DialTimeout:  5 * time.Second,
		ReadTimeout:  3 * time.Second,
		WriteTimeout: 3 * time.Second,
	}
	if cfg.TLS {
		opts.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	client := redis.NewClient(opts)

	pingCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := client.Ping(pingCtx).Err(); err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("connecting to Redis at %s: %w", cfg.Addr(), err)
	}
	return &Redis{client: client, prefix: keyPrefix}, nil
}

// Save stores data under code for AuthCodeTTL.
func (s *Redis) Save(ctx context.Context, code string, data AuthCode) error {
	value, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("encoding authorization code: %w", err)
	}
	if err := s.client.Set(ctx, s.prefix+code, value, AuthCodeTTL).Err(); err != nil {
		return fmt.Errorf("storing authorization code: %w", err)
	}
	return nil
}

// Consume atomically removes the code and returns its data, or ErrNotFound.
func (s *Redis) Consume(ctx context.Context, code string) (AuthCode, error) {
	value, err := s.client.GetDel(ctx, s.prefix+code).Bytes()
	if errors.Is(err, redis.Nil) {
		return AuthCode{}, ErrNotFound
	}
	if err != nil {
		return AuthCode{}, fmt.Errorf("reading authorization code: %w", err)
	}
	var data AuthCode
	if err := json.Unmarshal(value, &data); err != nil {
		return AuthCode{}, fmt.Errorf("decoding authorization code: %w", err)
	}
	return data, nil
}

// Close closes the Redis connection.
func (s *Redis) Close() error {
	return s.client.Close()
}
