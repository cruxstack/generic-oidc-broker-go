# generic-oidc-broker-go

## What

An OpenID Connect (OIDC) Identity Provider that acts as a broker between
OAuth 2.0 providers and applications expecting OIDC authentication. It wraps
OAuth flows from Twitter, GitHub, and Google into a single OIDC-compliant
interface.

## Why

Many identity providers (especially Twitter/X) don't natively support OIDC.

- **Unify multiple OAuth providers** into a single OIDC interface for your
  applications
- **Enable OIDC-only services** (like AWS Cognito) to use OAuth-only providers
- **Support multiple providers simultaneously** with provider-scoped OIDC
  endpoints
- **Deploy a single broker** to serve multiple applications with different
  OAuth providers

## How It Works

1. Your application initiates an OIDC authorization request to the broker
2. The broker redirects the user to the selected OAuth provider (Twitter,
   GitHub, or Google)
3. After OAuth authentication, the broker exchanges the OAuth tokens for user
   info
4. The broker issues standard OIDC tokens (ID token, access token) back to
   your application


## Deployment

### 1. Build

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-w -s" -o broker ./cmd/broker
```

### 2. Docker

```bash
docker build -t oidc-broker:latest .
docker run -p 3000:3000 --env-file .env oidc-broker:latest
```

### 3. Configure

Deploy as a standalone service and configure with environment variables.

### Environment Variables

| Variable                   | Description                              | Default      |
|----------------------------|------------------------------------------|--------------|
| `APP_OIDC_ISSUER`          | OIDC issuer URL (must match deployment)  | **required** |
| `APP_OIDC_CLIENTS`         | JSON array of OIDC client configurations | `[]`         |
| `APP_SESSION_SECRET`       | Session encryption key                   | **required** |
| `APP_KEY_ID`               | JWT signing key ID                       | **required** |
| `APP_KEY_PRIVATE_BASE64`   | Base64-encoded RSA private key           | **required** |
| `APP_KEY_PRIVATE_PEM_PATH` | Path to PEM file (alternative to base64) | -            |
| `PORT`                     | Server port                              | `3000`       |

**Provider Configuration:**

| Variable        | Description                                |
|-----------------|--------------------------------------------|
| `APP_PROVIDERS` | JSON array of OAuth provider configs       |

**Redis Configuration (optional, recommended for production):**

| Variable                            | Description                    | Default     |
|-------------------------------------|--------------------------------|-------------|
| `APP_REDIS_ENABLED`                 | Enable Redis connection        | `0`         |
| `APP_REDIS_HOST`                    | Redis host                     | `localhost` |
| `APP_REDIS_PORT`                    | Redis port                     | `6379`      |
| `APP_REDIS_PROTO`                   | Protocol (`redis` or `rediss`) | `rediss`    |
| `APP_REDIS_PASS`                    | Redis password                 | -           |
| `APP_REDIS_DB`                      | Redis database number          | `0`         |
| `APP_AUTH_CODE_REDIS_STORE_ENABLED` | Use Redis for auth codes       | `0`         |
| `APP_SESSION_REDIS_STORE_ENABLED`   | Use Redis for sessions         | `0`         |

### Provider Configuration

Configure OAuth providers via `APP_PROVIDERS` as a JSON array:

```json
[
  {
    "name": "twitter",
    "client_id": "your-twitter-client-id",
    "client_secret": "your-twitter-client-secret",
    "callback_url": "https://your-broker.com/auth/twitter/callback"
  },
  {
    "name": "github",
    "client_id": "your-github-client-id",
    "client_secret": "your-github-client-secret",
    "callback_url": "https://your-broker.com/auth/github/callback"
  },
  {
    "name": "google",
    "client_id": "your-google-client-id",
    "client_secret": "your-google-client-secret",
    "callback_url": "https://your-broker.com/auth/google/callback"
  }
]
```

**Supported providers:** `twitter`, `github`, `google`

**Optional fields:**

- `auth_url`: Custom authorization endpoint
- `token_url`: Custom token endpoint
- `user_url`: Custom user info endpoint
- `scopes`: Custom OAuth scopes
- `prefix_subject`: Prefix `sub` claim with provider name (default: `true`).
  When `true`, subjects are formatted as `twitter:12345`. When `false`,
  subjects are just `12345`.

### Client Configuration

Configure OIDC clients via `APP_OIDC_CLIENTS`:

```json
[
  {
    "client_id": "my-app",
    "client_secret": "my-secret",
    "redirect_uris": ["https://my-app.com/callback"]
  }
]
```

### OIDC Endpoints

**Root endpoints** (uses first configured provider):

| Endpoint                                | Description          |
|-----------------------------------------|----------------------|
| `GET /.well-known/openid-configuration` | Discovery document   |
| `GET /.well-known/jwks.json`            | JWKS endpoint        |
| `GET /authorize`                        | Authorization        |
| `POST /token`                           | Token endpoint       |
| `GET /userinfo`                         | Userinfo endpoint    |

**Provider-scoped endpoints** (for multi-provider setups):

| Endpoint                                                     | Description                 |
|--------------------------------------------------------------|-----------------------------|
| `GET /providers/{provider}/.well-known/openid-configuration` | Provider-specific discovery |
| `GET /providers/{provider}/authorize`                        | Provider-specific authorize |
| `POST /providers/{provider}/token`                           | Provider-specific token     |
| `GET /providers/{provider}/userinfo`                         | Provider-specific userinfo  |

### Supported Response Types

- `code` - Authorization Code flow
- `id_token` - Implicit flow
- `token id_token` / `id_token token` - Implicit with access token
- `code id_token` - Hybrid flow

### Token Details

- **Algorithm:** RS256
- **ID Token Expiry:** 1 hour
- **Access Token Expiry:** 1 hour
- **Auth Code TTL:** 10 minutes

**Claims supported:** `sub`, `name`, `preferred_username`, `email`,
`email_verified`, `picture`, `iss`, `aud`, `exp`, `iat`, `nonce`

---

# Development

## Project Structure

```
├── cmd/
│   ├── broker/         # Main application entrypoint
│   └── mock-provider/  # Mock OAuth server for testing
├── demo/               # Docker Compose demo setup
├── e2e/                # End-to-end tests
├── internal/
│   ├── config/         # Environment configuration
│   ├── crypto/         # PKCE and random string generation
│   ├── handler/        # HTTP handlers (authorize, token, userinfo, etc.)
│   ├── middleware/     # Session, rate limiting, logging
│   ├── provider/       # OAuth provider implementations
│   ├── service/        # Token and client services
│   └── store/          # Auth code storage (memory, Redis)
└── main.go             # Lambda/serverless entrypoint (if applicable)
```

## Running Locally

```bash
# Copy and configure environment
cp .env.example .env
# Edit .env with your OAuth credentials

# Run with hot reload (requires air)
make dev

# Or run directly
make run
```

## Running Tests

```bash
# All tests
make test

# Unit tests with verbose output
make test-v

# E2E tests
make test-e2e
```

## Demo Mode

Run a fully offline demo with mock OAuth providers:

```bash
make demo
```

This starts:

- **OIDC Broker** at http://localhost:3000
- **Mock OAuth Provider** at http://localhost:9999
- **Debug Login UI** at http://localhost:3000/debug/login

Demo uses:

- Auto-generated RSA keys
- Pre-configured test client (`test-client` / `test-secret`)
- Mock OAuth provider simulating Twitter, GitHub, Google

```bash
make demo-logs   # View logs
make demo-down   # Stop demo
```

## Debug Mode

Enable debug routes for local testing:

| Variable             | Description          | Default |
|----------------------|----------------------|---------|
| `APP_DEBUG_ENABLED`  | Enable debug routes  | `0`     |
| `APP_DEBUG_BASE_URL` | Base URL for debug UI | -      |

Debug routes:

- `GET /debug/login` - Debug login page
- `GET /debug/callback` - Debug callback page

## Generating RSA Keys

```bash
# Generate key pair
make gen-test-key

# Or manually
openssl genrsa -out private.pem 2048
openssl rsa -in private.pem -pubout -out public.pem

# Base64 encode for APP_KEY_PRIVATE_BASE64
cat private.pem | base64 -w 0
```

## Docker

```bash
# Build image
make docker-build

# Run with env file
make docker-run
```

## Makefile Targets

| Target              | Description          |
|---------------------|----------------------|
| `make build`        | Build the binary     |
| `make dev`          | Run with hot reload  |
| `make run`          | Run directly         |
| `make test`         | Run all tests        |
| `make test-e2e`     | Run E2E tests        |
| `make lint`         | Run linter           |
| `make fmt`          | Format code          |
| `make docker-build` | Build Docker image   |
| `make demo`         | Start offline demo   |
| `make help`        | Show all targets     |
