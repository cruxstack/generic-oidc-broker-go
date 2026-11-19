# generic-oidc-broker-go

## What

An OpenID Connect (OIDC) provider that brokers sign-in with OAuth 2.0
providers. It wraps Twitter/X, GitHub and Google sign-in in a standard OIDC
interface: discovery, signed ID tokens, and a userinfo endpoint.

## Why

Some identity providers, notably Twitter/X and GitHub, don't speak OIDC, so
OIDC-only services such as Amazon Cognito can't use them directly. The broker
lets those services use them anyway:

- **One OIDC interface** for several OAuth providers
- **One issuer per provider**, so each can be registered separately with a
  relying party
- **Several apps per provider type**, such as two Google OAuth clients

## How it works

1. Your application sends the user to the broker's authorization endpoint for a
   provider, such as `/providers/github/authorize`.
2. The broker sends the user to that provider to sign in.
3. The provider returns the user to the broker, which reads their profile.
4. The broker returns the user to your application with an authorization code
   and, if requested, an ID token.
5. Your application redeems the code at `/providers/github/token` for an ID
   token and an access token, and can call `/providers/github/userinfo`.

## Quick start

Try the whole flow locally with mock providers:

```bash
make demo
```

Then open <http://localhost:3000/debug/login>. See [demo/README.md](demo/README.md).

## Deployment

Build the image and run it with your configuration:

```bash
docker build -t oidc-broker .
docker run -p 3000:3000 --env-file .env oidc-broker
```

Or build the binary with `make build`, which writes `bin/broker`.

Run more than one instance only with the Redis authorization code store
enabled. Serve the broker over HTTPS in production.

### Generating secrets

```bash
# Token signing key (APP_KEY_PRIVATE_BASE64)
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 | base64 | tr -d '\n'

# Sign-in cookie secret (APP_SESSION_SECRET)
openssl rand -base64 32
```

## Configuration

Settings come from environment variables. For local development they can also
be put in `.env` and `.env.local` in the working directory; the environment
overrides `.env.local`, which overrides `.env`. Start from
[.env.example](.env.example). Booleans accept `true`/`false` or `1`/`0`. The
broker refuses to start if any setting is invalid, and logs a warning for any
unknown `APP_` setting.

### Core settings

| Variable                    | Description                                                   | Default            |
| --------------------------- | ------------------------------------------------------------- | ------------------ |
| `APP_OIDC_ISSUER`           | Public base URL of the broker, without a trailing slash      | **required**       |
| `APP_OIDC_CLIENTS`          | JSON array of OIDC clients (see below)                        | **required**       |
| `APP_PROVIDERS`             | JSON array of OAuth providers (see below)                     | **required**       |
| `APP_KEY_ID`                | Key ID (`kid`) of the signing key                             | **required**       |
| `APP_KEY_PRIVATE_BASE64`    | Base64-encoded PEM RSA private key, at least 2048 bits        | **required**       |
| `APP_KEY_PRIVATE_PEM_PATH`  | Path to the PEM key, used when `APP_KEY_PRIVATE_BASE64` is unset |                 |
| `APP_KEY_PREVIOUS_ID`       | Key ID of the previous signing key, during a rotation         |                    |
| `APP_KEY_PREVIOUS_BASE64`   | Base64-encoded PEM of the previous key (public or private)    |                    |
| `APP_SESSION_SECRET`        | Secret for the sign-in cookie, at least 32 characters         | **required**       |
| `APP_SESSION_SECURE_COOKIE` | Mark the sign-in cookie `Secure`                              | `true` for https   |
| `APP_LOG_LEVEL`             | `debug`, `info`, `warn` or `error`                            | `info`             |
| `PORT`                      | Listening port                                                | `3000`             |

### Clients

`APP_OIDC_CLIENTS` lists the applications allowed to use the broker. Redirect
URIs must match exactly.

```json
[
  {
    "client_id": "my-app",
    "client_secret": "a-long-random-secret",
    "redirect_uris": ["https://my-app.example.com/callback"]
  }
]
```

### Providers

`APP_PROVIDERS` lists the upstream OAuth apps. Register
`{APP_OIDC_ISSUER}/auth/{name}/callback` as the callback URL at each provider.

```json
[
  {
    "name": "github",
    "client_id": "your-github-client-id",
    "client_secret": "your-github-client-secret",
    "callback_url": "https://broker.example.com/auth/github/callback"
  },
  {
    "name": "google-staff",
    "type": "google",
    "client_id": "your-google-client-id",
    "client_secret": "your-google-client-secret",
    "callback_url": "https://broker.example.com/auth/google-staff/callback",
    "prefix_subject": false
  }
]
```

| Field            | Description                                                                  |
| ---------------- | ---------------------------------------------------------------------------- |
| `name`           | Identifier used in URLs: letters, digits, `-` and `_`. Must be unique.       |
| `type`           | `twitter`, `github` or `google`. Defaults to `name`.                         |
| `client_id`      | OAuth client ID at the provider. Required.                                   |
| `client_secret`  | OAuth client secret at the provider. Required.                               |
| `callback_url`   | `{APP_OIDC_ISSUER}/auth/{name}/callback`. Required.                          |
| `auth_url`       | Overrides the authorization endpoint, for example for GitHub Enterprise.     |
| `token_url`      | Overrides the token endpoint.                                                |
| `user_url`       | Overrides the profile endpoint. For GitHub, emails are read from `{user_url}/emails`. |
| `scopes`         | Overrides the requested scopes. GitHub needs `user:email` to report emails.  |
| `prefix_subject` | When `true` (the default), `sub` is `{name}:{id}`; when `false`, just `{id}`. |

Default scopes are `tweet.read users.read` for Twitter/X, `read:user user:email`
for GitHub and `openid profile email` for Google. Twitter/X doesn't share email
addresses. GitHub emails are reported as verified only when GitHub has verified
the account's primary address.

### Reverse proxies

Rate limiting and request logs use the client's IP address. By default that is
the TCP peer. Behind a reverse proxy, configure one of these so the broker can
find the real client address without trusting headers a client could forge:

| Variable                  | Description                                                                                       |
| ------------------------- | ------------------------------------------------------------------------------------------------- |
| `APP_CLIENT_IP_HEADER`    | A single-IP header your proxy always overwrites, such as `X-Real-IP` or `CF-Connecting-IP`.      |
| `APP_TRUSTED_PROXY_CIDRS` | Comma-separated proxy ranges. With the header above, it is only trusted from these peers; alone, `X-Forwarded-For` is read past these proxies. |
| `APP_TRUSTED_PROXY_COUNT` | Number of proxies in front of the broker, for proxies with changing addresses (`X-Forwarded-For`). |

### Redis

Authorization codes are kept in memory unless Redis is enabled. Redis 6.2 or
later is required.

| Variable                            | Description                      | Default     |
| ----------------------------------- | -------------------------------- | ----------- |
| `APP_REDIS_ENABLED`                 | Connect to Redis                 | `false`     |
| `APP_AUTH_CODE_REDIS_STORE_ENABLED` | Store authorization codes in Redis | `false`   |
| `APP_AUTH_CODE_REDIS_STORE_PREFIX`  | Key prefix                       | `authcode:` |
| `APP_REDIS_HOST`                    | Host                             | `localhost` |
| `APP_REDIS_PORT`                    | Port                             | `6379`      |
| `APP_REDIS_PROTO`                   | `rediss` (TLS) or `redis`        | `rediss`    |
| `APP_REDIS_USER`                    | Username                         |             |
| `APP_REDIS_PASS`                    | Password                         |             |
| `APP_REDIS_DB`                      | Database number                  | `0`         |

### Debug pages

`/debug/login` and `/debug/callback` walk through a sign-in and show the
resulting tokens. They are for development only.

| Variable                          | Description                                                       | Default     |
| --------------------------------- | ----------------------------------------------------------------- | ----------- |
| `APP_DEBUG_ENABLED`               | Enable the debug pages                                            | `false`     |
| `APP_DEBUG_BASE_URL`              | Broker URL as seen by the browser                                 | the issuer  |
| `APP_DEBUG_CLIENT_ID`             | Client the pages use; must allow `{base URL}/debug/callback`      | required    |
| `APP_DEBUG_CLIENT_SECRET`         | That client's secret                                              | required    |
| `APP_DEBUG_COGNITO_ENABLED`       | Also offer sign-in through an Amazon Cognito user pool            | `false`     |
| `APP_DEBUG_COGNITO_DOMAIN`        | Cognito domain, such as `https://example.auth.us-east-1.amazoncognito.com` |    |
| `APP_DEBUG_COGNITO_CLIENT_ID`     | Cognito app client ID                                             |             |
| `APP_DEBUG_COGNITO_CLIENT_SECRET` | Cognito app client secret                                         |             |

## OIDC endpoints

Each provider is a separate issuer at `{APP_OIDC_ISSUER}/providers/{name}`:

| Endpoint                                                     | Description              |
| ------------------------------------------------------------ | ------------------------ |
| `GET /providers/{name}/.well-known/openid-configuration`     | Discovery document       |
| `GET /providers/{name}/.well-known/jwks.json`                | Signing keys             |
| `GET /providers/{name}/authorize`                            | Authorization endpoint   |
| `POST /providers/{name}/token`                               | Token endpoint           |
| `GET`, `POST /providers/{name}/userinfo`                     | Userinfo endpoint        |
| `GET /auth/{name}/callback`                                  | Provider callback        |
| `GET /health`                                                | Health check             |

### Supported features

- **Response types:** `code`, `id_token` and `code id_token`. Response types
  that return access tokens from the authorization endpoint are not supported,
  following the OAuth 2.0 Security Best Current Practice (RFC 9700).
- **Scopes:** `openid` (required), `profile` and `email`. Others are ignored.
- **PKCE:** `S256`, optional for clients.
- **Client authentication:** `client_secret_basic` and `client_secret_post`.
- **Nonce:** required when the response includes an ID token from the
  authorization endpoint.
- **Parameter limits:** `state` up to 1024 characters (Amazon Cognito sends
  600-700) and `nonce` up to 512. Pending sign-ins share a 4 KB cookie, so a
  browser keeps up to three at once, or fewer when their `state` values are
  long; the oldest is dropped first.
- **Authorization response issuer:** responses include `iss` (RFC 9207).

### Tokens

Tokens are signed with RS256 and last one hour; authorization codes last ten
minutes and can be used once. ID tokens carry `sub`, `name`,
`preferred_username`, `picture`, `email` and `email_verified` when the provider
supplies them. Access tokens are JWTs with type `at+jwt` (RFC 9068) and can only
be used at the issuing provider's userinfo endpoint.

### Rotating the signing key

1. Generate a new key and give it a new `APP_KEY_ID`.
2. Move the old key ID to `APP_KEY_PREVIOUS_ID` and the old key (or just its
   public key) to `APP_KEY_PREVIOUS_BASE64`, then deploy. New tokens are signed
   with the new key; both keys are published and trusted.
3. After at least an hour, when every token signed with the old key has
   expired, remove the `APP_KEY_PREVIOUS_*` settings.

### Rate limits

The userinfo endpoint allows 100 requests per client IP every 15 minutes. After
10 failed client authentications from an IP, the token endpoint rejects that IP
for 15 minutes.

## Upgrading

This version changes behavior that existing deployments may rely on:

- `APP_SESSION_SECRET` must be at least 32 characters.
- The response types `token id_token` and `id_token token` were removed.
- Authorization requests must include the `openid` scope, and a `nonce`
  whenever the response includes an ID token.
- Token requests must include `redirect_uri`.
- `/auth/{name}` no longer exists; `/providers/{name}/authorize` sends the user
  to the provider directly.
- Google profiles come from Google's OpenID Connect userinfo endpoint. Set
  `user_url` if you overrode the old one.
- The sign-in cookie is `Secure` by default when the issuer is https.
- The debug pages need `APP_DEBUG_CLIENT_ID` and `APP_DEBUG_CLIENT_SECRET`.
- `APP_SESSION_REDIS_STORE_*`, `APP_DEBUG_INSPECTION_ENABLED` and the
  `APP_TWITTER_*` settings never had any effect; they are now reported as
  unknown settings at startup.
- Behind a reverse proxy, set the client IP settings above; proxy headers are no
  longer trusted by default.

______________________________________________________________________

# Development

## Project structure

```
├── cmd/
│   ├── broker/          # Broker entry point
│   └── mock-provider/   # Mock OAuth provider for the demo
├── demo/                # Docker Compose demo
├── e2e/                 # End-to-end tests against the real router
└── internal/
    ├── app/             # Assembles the broker from its configuration
    ├── config/          # Configuration loading and validation
    ├── handler/         # HTTP endpoints and debug pages
    ├── middleware/      # Request logging, rate limiting, security headers
    ├── mockprovider/    # Fake Twitter/X, GitHub and Google servers
    ├── provider/        # Upstream OAuth providers
    ├── store/           # Authorization code storage (memory, Redis)
    └── token/           # JWT signing and verification
```

## Running locally

```bash
cp .env.example .env   # then fill in the blanks
make gen-key           # writes testdata/private.pem for APP_KEY_PRIVATE_PEM_PATH
make run               # or `make dev` for live reload with air
```

## Checks

```bash
make check   # formatting, go vet and tests with the race detector, as CI runs
make vuln    # govulncheck
```

Run `make help` for every target.
