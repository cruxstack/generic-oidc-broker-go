# Offline demo

Runs the broker with Twitter/X, GitHub and Google providers that are all backed
by a local mock provider, so the whole sign-in flow works without accounts at
those providers.

## Start

From the repository root:

```bash
make demo
```

Then open <http://localhost:3000/debug/login>, choose a provider, and pick a
test account. The callback page shows the ID token's claims, the userinfo
response, and the raw tokens.

| Service       | URL                                                                     |
| ------------- | ----------------------------------------------------------------------- |
| Debug login   | <http://localhost:3000/debug/login>                                     |
| Discovery     | <http://localhost:3000/providers/github/.well-known/openid-configuration> |
| Mock provider | <http://localhost:9999>                                                 |

Every provider is its own issuer at `http://localhost:3000/providers/{name}`,
with `twitter`, `github` and `google` configured.

## Test accounts

| Name        | Username     | Email               | Email verified |
| ----------- | ------------ | ------------------- | -------------- |
| Alice Demo  | alice_demo   | alice@example.com   | Yes            |
| Bob Tester  | bob_test     | bob@example.com     | Yes            |
| Charlie Dev | charlie_dev  | charlie@example.com | No             |

Twitter/X profiles have no email address, as with the real API.

## Configuration

`docker-compose.yml` configures:

- the OIDC client `demo-client` / `demo-secret`, allowed to redirect to
  `http://localhost:3000/debug/callback`
- a signing key generated on first start and kept in the `keys` volume
- in-memory authorization codes, so no Redis is needed

## Commands

```bash
make demo          # build and start
make demo-logs     # follow logs
make demo-restart  # rebuild and restart
make demo-down     # stop and delete the signing key volume
```

If port 3000 or 9999 is taken, change the published ports in
`docker-compose.yml`. Changing the broker's port also means changing the URLs
that contain `localhost:3000`.
