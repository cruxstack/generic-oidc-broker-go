# Builds two images:
#   docker build .                         the broker (default target)
#   docker build --target mock-provider .  the mock OAuth provider for the demo

# ----------------------------------------------------------------------- build ---

FROM golang:1.27.4-alpine3.24 AS build

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/ ./cmd/...

# ------------------------------------------------------------------------ base ---

FROM alpine:3.24 AS base

# CA certificates for HTTPS requests to the upstream providers.
RUN apk add --no-cache ca-certificates \
    && adduser -D -H -u 10001 app

# The broker reads an optional .env file from its working directory.
WORKDIR /app
USER app

# --------------------------------------------------------------- mock-provider ---

FROM base AS mock-provider

COPY --from=build /out/mock-provider /usr/local/bin/mock-provider

ENV PORT=9999
EXPOSE 9999
HEALTHCHECK --interval=5s --timeout=3s --start-period=5s --retries=3 \
    CMD wget -q --spider "http://127.0.0.1:${PORT}/health" || exit 1

ENTRYPOINT ["/usr/local/bin/mock-provider"]

# ---------------------------------------------------------------------- broker ---

FROM base AS broker

COPY --from=build /out/broker /usr/local/bin/broker

ENV PORT=3000
EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget -q --spider "http://127.0.0.1:${PORT}/health" || exit 1

ENTRYPOINT ["/usr/local/bin/broker"]
