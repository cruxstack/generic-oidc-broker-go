# --------------------------------------------------------------------- build ---

FROM golang:1.24-alpine AS build

WORKDIR /app

# Install build dependencies
RUN apk add --no-cache git ca-certificates

# Copy go mod files first for caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the binary
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o /broker ./cmd/broker

# ---------------------------------------------------------------------- dev ---

FROM golang:1.24-alpine AS dev

WORKDIR /app

# Install development tools
RUN apk add --no-cache git ca-certificates
RUN go install github.com/air-verse/air@latest

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Run with hot reload
CMD ["air", "-c", ".air.toml"]

# ------------------------------------------------------------------ runtime ---

FROM alpine:3.19 AS runtime

WORKDIR /app

# Install runtime dependencies
RUN apk add --no-cache ca-certificates tzdata

# Create non-root user
RUN adduser -D -g '' appuser

# Copy binary from build stage
COPY --from=build /broker /app/broker

# Switch to non-root user
USER appuser

# Expose port
EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:3000/health || exit 1

# Run the binary
ENTRYPOINT ["/app/broker"]
