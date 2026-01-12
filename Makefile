.PHONY: all build dev test test-e2e test-e2e-external lint clean help demo demo-up demo-down demo-logs

# Default target
all: build

# Build the binary
build:
	go build -o bin/broker ./cmd/broker

# Run in development mode with hot reload (requires air)
dev:
	@if command -v air > /dev/null; then \
		air; \
	else \
		echo "air is not installed. Install with: go install github.com/air-verse/air@latest"; \
		echo "Running without hot reload..."; \
		go run ./cmd/broker; \
	fi

# Run the server directly
run:
	go run ./cmd/broker

# Run all tests
test:
	go test ./...

# Run tests with verbose output
test-v:
	go test -v ./...

# Run E2E tests
test-e2e:
	go test ./e2e/... -v -count=1

# Run E2E tests against external server
# Usage: E2E_SERVER_URL=http://localhost:3000 make test-e2e-external
test-e2e-external:
	go test ./e2e/... -v -count=1

# Run linter (requires golangci-lint)
lint:
	@if command -v golangci-lint > /dev/null; then \
		golangci-lint run; \
	else \
		echo "golangci-lint is not installed. Install from https://golangci-lint.run/usage/install/"; \
	fi

# Format code
fmt:
	go fmt ./...
	goimports -w .

# Tidy dependencies
tidy:
	go mod tidy

# Clean build artifacts
clean:
	rm -rf bin/
	rm -rf tmp/

# Generate test RSA key pair
gen-test-key:
	@mkdir -p testdata
	openssl genrsa -out testdata/private.pem 2048
	openssl rsa -in testdata/private.pem -pubout -out testdata/public.pem
	@echo "Keys generated in testdata/"

# Build Docker image
docker-build:
	docker build -t oidc-broker:latest .

# Run Docker container
docker-run:
	docker run -p 3000:3000 --env-file .env oidc-broker:latest

# Demo targets
demo: demo-up
	@echo ""
	@echo "Demo is running!"
	@echo ""
	@echo "  OIDC Broker:      http://localhost:3000"
	@echo "  Mock OAuth:       http://localhost:9999"
	@echo "  Debug Login:      http://localhost:3000/debug/login"
	@echo ""
	@echo "Run 'make demo-logs' to see logs"
	@echo "Run 'make demo-down' to stop"

demo-up:
	@echo "Starting demo stack..."
	docker compose -f demo/docker-compose.yml up --build -d

demo-down:
	@echo "Stopping demo stack..."
	docker compose -f demo/docker-compose.yml down -v

demo-logs:
	docker compose -f demo/docker-compose.yml logs -f

demo-restart: demo-down demo-up

# Build mock provider binary locally
build-mock-provider:
	go build -o bin/mock-provider ./cmd/mock-provider

# Run mock provider locally
run-mock-provider:
	go run ./cmd/mock-provider

# Show help
help:
	@echo "Available targets:"
	@echo "  build               - Build the binary"
	@echo "  dev                 - Run with hot reload (requires air)"
	@echo "  run                 - Run the server"
	@echo "  test                - Run all unit tests"
	@echo "  test-v              - Run tests with verbose output"
	@echo "  test-e2e            - Run E2E tests"
	@echo "  test-e2e-external   - Run E2E tests against external server (set E2E_SERVER_URL)"
	@echo "  lint                - Run linter"
	@echo "  fmt                 - Format code"
	@echo "  tidy                - Tidy dependencies"
	@echo "  clean               - Clean build artifacts"
	@echo "  gen-test-key        - Generate test RSA key pair"
	@echo "  docker-build        - Build Docker image"
	@echo "  docker-run          - Run Docker container"
	@echo "  demo                - Start the offline demo (docker compose)"
	@echo "  demo-up             - Start demo containers"
	@echo "  demo-down           - Stop demo containers"
	@echo "  demo-logs           - View demo container logs"
	@echo "  demo-restart        - Restart demo containers"
	@echo "  build-mock-provider - Build mock provider binary"
	@echo "  run-mock-provider   - Run mock provider locally"
	@echo "  help                - Show this help"
