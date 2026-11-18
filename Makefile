GO ?= go
IMAGE ?= oidc-broker
COMPOSE := docker compose -f demo/docker-compose.yml

.DEFAULT_GOAL := help

.PHONY: help build run dev test check fmt fmt-check vet lint vuln tidy clean gen-key \
	docker-build docker-run demo demo-up demo-down demo-logs demo-restart

help: ## Show this help
	@awk 'BEGIN {FS = ":.*## "} /^[a-z-]+:.*## / {printf "  %-14s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

build: ## Build the broker and mock provider into bin/
	$(GO) build -trimpath -o bin/ ./cmd/...

run: ## Run the broker (reads .env and .env.local)
	$(GO) run ./cmd/broker

dev: ## Run the broker with live reload (requires air)
	@command -v air >/dev/null || { echo "air is not installed: https://github.com/air-verse/air"; exit 1; }
	air

test: ## Run all tests with the race detector
	$(GO) test -race ./...

check: fmt-check vet test ## Run the checks CI runs

fmt: ## Format the code
	gofmt -w .

fmt-check: ## Fail if any file needs formatting
	@unformatted="$$(gofmt -l .)"; if [ -n "$$unformatted" ]; then echo "Run 'make fmt':"; echo "$$unformatted"; exit 1; fi

vet: ## Run go vet
	$(GO) vet ./...

lint: ## Run golangci-lint (must be installed)
	golangci-lint run

vuln: ## Check dependencies for known vulnerabilities (must be installed)
	govulncheck ./...

tidy: ## Tidy go.mod and go.sum
	$(GO) mod tidy

clean: ## Remove build output
	rm -rf bin/ tmp/

gen-key: ## Generate a development signing key at testdata/private.pem
	@mkdir -p testdata
	openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out testdata/private.pem
	@echo "Set APP_KEY_PRIVATE_PEM_PATH=testdata/private.pem"

docker-build: ## Build the broker image
	docker build -t $(IMAGE) .

docker-run: ## Run the broker image with .env
	docker run --rm -p 3000:3000 --env-file .env $(IMAGE)

demo: demo-up ## Start the offline demo
	@echo ""
	@echo "  Debug login:    http://localhost:3000/debug/login"
	@echo "  Mock provider:  http://localhost:9999"
	@echo ""
	@echo "  make demo-logs to follow logs, make demo-down to stop"

demo-up: ## Start the demo containers
	$(COMPOSE) up --build -d

demo-down: ## Stop the demo and remove its volumes
	$(COMPOSE) down -v

demo-logs: ## Follow the demo logs
	$(COMPOSE) logs -f

demo-restart: demo-down demo-up ## Restart the demo
