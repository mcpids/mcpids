SHELL := /bin/bash
.DEFAULT_GOAL := help

MODULE := github.com/mcpids/mcpids
GO := go
GOFLAGS := -trimpath
DIST := dist
PROTO_DIR := pkg/proto/mcpids/v1
GEN_DIR := pkg/proto/gen
GO_BIN := $(shell $(GO) env GOBIN)
ifeq ($(GO_BIN),)
GO_BIN := $(shell $(GO) env GOPATH)/bin
endif
GOOSE := $(GO_BIN)/goose

# DB settings (override via env)
DB_URL ?= postgres://mcpids:mcpids@localhost:5432/mcpids?sslmode=disable
REDIS_URL ?= redis://localhost:6379

.PHONY: help
help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-25s\033[0m %s\n", $$1, $$2}'

##@ Build

.PHONY: build
build: ## Build all binaries into dist/
	@mkdir -p $(DIST)
	$(GO) build $(GOFLAGS) -o $(DIST)/gateway       ./cmd/gateway
	$(GO) build $(GOFLAGS) -o $(DIST)/agent         ./cmd/agent
	$(GO) build $(GOFLAGS) -o $(DIST)/control-plane ./cmd/control-plane
	$(GO) build $(GOFLAGS) -o $(DIST)/sensor-ebpf   ./cmd/sensor-ebpf
	$(GO) build $(GOFLAGS) -o $(DIST)/semantic-service ./cmd/semantic-service
	@echo "✓ Built all binaries into $(DIST)/"

.PHONY: build-gateway
build-gateway: ## Build gateway binary
	@mkdir -p $(DIST)
	$(GO) build $(GOFLAGS) -o $(DIST)/gateway ./cmd/gateway

.PHONY: build-control-plane
build-control-plane: ## Build control-plane binary
	@mkdir -p $(DIST)
	$(GO) build $(GOFLAGS) -o $(DIST)/control-plane ./cmd/control-plane

##@ Testing

.PHONY: test
test: test-unit test-integration ## Run all tests

.PHONY: test-unit
test-unit: ## Run unit tests
	$(GO) test -race -count=1 ./internal/... ./pkg/... ./tests/unit/... 2>&1 | tee /tmp/unit-test.log
	@echo "✓ Unit tests complete"

.PHONY: test-integration
test-integration: ## Run integration tests (requires docker-compose.dev.yml running)
	$(GO) test -race -count=1 -timeout 120s -tags integration ./tests/integration/... 2>&1 | tee /tmp/integration-test.log
	@echo "✓ Integration tests complete"

.PHONY: test-integration-infra
test-integration-infra: docker-up migrate ## Run infra-backed integration smoke tests against local Postgres/Redis
	MCPIDS_TEST_DATABASE_URL="$(DB_URL)" MCPIDS_TEST_REDIS_URL="$(REDIS_URL)" \
		$(GO) test -race -count=1 -timeout 120s -tags integration ./tests/integration/... 2>&1 | tee /tmp/integration-test-infra.log
	@echo "✓ Infra integration smoke tests complete"

.PHONY: test-threats
test-threats: ## Run all 8 threat scenario tests
	@bash scripts/run-threat-scenarios.sh

.PHONY: test-coverage
test-coverage: ## Generate test coverage report
	$(GO) test -race -coverprofile=coverage.txt -covermode=atomic ./internal/... ./pkg/... ./tests/unit/...
	$(GO) tool cover -html=coverage.txt -o coverage.html
	@echo "✓ Coverage report: coverage.html"

##@ Development

.PHONY: run-control-plane
run-control-plane: ## Run control-plane locally
	$(GO) run ./cmd/control-plane --config=configs/control-plane.dev.yaml

.PHONY: run-gateway
run-gateway: ## Run gateway locally
	$(GO) run ./cmd/gateway --config=configs/gateway.dev.yaml

.PHONY: run-agent
run-agent: ## Run agent locally
	$(GO) run ./cmd/agent --config=configs/agent.dev.yaml

##@ Database

.PHONY: migrate
migrate: ## Run all pending goose migrations
	@test -x "$(GOOSE)" || (echo "Installing goose..." && $(GO) install github.com/pressly/goose/v3/cmd/goose@latest)
	"$(GOOSE)" -dir internal/storage/postgres/migrations postgres "$(DB_URL)" up
	@echo "✓ Migrations applied"

.PHONY: migrate-down
migrate-down: ## Rollback last migration
	@test -x "$(GOOSE)" || (echo "Installing goose..." && $(GO) install github.com/pressly/goose/v3/cmd/goose@latest)
	"$(GOOSE)" -dir internal/storage/postgres/migrations postgres "$(DB_URL)" down

.PHONY: migrate-status
migrate-status: ## Show migration status
	@test -x "$(GOOSE)" || (echo "Installing goose..." && $(GO) install github.com/pressly/goose/v3/cmd/goose@latest)
	"$(GOOSE)" -dir internal/storage/postgres/migrations postgres "$(DB_URL)" status

.PHONY: seed
seed: ## Seed database with default tenant, policies, and rules
	@bash scripts/seed-db.sh "$(DB_URL)"

##@ Code Generation

.PHONY: generate
generate: proto-gen ## Run all code generators

.PHONY: proto-gen
proto-gen: ## Generate protobuf/gRPC Go code from .proto files
	@which buf > /dev/null || (echo "buf not found. Install: https://buf.build/docs/installation" && exit 1)
	cd pkg/proto && buf generate
	@echo "✓ Protobuf code generated"

.PHONY: proto-lint
proto-lint: ## Lint proto files
	cd pkg/proto && buf lint

.PHONY: proto-breaking
proto-breaking: ## Check for breaking changes in proto files
	cd pkg/proto && buf breaking --against '.git#branch=main'

##@ Docker

.PHONY: docker-build
docker-build: ## Build all Docker images
	docker build -f deploy/docker/Dockerfile.gateway       -t mcpids/gateway:dev .
	docker build -f deploy/docker/Dockerfile.control-plane -t mcpids/control-plane:dev .
	docker build -f deploy/docker/Dockerfile.agent         -t mcpids/agent:dev .
	docker build -f deploy/docker/Dockerfile.sensor-ebpf  -t mcpids/sensor-ebpf:dev .
	docker build -f deploy/docker/Dockerfile.semantic-service -t mcpids/semantic-service:dev .
	@echo "✓ All Docker images built"

.PHONY: docker-up
docker-up: ## Start supporting services (postgres, redis, otel-collector)
	docker compose -f deploy/docker-compose.yml up -d postgres redis otel-collector
	@echo "✓ Infrastructure services started"
	@echo "  PostgreSQL: localhost:5432"
	@echo "  Redis:      localhost:6379"
	@echo "  OTLP:       localhost:4317"

.PHONY: docker-up-all
docker-up-all: ## Start full stack via Docker Compose
	docker compose -f deploy/docker-compose.yml up -d
	@echo "✓ Full stack started"

.PHONY: docker-down
docker-down: ## Stop and remove all containers
	docker compose -f deploy/docker-compose.yml down

.PHONY: docker-logs
docker-logs: ## Follow logs from all services
	docker compose -f deploy/docker-compose.yml logs -f

##@ Quality

.PHONY: lint
lint: ## Run golangci-lint
	@which golangci-lint > /dev/null || (echo "golangci-lint not found. Install: https://golangci-lint.run/usage/install/" && exit 1)
	golangci-lint run ./...

.PHONY: fmt
fmt: ## Format all Go files
	$(GO) fmt ./...
	$(GO) mod tidy

.PHONY: vet
vet: ## Run go vet
	$(GO) vet ./...

.PHONY: tidy
tidy: ## Tidy go.mod
	$(GO) mod tidy

##@ Certificates

.PHONY: gen-certs
gen-certs: ## Generate dev TLS certificates
	@bash scripts/gen-certs.sh

##@ Cleanup

.PHONY: clean
clean: ## Remove build artifacts
	rm -rf $(DIST)/ coverage.txt coverage.html /tmp/unit-test.log /tmp/integration-test.log /tmp/integration-test-infra.log
	@echo "✓ Cleaned build artifacts"
