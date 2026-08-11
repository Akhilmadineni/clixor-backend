GO ?= go

.PHONY: run test test-race test-integration fmt vet tidy migrate-up migrate-down

run:
	CLUSTER_STORE=memory $(GO) run ./cmd/api

test:
	$(GO) test ./...

test-race:
	$(GO) test -race ./...

test-integration:
	test -n "$$TEST_DATABASE_URL"
	$(GO) test -race ./internal/store/postgres

fmt:
	$(GO) fmt ./...

vet:
	$(GO) vet ./...

tidy:
	$(GO) mod tidy

migrate-up:
	@echo "Migrations run automatically on API startup when CLUSTER_AUTO_MIGRATE=true."

migrate-down:
	@echo "Production migrations are forward-only. Restore a snapshot to roll back data."
