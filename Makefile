GO ?= go

.PHONY: run test test-race test-integration fmt vet deadcode tidy migrate-up migrate-down

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

# Include test roots: development adapters and test fixtures are intentional.
# deadcode reports findings on stdout but does not fail solely for findings.
deadcode:
	@findings="$$( $(GO) run golang.org/x/tools/cmd/deadcode@v0.44.0 -test ./... )" || exit $$?; \
	if test -n "$$findings"; then printf '%s\n' "$$findings"; exit 1; fi
	$(GO) run honnef.co/go/tools/cmd/staticcheck@v0.7.0 -checks=U1000 ./...

tidy:
	$(GO) mod tidy

migrate-up:
	@echo "Migrations run automatically on API startup when CLUSTER_AUTO_MIGRATE=true."

migrate-down:
	@echo "Production migrations are forward-only. Restore a snapshot to roll back data."
