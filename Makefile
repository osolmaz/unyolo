BINARY_NAME := gh-broker
MAIN_PATH := ./cmd/gh-broker
BUILD_DIR := bin

.DEFAULT_GOAL := help

CYAN := \033[36m
GREEN := \033[32m
RESET := \033[0m

## help: Show available commands
.PHONY: help
help:
	@grep -E '^## [a-zA-Z_-]+:' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = "## "}; {printf "  $(GREEN)%-18s$(RESET) %s\n", $$2, $$3}' | sed 's/: / - /'

## deps: Download and verify dependencies
.PHONY: deps
deps:
	@echo "$(CYAN)Installing dependencies...$(RESET)"
	go mod download
	go mod tidy
	go mod verify

## build: Build the server binary
.PHONY: build
build:
	@echo "$(CYAN)Building server...$(RESET)"
	mkdir -p $(BUILD_DIR)
	go build -o $(BUILD_DIR)/$(BINARY_NAME) $(MAIN_PATH)

## run: Run the server
.PHONY: run
run:
	go run $(MAIN_PATH)

## test: Run tests
.PHONY: test
test:
	go test ./...

## test-coverage: Run tests with coverage
.PHONY: test-coverage
test-coverage:
	./scripts/check-go-coverage.sh

## vet: Run go vet
.PHONY: vet
vet:
	go vet ./...

## lint: Run golangci-lint
.PHONY: lint
lint:
	@which golangci-lint > /dev/null || go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest
	golangci-lint run

## check: Run local quality checks
.PHONY: check
check: vet test build

## slophammer: Run Slophammer quality checks
.PHONY: slophammer
slophammer:
	slophammer-go dry .
	slophammer-go crap .
	slophammer-go mutate . --scan
	slophammer-go check .
	slophammer-go check . --execute

## clean: Remove build artifacts
.PHONY: clean
clean:
	rm -rf $(BUILD_DIR) coverage.out
