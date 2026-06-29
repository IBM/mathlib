GO_MODULES := . driver/gurvy/compat

.PHONY: all
all: checks unit-tests unit-tests-race

.PHONY: checks
checks: check-deps
	@test -z $(shell gofmt -l -s $(shell go list -f '{{.Dir}}' ./... | grep -v mpc) | tee /dev/stderr) || (echo "Fix formatting issues"; exit 1)
	@go vet -all $(shell go list -f '{{.Dir}}' ./... | grep -v mpc)
	find . -name '*.go' | xargs addlicense -check || (echo "Missing license headers"; exit 1)

.PHONY: unit-tests
unit-tests:
	@echo "Unit-testing Go modules..."
	@for dir in $(GO_MODULES); do \
		echo "  Unit-testing module: $$dir"; \
		(cd $$dir && go test -cover ./...); \
	done

.PHONY: unit-tests-race
unit-tests-race:
	@echo "Unit-testing with race Go modules..."
	@for dir in $(GO_MODULES); do \
		echo "  Unit-testing with race module: $$dir"; \
		(export GORACE=history_size=7 && cd $$dir && go test -race -cover ./...); \
	done

.PHONY: perf
perf:
	@go test -benchmem -bench=Benchmark_Sequential.* -run=^$$ -v
	@go test -benchmem -bench=Benchmark_Parallel.* -run=^$$ -cpu=1,2,4,8,16,32,64 -v

.PHONY: check-deps
check-deps:
	@go install github.com/google/addlicense@latest

.PHONY: lint
# run various linters
lint:
	@echo "Running Go linters..."
	@for dir in $(GO_MODULES); do \
		echo "  Running Go linters on module: $$dir"; \
		(cd $$dir && golangci-lint run --color=always --timeout=4m); \
	done

.PHONY: lint-auto-fix
# run linters with auto-fix
lint-auto-fix:
	@echo "Running Go linters with auto-fix..."
	@for dir in $(GO_MODULES); do \
		echo "  Running Go linters with auto-fix on module: $$dir"; \
		(cd $$dir && golangci-lint run --color=always --timeout=4m --fix); \
	done

.PHONY: install-linter-tool
# install golangci-lint
install-linter-tool:
	@echo "Installing golangci Linter"
	@curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/HEAD/install.sh | sh -s -- -b $(HOME)/go/bin v2.12.2

.PHONY: fmt
fmt: ## Run gofmt on the entire project
	@echo "Running gofmt..."
	@for dir in $(GO_MODULES); do \
		echo "  Formatting module: $$dir"; \
		(cd $$dir && find . -path './.git' -prune -o -name '*.go' -print | xargs gofmt -l -s -w); \
	done

.PHONY: tidy
# tidy up go modules
tidy:
	@echo "Tidying Go modules..."
	@for dir in $(GO_MODULES); do \
		echo "  Tidying module: $$dir"; \
		(cd $$dir && go mod tidy); \
	done
