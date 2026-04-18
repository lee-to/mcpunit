.PHONY: build release demo test clippy lint fmt check install uninstall clean reports snapshots help

# Default target
all: install

# Debug build
build:
	cargo build

# Release build (optimized)
release:
	cargo build --release --bin mcpunit

# Release build of the bundled demo MCP server (consumed by `reports`)
demo:
	cargo build --release --example demo

# Run all tests
test:
	cargo test

# Clippy lint (all targets, warnings are errors)
clippy:
	cargo clippy --all-targets -- -D warnings

# Full lint: clippy + fmt check
lint: clippy
	cargo fmt -- --check

# Format code
fmt:
	cargo fmt

# Run mcpunit against the bundled demo MCP server
check: release demo
	./target/release/mcpunit test --cmd ./target/release/examples/demo

# Regenerate .reports/demo.* from the demo server
reports: release demo
	@mkdir -p .reports
	./target/release/mcpunit --log warn test \
		--min-score 0 \
		--json-out .reports/demo.json \
		--sarif-out .reports/demo.sarif \
		--markdown-out .reports/demo.md \
		--cmd ./target/release/examples/demo \
		> .reports/demo.txt
	@echo "regenerated .reports/demo.{json,sarif,md,txt}"

# Regenerate insta snapshots after an intentional reporter change
snapshots:
	INSTA_UPDATE=always cargo test --test reporter_snapshots

# Install release binary to /usr/local/bin
install: release
	cp target/release/mcpunit /usr/local/bin/mcpunit
	@echo "Installed mcpunit to /usr/local/bin/mcpunit"

# Uninstall
uninstall:
	rm -f /usr/local/bin/mcpunit
	@echo "Removed /usr/local/bin/mcpunit"

# Clean build artifacts
clean:
	cargo clean
	rm -rf dist/

# Help
help:
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@echo "  build      Debug build"
	@echo "  release    Release build (optimized)"
	@echo "  test       Run all tests"
	@echo "  clippy     Run clippy linter"
	@echo "  lint       Clippy + fmt check"
	@echo "  fmt        Auto-format code"
	@echo "  check      Build + test the bundled demo MCP server"
	@echo "  reports    Regenerate .reports/demo.* from the demo server"
	@echo "  snapshots  Regenerate insta snapshots (reporter output changed)"
	@echo "  install    Release build + copy to /usr/local/bin"
	@echo "  uninstall  Remove from /usr/local/bin"
	@echo "  clean      Remove build artifacts"
