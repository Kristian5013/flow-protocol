# FTC Project Makefile (Linux/macOS)
# Usage: make [target]

.PHONY: all clean release debug node miner wallet keygen install deps

# Default target
all: release

# Build all in release mode
release:
	@./scripts/build-all.sh

# Build all in debug mode
debug:
	@./scripts/build-all.sh --debug

# Clean all build directories
clean:
	@./scripts/build-all.sh --clean
	@rm -rf bin/

# Install dependencies
deps:
	@./scripts/build-all.sh --install-deps

# Build individual components
node:
	@mkdir -p ftc-node/build && cd ftc-node/build && cmake .. -DCMAKE_BUILD_TYPE=Release && cmake --build . && cp -f ftc-node ../..bin/ 2>/dev/null || true

miner:
	@mkdir -p ftc-miner-v2/build && cd ftc-miner-v2/build && cmake .. -DCMAKE_BUILD_TYPE=Release && cmake --build . && cp -f ftc-miner ../../bin/ 2>/dev/null || true

wallet:
	@mkdir -p ftc-wallet/build && cd ftc-wallet/build && cmake .. -DCMAKE_BUILD_TYPE=Release && cmake --build . && cp -f ftc-wallet ../../bin/ 2>/dev/null || true

keygen:
	@mkdir -p ftc-keygen/build && cd ftc-keygen/build && cmake .. -DCMAKE_BUILD_TYPE=Release && cmake --build . && cp -f ftc-keygen ../../bin/ 2>/dev/null || true

# Install to /usr/local/bin (requires sudo)
install: release
	@echo "Installing binaries to /usr/local/bin..."
	@sudo cp -f bin/ftc-* /usr/local/bin/
	@echo "Done!"

# Help
help:
	@echo "FTC Build System"
	@echo ""
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@echo "  all (default)  - Build all components in release mode"
	@echo "  release        - Build all components in release mode"
	@echo "  debug          - Build all components in debug mode"
	@echo "  clean          - Clean all build directories"
	@echo "  deps           - Install dependencies (requires sudo)"
	@echo "  node           - Build only ftc-node"
	@echo "  miner          - Build only ftc-miner"
	@echo "  wallet         - Build only ftc-wallet"
	@echo "  keygen         - Build only ftc-keygen"
	@echo "  install        - Install binaries to /usr/local/bin"
	@echo "  help           - Show this help"
