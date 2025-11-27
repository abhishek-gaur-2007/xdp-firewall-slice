.PHONY: all build clean install uninstall

CLANG ?= clang
LLC ?= llc
GO ?= go
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')
KERNEL_VERSION := $(shell uname -r)
KERNEL_HEADERS := /usr/src/linux-headers-$(KERNEL_VERSION)

# BPF compilation flags - use system headers (libbpf-dev provides these)
BPF_CFLAGS := -O2 -target bpf -D__TARGET_ARCH_$(ARCH)
BPF_CFLAGS += -Wall -Wno-unused-value -Wno-pointer-sign
BPF_CFLAGS += -Wno-compare-distinct-pointer-types
BPF_CFLAGS += -Wno-gnu-variable-sized-type-not-at-end
BPF_CFLAGS += -Wno-address-of-packed-member -Wno-tautological-compare
BPF_CFLAGS += -Wno-unknown-warning-option -Wno-pragma-once-outside-header

BPF_SOURCE := xdp_firewall.c
BPF_OBJECT := xdp_firewall.o

GO_SOURCE := main.go
GO_BINARY := start

all: build

build: $(BPF_OBJECT) $(GO_BINARY)

$(BPF_OBJECT): $(BPF_SOURCE)
	@echo "Building XDP program..."
	$(CLANG) $(BPF_CFLAGS) -c $(BPF_SOURCE) -o $(BPF_OBJECT)
	@echo "✓ XDP program built successfully"

$(GO_BINARY): $(GO_SOURCE)
	@echo "Building Go loader..."
	$(GO) mod download
	$(GO) build -o $(GO_BINARY) $(GO_SOURCE)
	@echo "✓ Go loader built successfully"

clean:
	@echo "Cleaning build artifacts..."
	rm -f $(BPF_OBJECT) $(GO_BINARY)
	@echo "✓ Clean complete"

install: build
	@echo "Installing Slice-XDP..."
	@if [ "$$(id -u)" != "0" ]; then \
		echo "Error: Installation requires root privileges"; \
		echo "Please run: sudo make install"; \
		exit 1; \
	fi
	install -m 0755 $(GO_BINARY) /usr/local/bin/slice-xdp
	mkdir -p /usr/local/lib/slice-xdp
	install -m 0644 $(BPF_OBJECT) /usr/local/lib/slice-xdp/$(BPF_OBJECT)
	mkdir -p /etc/slice-xdp
	@if [ ! -f /etc/slice-xdp/config.toml ]; then \
		install -m 0644 config.toml /etc/slice-xdp/config.toml; \
	fi
	@if [ ! -f /etc/slice-xdp/whitelist.txt ]; then \
		install -m 0644 whitelist.txt /etc/slice-xdp/whitelist.txt; \
	fi
	@if [ ! -f /etc/slice-xdp/blacklist.txt ]; then \
		install -m 0644 blacklist.txt /etc/slice-xdp/blacklist.txt; \
	fi
	mkdir -p /var/log/slice-xdp
	@echo "✓ Installation complete"
	@echo ""
	@echo "Usage: slice-xdp -t <seconds> -i <interface> -d <native|generic>"
	@echo "Config: /etc/slice-xdp/config.toml"

uninstall:
	@echo "Uninstalling Slice-XDP..."
	@if [ "$$(id -u)" != "0" ]; then \
		echo "Error: Uninstallation requires root privileges"; \
		echo "Please run: sudo make uninstall"; \
		exit 1; \
	fi
	rm -f /usr/local/bin/slice-xdp
	rm -rf /usr/local/lib/slice-xdp
	@echo "✓ Uninstall complete"
	@echo "Note: Config files in /etc/slice-xdp and logs in /var/log/slice-xdp were preserved"
	@echo "To remove them: sudo rm -rf /etc/slice-xdp /var/log/slice-xdp"

test: build
	@echo "Testing XDP program compilation..."
	@if [ ! -f $(BPF_OBJECT) ]; then \
		echo "✗ BPF object file not found"; \
		exit 1; \
	fi
	@echo "✓ BPF object file exists"
	@if [ ! -f $(GO_BINARY) ]; then \
		echo "✗ Go binary not found"; \
		exit 1; \
	fi
	@echo "✓ Go binary exists"
	@echo "✓ All tests passed"

help:
	@echo "Slice-XDP Firewall Makefile"
	@echo ""
	@echo "Targets:"
	@echo "  all       - Build XDP program and Go loader (default)"
	@echo "  build     - Build XDP program and Go loader"
	@echo "  clean     - Remove build artifacts"
	@echo "  install   - Install to system (requires root)"
	@echo "  uninstall - Remove from system (requires root)"
	@echo "  test      - Run basic tests"
	@echo "  help      - Show this help message"
	@echo ""
	@echo "Variables:"
	@echo "  CLANG     - Clang compiler (default: clang)"
	@echo "  GO        - Go compiler (default: go)"
	@echo ""
	@echo "Examples:"
	@echo "  make              # Build everything"
	@echo "  make clean        # Clean build artifacts"
	@echo "  sudo make install # Install to system"

