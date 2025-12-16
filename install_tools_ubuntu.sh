#!/usr/bin/env bash
set -euo pipefail

info() { printf '[*] %s\n' "$*"; }
warn() { printf '[!] %s\n' "$*"; }
err()  { printf '[x] %s\n' "$*" >&2; }

ensure_go() {
    if command -v go >/dev/null 2>&1; then
        info "Go is already installed: $(go version)"
        return
    fi

    if command -v apt-get >/dev/null 2>&1; then
        info "Installing Go via apt-get..."
        if [ "${EUID:-0}" -ne 0 ]; then
            sudo apt-get update
            sudo apt-get install -y golang-go
        else
            apt-get update
            apt-get install -y golang-go
        fi
    else
        err "Go toolchain not found and apt-get unavailable. Install Go manually, then rerun."
        exit 1
    fi
}

ensure_path() {
    local dir="$1"
    case ":$PATH:" in
        *":$dir:"*) ;;
        *) info "Adding $dir to PATH for this session"; export PATH="$dir:$PATH" ;;
    esac

    local profile="$HOME/.bashrc"
    if [ -n "${ZSH_VERSION-}" ]; then
        profile="$HOME/.zshrc"
    fi
    if [ ! -f "$profile" ] || ! grep -F "$dir" "$profile" >/dev/null 2>&1; then
        info "Persisting $dir to PATH in $profile"
        printf '\nexport PATH="%s:$PATH"\n' "$dir" >> "$profile"
    fi
}

ensure_go

gopath="$(go env GOPATH 2>/dev/null || true)"
if [ -z "$gopath" ]; then
    gopath="$HOME/go"
fi
bindir="$gopath/bin"
mkdir -p "$bindir"
ensure_path "$bindir"

tools=(
    "subfinder=github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    "dnsx=github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
    "httpx=github.com/projectdiscovery/httpx/cmd/httpx@latest"
    "katana=github.com/projectdiscovery/katana/cmd/katana@latest"
    "gau=github.com/lc/gau/v2/cmd/gau@latest"
    "waybackurls=github.com/tomnomnom/waybackurls@latest"
)

for entry in "${tools[@]}"; do
    tool="${entry%%=*}"
    module="${entry#*=}"
    info "Installing $tool from $module ..."
    GO111MODULE=on go install "$module"
done

declare -A version_flags=(
    [subfinder]="-version"
    [dnsx]="-version"
    [httpx]="-version"
    [katana]="-version"
    [gau]="--version"
    [waybackurls]="--version"
)

info "Verifying installed tool versions:"
for tool in "${!version_flags[@]}"; do
    flag="${version_flags[$tool]}"
    if command -v "$tool" >/dev/null 2>&1; then
        output=$("$tool" "$flag" 2>/dev/null || true)
        if [ -z "$output" ]; then
            output=$("$tool" -h 2>&1 | head -n 1)
        else
            output=$(printf '%s\n' "$output" | head -n 1)
        fi
        printf ' - %s: %s\n' "$tool" "$output"
    else
        warn "Could not find $tool in PATH after install."
    fi
done

printf '\n'
info "Done. Open a new shell or source your shell profile for PATH changes to take effect."
