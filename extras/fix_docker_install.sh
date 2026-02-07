#!/usr/bin/env bash
#
# Fix Docker Desktop installation conflicts
# Run this script to resolve binary conflicts before installing Docker
#

set -euo pipefail

echo "============================================"
echo "  Fixing Docker Desktop Installation"
echo "============================================"
echo

# Check for conflicting binaries
CONFLICTS=(
    "/usr/local/bin/hub-tool"
    "/usr/local/bin/kubectl.docker"
    "/usr/local/bin/docker"
    "/usr/local/bin/docker-compose"
    "/usr/local/bin/docker-credential-desktop"
    "/usr/local/bin/docker-credential-osxkeychain"
    "/usr/local/bin/docker-index"
)

echo "Checking for conflicting binaries..."
FOUND_CONFLICTS=0

for binary in "${CONFLICTS[@]}"; do
    if [[ -L "$binary" ]] || [[ -f "$binary" ]]; then
        TARGET=$(readlink -f "$binary" 2>/dev/null || echo "broken link")
        if [[ "$TARGET" == *"Docker.app"* ]] && [[ ! -e "$TARGET" ]]; then
            echo "⚠️  Found stale link: $binary -> $TARGET (target missing)"
            FOUND_CONFLICTS=1
        elif [[ -L "$binary" ]] || [[ -f "$binary" ]]; then
            echo "⚠️  Found conflict: $binary"
            FOUND_CONFLICTS=1
        fi
    fi
done

if [[ $FOUND_CONFLICTS -eq 0 ]]; then
    echo "✅ No conflicts found. You can proceed with Docker installation."
    echo
    echo "Run: brew install --cask docker"
    exit 0
fi

echo
echo "Conflicts detected. To fix, run these commands:"
echo
for binary in "${CONFLICTS[@]}"; do
    if [[ -L "$binary" ]] || [[ -f "$binary" ]]; then
        echo "sudo rm -f $binary"
    fi
done
echo
echo "Then run: brew install --cask docker"
echo
echo "Or run this script with sudo to auto-fix:"
echo "  sudo ./fix_docker_install.sh --fix"
echo

if [[ "${1:-}" == "--fix" ]]; then
    if [[ $EUID -ne 0 ]]; then
        echo "❌ This script must be run with sudo to fix conflicts"
        exit 1
    fi
    
    echo "Removing conflicting/stale binaries..."
    for binary in "${CONFLICTS[@]}"; do
        if [[ -L "$binary" ]] || [[ -f "$binary" ]]; then
            rm -f "$binary"
            echo "✅ Removed: $binary"
        fi
    done
    
    echo
    echo "✅ Conflicts resolved. You can now install Docker:"
    echo "   brew install --cask docker"
    echo
    echo "After installation, start Docker Desktop:"
    echo "   open -a Docker"
fi
