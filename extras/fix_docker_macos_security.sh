#!/usr/bin/env bash
#
# Fix Docker macOS Security/Quarantine Issues
# Resolves "Malware Blocked" false positives for Docker components
#

set -euo pipefail

echo "============================================"
echo "  Fixing Docker macOS Security Issues"
echo "============================================"
echo

# Step 1: Stop Docker if it's trying to start
echo "Step 1: Stopping Docker processes..."
pkill -f Docker.app 2>/dev/null || true
pkill -f com.docker 2>/dev/null || true
killall Docker 2>/dev/null || true

echo "✅ Docker processes stopped"
echo

# Step 2: Remove Docker from quarantine
if [[ -d "/Applications/Docker.app" ]]; then
    echo "Step 2: Removing quarantine attribute from Docker.app..."
    sudo xattr -d com.apple.quarantine /Applications/Docker.app 2>/dev/null || echo "⚠️  Quarantine attribute not found (may already be removed)"
    sudo xattr -cr /Applications/Docker.app
    
    echo "✅ Quarantine removed"
    echo
else
    echo "⚠️  Docker.app not found in /Applications"
    echo "   Docker may not be fully installed yet."
    echo
fi

# Step 3: Instructions for System Settings
echo "Step 3: Manual Security Settings (REQUIRED)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo
echo "You need to allow Docker in macOS Security settings:"
echo
echo "1. Open System Settings (System Preferences on older macOS)"
echo "2. Go to: Privacy & Security (or Security & Privacy)"
echo "3. Scroll down to find blocked items"
echo "4. Look for 'com.docker.vmnetd' or 'Docker' entries"
echo "5. Click 'Allow' or 'Open Anyway' next to each Docker component"
echo
echo "OR use this command to open Security settings:"
echo "   open 'x-apple.systempreferences:com.apple.preference.security'"
echo

# Step 4: Alternative - Remove and reinstall with proper permissions
echo "Step 4: If issues persist, reinstall Docker:"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo
echo "1. Remove Docker completely:"
echo "   sudo rm -rf /Applications/Docker.app"
echo "   sudo rm -f /usr/local/bin/docker*"
echo
echo "2. Download Docker Desktop directly (not via Homebrew):"
echo "   https://www.docker.com/products/docker-desktop"
echo
echo "3. After downloading, before opening:"
echo "   xattr -cr ~/Downloads/Docker.dmg"
echo "   sudo xattr -cr /Applications/Docker.app"
echo
echo "4. Then open Docker Desktop normally"
echo

echo "============================================"
echo "  Quick Fix Commands"
echo "============================================"
echo
echo "Stop Docker from auto-starting:"
echo "  pkill -f Docker"
echo
echo "Remove quarantine (run after fixing in System Settings):"
echo "  sudo xattr -cr /Applications/Docker.app"
echo
echo "Open Security settings:"
echo "  open 'x-apple.systempreferences:com.apple.preference.security'"
echo
