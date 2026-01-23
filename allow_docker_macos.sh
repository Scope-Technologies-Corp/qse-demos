#!/usr/bin/env bash
#
# Allow Docker on macOS - Multiple Methods
#

set -euo pipefail

echo "============================================"
echo "  Allowing Docker on macOS"
echo "============================================"
echo

# Method 1: Remove quarantine and allow via command line
echo "Method 1: Removing quarantine attributes..."
if [[ -d "/Applications/Docker.app" ]]; then
    echo "Removing quarantine from Docker.app..."
    xattr -d com.apple.quarantine /Applications/Docker.app 2>/dev/null || echo "  (quarantine already removed or not present)"
    xattr -cr /Applications/Docker.app 2>/dev/null || echo "  (requires sudo for some attributes)"
    echo "✅ Quarantine removed"
else
    echo "⚠️  Docker.app not found in /Applications"
fi
echo

# Method 2: Check Gatekeeper status
echo "Method 2: Checking Gatekeeper status..."
spctl --status
echo

# Method 3: Try to open Docker with explicit allow
echo "Method 3: Instructions to allow Docker:"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo
echo "Option A: Via Terminal (Recommended)"
echo "  1. Run this command:"
echo "     sudo spctl --master-disable"
echo "     (This temporarily disables Gatekeeper - re-enable after Docker works)"
echo
echo "  2. Or allow Docker specifically:"
echo "     sudo spctl --add /Applications/Docker.app"
echo "     sudo spctl --enable --label Docker"
echo
echo "Option B: Via System Settings"
echo "  1. Open System Settings"
echo "  2. Search for 'Security' or 'Privacy'"
echo "  3. Look for 'General' tab in Privacy & Security"
echo "  4. Check 'Allow applications downloaded from: App Store and identified developers'"
echo "  5. If you see a message about Docker being blocked, click 'Open Anyway'"
echo
echo "Option C: Right-click method"
echo "  1. Open Finder"
echo "  2. Go to Applications"
echo "  3. Find Docker.app"
echo "  4. Right-click (or Control+click) on Docker.app"
echo "  5. Select 'Open' (not double-click)"
echo "  6. When prompted, click 'Open' in the security dialog"
echo

# Method 4: Check what's actually blocked
echo "Method 4: Checking blocked processes..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo
echo "To see what macOS is blocking, check Console.app:"
echo "  1. Open Console.app (Applications > Utilities > Console)"
echo "  2. Search for: 'com.docker.vmnetd' or 'malware'"
echo "  3. Look for recent blocked entries"
echo

# Method 5: Disable auto-start
echo "Method 5: Prevent Docker from auto-starting:"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo
echo "To stop Docker from trying to start automatically:"
echo
echo "  # Disable Docker launch agent"
echo "  launchctl unload ~/Library/LaunchAgents/com.docker.* 2>/dev/null || true"
echo "  rm -f ~/Library/LaunchAgents/com.docker.*"
echo
echo "  # Or if Docker Desktop is installed:"
echo "  defaults write com.docker.docker AppleAutoLaunch -bool false"
echo

echo "============================================"
echo "  Quick Commands"
echo "============================================"
echo
echo "Stop Docker processes:"
echo "  pkill -f Docker; pkill -f com.docker"
echo
echo "Remove quarantine:"
echo "  xattr -cr /Applications/Docker.app"
echo
echo "Temporarily disable Gatekeeper (then re-enable after Docker works):"
echo "  sudo spctl --master-disable"
echo "  # After Docker works, re-enable with:"
echo "  sudo spctl --master-enable"
echo
echo "Open Security settings:"
echo "  open 'x-apple.systempreferences:com.apple.preference.security'"
echo
