# Stop Docker macOS Security Alerts

## Immediate Fix (Stop the Alerts)

Run these commands to stop Docker from auto-starting and triggering alerts:

```bash
# 1. Stop all Docker processes
pkill -f Docker
pkill -f com.docker

# 2. Disable Docker auto-launch
defaults write com.docker.docker AppleAutoLaunch -bool false

# 3. Remove launch agents
rm -f ~/Library/LaunchAgents/com.docker.*

# 4. Verify no Docker processes are running
ps aux | grep -i docker | grep -v grep
```

**This should stop the alerts immediately.**

## Allow Docker Properly (Choose One Method)

### Method 1: Right-Click Open (Easiest)

1. Open **Finder**
2. Go to **Applications**
3. Find **Docker.app**
4. **Right-click** (or Control+click) on Docker.app
5. Select **"Open"** (NOT double-click)
6. When the security dialog appears, click **"Open"**

This will add Docker to your allowed applications.

### Method 2: Terminal Command

```bash
# Temporarily disable Gatekeeper (allows all apps)
sudo spctl --master-disable

# Open Docker
open -a Docker

# After Docker works, re-enable Gatekeeper:
sudo spctl --master-enable
```

### Method 3: System Settings (If Available)

1. Open **System Settings** (or System Preferences on older macOS)
2. Go to **Privacy & Security** (or **Security & Privacy**)
3. Scroll to the bottom
4. Look for a message like: *"Docker.app was blocked from use because it is not from an identified developer"*
5. Click **"Open Anyway"** next to it

**Note:** This option only appears AFTER macOS has tried to block Docker. If you don't see it, use Method 1 or 2.

### Method 4: Check Console for Blocked Items

1. Open **Console.app** (Applications > Utilities > Console)
2. In the search box, type: `com.docker.vmnetd` or `malware`
3. Look for recent entries showing what was blocked
4. This helps identify exactly what macOS is blocking

## After Allowing Docker

Once Docker is allowed and working:

```bash
# Verify Docker works
docker --version

# Re-enable auto-launch if you want (optional)
defaults write com.docker.docker AppleAutoLaunch -bool true
```

## If Alerts Continue

If alerts persist even after stopping Docker:

1. **Completely remove Docker:**
   ```bash
   sudo rm -rf /Applications/Docker.app
   sudo rm -f /usr/local/bin/docker*
   ```

2. **Download Docker Desktop directly** from https://www.docker.com/products/docker-desktop
   - This avoids Homebrew quarantine issues
   - Before opening, remove quarantine: `xattr -cr ~/Downloads/Docker.dmg`

3. **Use the setup script instead** (no Docker needed):
   ```bash
   ./setup.sh
   ```

## Recommendation

For now, **use the setup script** (`./setup.sh`) which doesn't require Docker. You can test Docker later when you have time to properly configure macOS security settings.
