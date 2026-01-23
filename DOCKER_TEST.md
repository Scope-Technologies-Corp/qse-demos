# Docker Testing Guide

## Fixing Docker Installation Issue

The Docker installation failed due to conflicts with existing binaries. Fix it:

### Option 1: Use the fix script

```bash
# Check for conflicts
./fix_docker_install.sh

# Auto-fix conflicts (requires sudo password)
sudo ./fix_docker_install.sh --fix

# Then install Docker
brew install --cask docker
```

### Option 2: Manual fix

```bash
# Remove ALL conflicting binaries
sudo rm -f /usr/local/bin/hub-tool
sudo rm -f /usr/local/bin/kubectl.docker
sudo rm -f /usr/local/bin/docker
sudo rm -f /usr/local/bin/docker-compose

# Also check for docker in other locations
which docker
which docker-compose

# Reinstall Docker Desktop
brew install --cask docker
```

**Note:** If you have Docker installed via other means (e.g., Colima, Podman), you may need to uninstall those first.

### Start Docker Desktop

```bash
# Open Docker Desktop
open -a Docker

# OR manually: Applications > Docker
```

Wait for Docker Desktop to start (whale icon in menu bar should be steady, not animating).

Verify Docker is running:
```bash
docker --version
docker compose version
```

## Testing Docker Setup

### 1. Verify Docker is Running

```bash
docker --version
docker compose version  # or docker-compose --version
```

### 2. Test Docker Build

```bash
# Build the image (this will take 10-15 minutes first time)
docker build -t qse-demos:test .

# Check if build succeeded
docker images | grep qse-demos
```

### 3. Test Docker Run

```bash
# Run the container
docker run -d \
  --name qse-demos-test \
  -p 5001:5001 \
  qse-demos:test

# Check if container is running
docker ps | grep qse-demos

# View logs
docker logs qse-demos-test

# Test the application
curl http://localhost:5001

# Stop and remove test container
docker stop qse-demos-test
docker rm qse-demos-test
```

### 4. Test Docker Compose

```bash
# Using newer Docker (with compose plugin)
docker compose up -d

# OR using older Docker (standalone)
docker-compose up -d

# Check status
docker compose ps

# View logs
docker compose logs -f

# Test the application
open http://localhost:5001

# Stop
docker compose down
```

### 5. Verify Binaries Work

```bash
# Test NIST STS binary
docker run --rm qse-demos:test ./sts-2.1.2/assess --help

# Test Dieharder binary
docker run --rm qse-demos:test ./dieharder/dieharder/dieharder -h
```

## Common Issues

### macOS "Malware Blocked" Alert (com.docker.vmnetd)

If you see repeated "Malware Blocked" alerts for Docker components:

**Quick Fix:**
```bash
# Stop Docker processes
pkill -f Docker

# Run the fix script
./fix_docker_macos_security.sh

# Then manually allow in System Settings:
# System Settings > Privacy & Security > Allow Docker components
```

**Detailed Steps:**
1. Stop Docker: `pkill -f Docker`
2. Open System Settings > Privacy & Security
3. Scroll to "Security" section
4. Find blocked Docker entries and click "Allow" or "Open Anyway"
5. Remove quarantine: `sudo xattr -cr /Applications/Docker.app`
6. Restart Docker Desktop

**Alternative:** Download Docker Desktop directly from docker.com instead of Homebrew to avoid quarantine issues.

### Build Fails on NIST STS
- Check that `sts-2.1.2/makefile` exists
- Verify all source files are present

### Build Fails on Dieharder
- Check internet connection (clones from GitHub)
- Verify GSL is installed in builder stage

### Container Starts but App Doesn't Work
- Check logs: `docker logs qse-demos-test`
- Verify port mapping: `docker port qse-demos-test`
- Check if app found free port (might not be 5001)

### Health Check Fails
- The healthcheck uses Python's urllib (no extra dependencies)
- Increase `start_period` if app takes time to start

## Production Readiness Checklist

- [ ] Docker build completes successfully
- [ ] Container starts and app is accessible
- [ ] NIST STS binary works in container
- [ ] Dieharder binary works in container
- [ ] Volumes mount correctly (results persist)
- [ ] Health check passes
- [ ] No errors in logs
- [ ] Can access web UI from browser

## Next Steps After Testing

Once Docker is working locally:
1. Test with actual entropy endpoint
2. Run a full STS test in container
3. Run a full Dieharder test in container
4. Verify results are saved to mounted volumes
5. Commit and push to git
6. Deploy to production environment
