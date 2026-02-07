# Quick Setup Guide

## Option 1: Automated Setup Script (No Docker Required)

The easiest way to get started without Docker:

```bash
chmod +x setup.sh
./setup.sh
```

This script will:
- Install all system dependencies
- Set up Python virtual environment
- Build NIST STS and Dieharder binaries
- Verify everything is working

Then run:
```bash
source .env/bin/activate
python3 web_demo_app.py
```

## Option 2: Docker (Recommended for Production)

If you have Docker installed:

```bash
# Newer Docker (with compose plugin)
docker compose up -d

# Older Docker (standalone docker-compose)
docker-compose up -d
```

The app will be available at `http://localhost:5001`

## Option 3: Manual Setup

See [DEPLOYMENT.md](DEPLOYMENT.md) for detailed manual setup instructions.

## Troubleshooting

**Docker not found?**
- Install Docker Desktop from https://www.docker.com/products/docker-desktop
- Or use the `setup.sh` script instead (no Docker needed)

**Build failures?**
- Ensure you have build tools installed (gcc, make, autoconf, automake, libtool)
- On macOS: `brew install autoconf automake libtool gsl`
- On Linux: `sudo apt-get install build-essential autoconf automake libtool libgsl-dev`

**Need help?**
- Check [DEPLOYMENT.md](DEPLOYMENT.md) for detailed troubleshooting
- Verify all prerequisites are installed
