# QSE Demos Deployment Guide

This guide covers two deployment approaches:
1. **Docker** (Recommended for production/consistent environments)
2. **Manual Setup** (For local development)

---

## 🐳 Docker Deployment (Recommended)

### Prerequisites
- Docker 20.10+ (includes Docker Compose plugin)
- OR Docker Compose 2.0+ (standalone, older versions)

### Installing Docker

**macOS:**
```bash
# Install Docker Desktop (includes docker compose)
brew install --cask docker
# Or download from https://www.docker.com/products/docker-desktop
```

**Linux (Ubuntu/Debian):**
```bash
# Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh

# Add user to docker group (logout/login required)
sudo usermod -aG docker $USER
```

**Verify installation:**
```bash
docker --version
docker compose version  # Newer Docker (plugin)
# OR
docker-compose --version  # Older standalone version
```

### Quick Start

#### Option 1: Using Docker Compose (Easiest)

**For newer Docker (with compose plugin):**
```bash
# Build and start the container
docker compose up -d

# View logs
docker compose logs -f

# Stop the container
docker compose down
```

**For older Docker (standalone docker-compose):**
```bash
# Build and start the container
docker-compose up -d

# View logs
docker-compose logs -f

# Stop the container
docker-compose down
```

The application will be available at `http://localhost:5001`

#### Option 2: Using Docker directly

```bash
# Build the image
docker build -t qse-demos .

# Run the container
docker run -d \
  --name qse-demos \
  -p 5001:5001 \
  -v $(pwd)/sts-2.1.2/sts-results:/app/sts-2.1.2/sts-results \
  -v $(pwd)/dieharder/dieharder-results:/app/dieharder/dieharder-results \
  qse-demos

# View logs
docker logs -f qse-demos

# Stop the container
docker stop qse-demos
docker rm qse-demos
```

### Environment Variables

Set environment variables in `docker-compose.yml` or via `-e` flag:

```bash
docker run -d \
  -p 5001:5001 \
  -e ENTROPY_ENDPOINT=http://your-api:8888/entropy \
  qse-demos
```

### Persisting Results

Mount volumes to persist test results:

```bash
docker run -d \
  -p 5001:5001 \
  -v $(pwd)/sts-results:/app/sts-2.1.2/sts-results \
  -v $(pwd)/dieharder-results:/app/dieharder/dieharder-results \
  qse-demos
```

### Building for Different Platforms

```bash
# For ARM64 (Apple Silicon, AWS Graviton)
docker build --platform linux/arm64 -t qse-demos:arm64 .

# For AMD64 (Intel/AMD x86_64)
docker build --platform linux/amd64 -t qse-demos:amd64 .
```

---

## 🛠️ Manual Setup (Local Development)

### Prerequisites
- Python 3.10+
- Build tools: `gcc`, `make`, `autoconf`, `automake`, `libtool`
- GSL (GNU Scientific Library)

### Quick Setup

Run the automated setup script:

```bash
chmod +x setup.sh
./setup.sh
```

This script will:
1. Install system dependencies (via Homebrew on macOS, apt/yum/dnf on Linux)
2. Create Python virtual environment
3. Install Python packages
4. Build NIST STS binary
5. Build Dieharder binary

### Manual Steps (if setup.sh doesn't work)

#### 1. Install System Dependencies

**macOS:**
```bash
brew install autoconf automake libtool gsl
```

**Ubuntu/Debian:**
```bash
sudo apt-get update
sudo apt-get install -y build-essential autoconf automake libtool libgsl-dev python3-pip python3-venv
```

**CentOS/RHEL:**
```bash
sudo yum install -y gcc make autoconf automake libtool gsl-devel python3-pip
```

#### 2. Install Python Dependencies

```bash
python3 -m venv .env
source .env/bin/activate
pip install -r requirements.txt
```

#### 3. Build NIST STS

```bash
cd sts-2.1.2
make
cd ..
```

#### 4. Build Dieharder

```bash
# Clone if not already present
if [ ! -d "dieharder" ]; then
    git clone https://github.com/eddelbuettel/dieharder.git
fi

cd dieharder
rm -rf .git  # Remove git to avoid submodule issues
./autogen.sh

# macOS
./configure --prefix=/usr/local CPPFLAGS="-I/opt/homebrew/include" LDFLAGS="-L/opt/homebrew/lib"

# Linux
./configure --prefix=/usr/local

make
cd ..
```

#### 5. Run the Application

```bash
source .env/bin/activate
python3 web_demo_app.py
```

Or use the convenience script:
```bash
./start_web_demo.sh
```

---

## 🔍 Verification

After setup, verify everything works:

```bash
# Check Python packages
python3 -c "import flask, cryptography; print('✅ Python packages OK')"

# Check NIST STS binary
./sts-2.1.2/assess --help

# Check Dieharder binary
./dieharder/dieharder/dieharder -h
```

---

## 📦 Production Deployment

### Docker on Cloud Platforms

**Note:** If Docker is not installed or you prefer not to use it, you can use the `setup.sh` script instead (see Manual Setup section below).

**AWS ECS/Fargate:**
```bash
# Build and push to ECR
aws ecr create-repository --repository-name qse-demos
docker tag qse-demos:latest <account>.dkr.ecr.<region>.amazonaws.com/qse-demos:latest
docker push <account>.dkr.ecr.<region>.amazonaws.com/qse-demos:latest
```

**Google Cloud Run:**
```bash
gcloud builds submit --tag gcr.io/<project>/qse-demos
gcloud run deploy qse-demos --image gcr.io/<project>/qse-demos --platform managed
```

**Azure Container Instances:**
```bash
az acr build --registry <registry> --image qse-demos:latest .
az container create --resource-group <rg> --name qse-demos --image <registry>.azurecr.io/qse-demos:latest
```

### Kubernetes

Create `k8s-deployment.yaml`:
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: qse-demos
spec:
  replicas: 1
  selector:
    matchLabels:
      app: qse-demos
  template:
    metadata:
      labels:
        app: qse-demos
    spec:
      containers:
      - name: qse-demos
        image: qse-demos:latest
        ports:
        - containerPort: 5001
        env:
        - name: ENTROPY_ENDPOINT
          value: "http://your-api:8888/entropy"
        volumeMounts:
        - name: results
          mountPath: /app/sts-2.1.2/sts-results
        - name: dieharder-results
          mountPath: /app/dieharder/dieharder-results
      volumes:
      - name: results
        persistentVolumeClaim:
          claimName: qse-demos-results
      - name: dieharder-results
        persistentVolumeClaim:
          claimName: qse-demos-dieharder-results
---
apiVersion: v1
kind: Service
metadata:
  name: qse-demos
spec:
  selector:
    app: qse-demos
  ports:
  - port: 80
    targetPort: 5001
  type: LoadBalancer
```

---

## 🐛 Troubleshooting

### Build Failures

**NIST STS build fails:**
- Ensure `make` and `gcc` are installed
- Check `sts-2.1.2/makefile` exists

**Dieharder build fails:**
- Ensure GSL is installed: `brew install gsl` (macOS) or `apt-get install libgsl-dev` (Linux)
- On macOS, use CPPFLAGS and LDFLAGS for Homebrew paths
- Check autoconf/automake versions are compatible

### Runtime Issues

**Port already in use:**
- The app automatically finds a free port starting from 5001
- Or set `PORT` environment variable

**Binary not found:**
- Verify binaries exist: `ls -la sts-2.1.2/assess` and `ls -la dieharder/dieharder/dieharder`
- Rebuild if missing: `cd sts-2.1.2 && make`

**Permission denied:**
- Make scripts executable: `chmod +x setup.sh start_web_demo.sh`
- Make binaries executable: `chmod +x sts-2.1.2/assess dieharder/dieharder/dieharder`

---

## 📝 Notes

- **Docker is recommended** for consistent deployments across different environments
- **Setup script** is useful for local development and quick iteration
- Binaries are built during Docker build, so the image is self-contained
- Results directories are excluded from git but can be persisted via volumes
- The application automatically finds available ports to avoid conflicts
