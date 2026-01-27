#!/usr/bin/env bash
#
# QSE Demos Setup Script
# Installs all dependencies and builds required binaries
# Optimized for EC2 Linux servers (Amazon Linux 2/2023, Ubuntu)
#
set -euo pipefail

echo "============================================"
echo "  QSE Demos Setup Script"
echo "============================================"
echo

# Detect OS
OS="$(uname -s)"
if [[ "$OS" == "Darwin" ]]; then
    OS_TYPE="macos"
    PKG_MGR="brew"
elif [[ "$OS" == "Linux" ]]; then
    OS_TYPE="linux"
    # Detect Linux package manager (EC2 compatible)
    if command -v apt-get &> /dev/null; then
        PKG_MGR="apt"
    elif command -v yum &> /dev/null; then
        PKG_MGR="yum"
    elif command -v dnf &> /dev/null; then
        PKG_MGR="dnf"
    else
        echo "❌ Unsupported Linux distribution. Please install dependencies manually."
        exit 1
    fi
else
    echo "❌ Unsupported OS: $OS"
    exit 1
fi

echo "Detected OS: $OS_TYPE"
echo "Package manager: $PKG_MGR"
echo

# Check for Python 3
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is required but not found. Please install Python 3.10+ first."
    exit 1
fi

PYTHON_VERSION=$(python3 --version | cut -d' ' -f2 | cut -d'.' -f1,2)
echo "✅ Python version: $(python3 --version)"
echo

# Get the script directory (works on EC2)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"
echo "Working directory: $SCRIPT_DIR"
echo

# Install system dependencies
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Step 1/6: Installing system dependencies"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo

if [[ "$OS_TYPE" == "macos" ]]; then
    if ! command -v brew &> /dev/null; then
        echo "❌ Homebrew is required. Install from https://brew.sh"
        exit 1
    fi
    
    echo "Installing build tools and GSL via Homebrew..."
    brew install autoconf automake libtool gsl || {
        echo "⚠️  Some packages may already be installed. Continuing..."
    }
elif [[ "$OS_TYPE" == "linux" ]]; then
    if [[ "$PKG_MGR" == "apt" ]]; then
        echo "Installing build tools and GSL via apt (Ubuntu/Debian)..."
        sudo apt-get update
        sudo apt-get install -y \
            build-essential \
            autoconf \
            automake \
            libtool \
            libgsl-dev \
            python3-pip \
            python3-venv \
            git \
            wget \
            file \
            || {
            echo "⚠️  Some packages may already be installed. Continuing..."
        }
    elif [[ "$PKG_MGR" == "yum" ]]; then
        echo "Installing build tools and GSL via yum (Amazon Linux 2/RHEL 7)..."
        sudo yum groupinstall -y "Development Tools" || true
        sudo yum install -y \
            gcc \
            make \
            autoconf \
            automake \
            libtool \
            gsl-devel \
            python3 \
            python3-pip \
            git \
            wget \
            file \
            || {
            echo "⚠️  Some packages may already be installed. Continuing..."
        }
    elif [[ "$PKG_MGR" == "dnf" ]]; then
        echo "Installing build tools and GSL via dnf (Amazon Linux 2023/RHEL 8+)..."
        sudo dnf groupinstall -y "Development Tools" || true
        sudo dnf install -y \
            gcc \
            make \
            autoconf \
            automake \
            libtool \
            gsl-devel \
            python3 \
            python3-pip \
            git \
            wget \
            file \
            || {
            echo "⚠️  Some packages may already be installed. Continuing..."
        }
    fi
fi

echo "✅ System dependencies installed"
echo

# Install Python dependencies
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Step 2/6: Installing Python dependencies"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo

if [[ -d ".env" ]]; then
    echo "Virtual environment exists. Activating..."
    source .env/bin/activate
else
    echo "Creating Python virtual environment..."
    python3 -m venv .env
    source .env/bin/activate
fi

echo "Upgrading pip..."
pip install --upgrade pip setuptools wheel

echo "Installing Python packages from requirements.txt..."
if [[ -f "requirements.txt" ]]; then
    pip install -r requirements.txt
else
    echo "⚠️  requirements.txt not found. Installing basic packages..."
    pip install flask cryptography requests
fi

echo "✅ Python dependencies installed"
echo

# Create necessary directories
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Step 3/6: Creating directory structure"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo

echo "Creating STS directories..."
mkdir -p sts-2.1.2/entropy-streams/qse
mkdir -p sts-2.1.2/entropy-streams/system
mkdir -p sts-2.1.2/data
mkdir -p sts-2.1.2/sts-results/qse
mkdir -p sts-2.1.2/sts-results/system
mkdir -p sts-2.1.2/sts-results/past-reports
mkdir -p sts-2.1.2/experiments/AlgorithmTesting

echo "Creating Dieharder directories..."
mkdir -p dieharder/entropy-streams/qse
mkdir -p dieharder/entropy-streams/system
mkdir -p dieharder/data
mkdir -p dieharder/dieharder-results/qse
mkdir -p dieharder/dieharder-results/system
mkdir -p dieharder/dieharder-results/past-reports

echo "Setting permissions..."
chmod -R 755 sts-2.1.2/experiments
chmod -R 755 sts-2.1.2/sts-results
chmod -R 755 dieharder/dieharder-results

echo "✅ Directory structure created"
echo

# Build NIST STS binary
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Step 4/6: Building NIST STS binary"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo

if [[ -f "sts-2.1.2/assess" ]]; then
    echo "✅ NIST STS binary already exists"
    # Verify it's executable
    if [[ -x "sts-2.1.2/assess" ]]; then
        echo "   Binary is executable"
    else
        echo "   Making binary executable..."
        chmod +x sts-2.1.2/assess
    fi
else
    echo "Building NIST STS..."
    cd sts-2.1.2
    
    # Clean any previous build artifacts
    make clean 2>/dev/null || true
    
    # Build
    if make; then
        chmod +x assess
        echo "✅ NIST STS binary built successfully"
        
        # Verify binary type (should be ELF on Linux)
        if [[ "$OS_TYPE" == "linux" ]]; then
            if file assess | grep -q "ELF"; then
                echo "   ✅ Verified: Linux ELF binary"
            else
                echo "   ⚠️  Warning: Binary type may be incorrect"
            fi
        fi
    else
        echo "❌ Failed to build NIST STS binary"
        echo "   Check build errors above"
        exit 1
    fi
    cd ..
fi
echo

# Build Dieharder binary
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Step 5/6: Building Dieharder binary"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo

# Check if dieharder binary exists (could be in dieharder/dieharder/dieharder or dieharder/dieharder)
DIEHARDER_BIN=""
if [[ -f "dieharder/dieharder/dieharder" ]]; then
    DIEHARDER_BIN="dieharder/dieharder/dieharder"
elif [[ -f "dieharder/dieharder" ]]; then
    DIEHARDER_BIN="dieharder/dieharder"
fi

if [[ -n "$DIEHARDER_BIN" ]] && [[ -f "$DIEHARDER_BIN" ]]; then
    echo "✅ Dieharder binary already exists at: $DIEHARDER_BIN"
    # Verify it's executable
    if [[ -x "$DIEHARDER_BIN" ]]; then
        echo "   Binary is executable"
    else
        echo "   Making binary executable..."
        chmod +x "$DIEHARDER_BIN"
    fi
else
    # Check if dieharder directory exists but is incomplete
    if [[ -d "dieharder" ]] && [[ ! -d "dieharder/dieharder" ]]; then
        echo "⚠️  Found incomplete dieharder directory. Removing..."
        rm -rf dieharder
    fi
    
    if [[ ! -d "dieharder" ]]; then
        echo "Cloning dieharder repository..."
        git clone https://github.com/eddelbuettel/dieharder.git dieharder-temp
        mv dieharder-temp dieharder
    fi
    
    echo "Building Dieharder..."
    cd dieharder
    
    # Remove .git to avoid submodule issues
    if [[ -d ".git" ]]; then
        rm -rf .git
    fi
    
    # Clean previous build
    make clean 2>/dev/null || true
    make distclean 2>/dev/null || true
    
    # Configure and build
    if [[ "$OS_TYPE" == "macos" ]]; then
        echo "Running autogen.sh..."
        ./autogen.sh
        echo "Configuring for macOS..."
        ./configure --prefix=/usr/local CPPFLAGS="-I/opt/homebrew/include" LDFLAGS="-L/opt/homebrew/lib"
    else
        echo "Running autogen.sh..."
        ./autogen.sh
        echo "Configuring for Linux..."
        ./configure --prefix=/usr/local
    fi
    
    echo "Compiling..."
    if make -j$(nproc 2>/dev/null || echo 2); then
        # Find the binary location
        if [[ -f "dieharder/dieharder" ]]; then
            chmod +x dieharder/dieharder
            echo "✅ Dieharder binary built successfully at: dieharder/dieharder"
        elif [[ -f "dieharder" ]]; then
            chmod +x dieharder
            echo "✅ Dieharder binary built successfully at: dieharder"
        else
            echo "⚠️  Binary built but location unclear. Searching..."
            find . -name "dieharder" -type f -executable 2>/dev/null | head -1
        fi
        
        # Verify binary type (should be ELF on Linux)
        if [[ "$OS_TYPE" == "linux" ]]; then
            BIN_PATH=$(find . -name "dieharder" -type f -executable 2>/dev/null | head -1)
            if [[ -n "$BIN_PATH" ]] && file "$BIN_PATH" | grep -q "ELF"; then
                echo "   ✅ Verified: Linux ELF binary"
            fi
        fi
    else
        echo "❌ Failed to build Dieharder binary"
        echo "   Check build errors above"
        exit 1
    fi
    cd ..
fi
echo

# Verify installation
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Step 6/6: Verifying installation"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo

echo "Checking binaries..."
if [[ -f "sts-2.1.2/assess" ]] && [[ -x "sts-2.1.2/assess" ]]; then
    SIZE=$(ls -lh sts-2.1.2/assess | awk '{print $5}')
    echo "✅ NIST STS: $SIZE (executable)"
    
    # Test binary
    if sts-2.1.2/assess --help &>/dev/null || sts-2.1.2/assess -h &>/dev/null; then
        echo "   ✅ Binary is functional"
    fi
else
    echo "❌ NIST STS binary not found or not executable"
    exit 1
fi

# Check for dieharder binary in multiple possible locations
DIEHARDER_BIN=""
if [[ -f "dieharder/dieharder/dieharder" ]] && [[ -x "dieharder/dieharder/dieharder" ]]; then
    DIEHARDER_BIN="dieharder/dieharder/dieharder"
elif [[ -f "dieharder/dieharder" ]] && [[ -x "dieharder/dieharder" ]]; then
    DIEHARDER_BIN="dieharder/dieharder"
fi

if [[ -n "$DIEHARDER_BIN" ]]; then
    SIZE=$(ls -lh "$DIEHARDER_BIN" | awk '{print $5}')
    echo "✅ Dieharder: $SIZE (executable at $DIEHARDER_BIN)"
    
    # Test binary
    if "$DIEHARDER_BIN" -h &>/dev/null || "$DIEHARDER_BIN" --help &>/dev/null; then
        echo "   ✅ Binary is functional"
    fi
else
    echo "❌ Dieharder binary not found or not executable"
    exit 1
fi

echo
echo "Checking Python packages..."
if python3 -c "import flask, cryptography; print('✅ Flask and cryptography installed')" 2>/dev/null; then
    echo "✅ Core Python packages verified"
else
    echo "❌ Python packages missing"
    echo "   Try: pip install -r requirements.txt"
    exit 1
fi

echo
echo "Checking directory structure..."
MISSING_DIRS=0
for dir in "sts-2.1.2/experiments/AlgorithmTesting" \
           "sts-2.1.2/sts-results/past-reports" \
           "dieharder/dieharder-results/past-reports"; do
    if [[ ! -d "$dir" ]]; then
        echo "❌ Missing directory: $dir"
        MISSING_DIRS=$((MISSING_DIRS + 1))
    fi
done

if [[ $MISSING_DIRS -eq 0 ]]; then
    echo "✅ All required directories exist"
else
    echo "⚠️  Some directories are missing. Creating them..."
    mkdir -p sts-2.1.2/experiments/AlgorithmTesting
    mkdir -p sts-2.1.2/sts-results/past-reports
    mkdir -p dieharder/dieharder-results/past-reports
    chmod -R 755 sts-2.1.2/experiments sts-2.1.2/sts-results dieharder/dieharder-results
    echo "✅ Directories created"
fi

echo
echo "============================================"
echo "  ✅ Setup Complete!"
echo "============================================"
echo
echo "Installation Summary:"
echo "  • System dependencies: ✅"
echo "  • Python packages: ✅"
echo "  • NIST STS binary: ✅"
echo "  • Dieharder binary: ✅"
echo "  • Directory structure: ✅"
echo
echo "To run the web demo:"
echo "  source .env/bin/activate  # if not already activated"
echo "  python3 web_demo_app.py"
echo
echo "Or use the convenience script:"
echo "  ./start_web_demo.sh"
echo
echo "For EC2 deployment, ensure:"
echo "  • Security groups allow HTTP/HTTPS traffic"
echo "  • Port 5000 (or configured port) is open"
echo "  • Consider using a process manager (systemd, supervisor)"
echo
