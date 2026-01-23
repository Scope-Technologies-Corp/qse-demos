#!/usr/bin/env bash
#
# QSE Demos Setup Script
# Installs all dependencies and builds required binaries
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
    # Detect Linux package manager
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

# Install system dependencies
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Step 1/5: Installing system dependencies"
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
        echo "Installing build tools and GSL via apt..."
        sudo apt-get update
        sudo apt-get install -y build-essential autoconf automake libtool libgsl-dev python3-pip python3-venv
    elif [[ "$PKG_MGR" == "yum" ]]; then
        echo "Installing build tools and GSL via yum..."
        sudo yum install -y gcc make autoconf automake libtool gsl-devel python3-pip
    elif [[ "$PKG_MGR" == "dnf" ]]; then
        echo "Installing build tools and GSL via dnf..."
        sudo dnf install -y gcc make autoconf automake libtool gsl-devel python3-pip
    fi
fi

echo "✅ System dependencies installed"
echo

# Install Python dependencies
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Step 2/5: Installing Python dependencies"
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

echo "Installing Python packages from requirements.txt..."
pip install --upgrade pip
pip install -r requirements.txt

echo "✅ Python dependencies installed"
echo

# Build NIST STS binary
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Step 3/5: Building NIST STS binary"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo

if [[ -f "sts-2.1.2/assess" ]]; then
    echo "✅ NIST STS binary already exists"
else
    echo "Building NIST STS..."
    cd sts-2.1.2
    if make; then
        echo "✅ NIST STS binary built successfully"
    else
        echo "❌ Failed to build NIST STS binary"
        exit 1
    fi
    cd ..
fi
echo

# Build Dieharder binary
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Step 4/5: Building Dieharder binary"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo

if [[ -f "dieharder/dieharder/dieharder" ]]; then
    echo "✅ Dieharder binary already exists"
else
    if [[ ! -d "dieharder" ]]; then
        echo "Cloning dieharder repository..."
        git clone https://github.com/eddelbuettel/dieharder.git
    fi
    
    echo "Building Dieharder..."
    cd dieharder
    
    # Remove .git to avoid submodule issues
    if [[ -d ".git" ]]; then
        rm -rf .git
    fi
    
    # Configure and build
    if [[ "$OS_TYPE" == "macos" ]]; then
        ./autogen.sh
        ./configure --prefix=/usr/local CPPFLAGS="-I/opt/homebrew/include" LDFLAGS="-L/opt/homebrew/lib"
    else
        ./autogen.sh
        ./configure --prefix=/usr/local
    fi
    
    if make; then
        echo "✅ Dieharder binary built successfully"
    else
        echo "❌ Failed to build Dieharder binary"
        exit 1
    fi
    cd ..
fi
echo

# Verify installation
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Step 5/5: Verifying installation"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo

echo "Checking binaries..."
if [[ -f "sts-2.1.2/assess" ]]; then
    echo "✅ NIST STS: $(ls -lh sts-2.1.2/assess | awk '{print $5}')"
else
    echo "❌ NIST STS binary not found"
fi

if [[ -f "dieharder/dieharder/dieharder" ]]; then
    echo "✅ Dieharder: $(ls -lh dieharder/dieharder/dieharder | awk '{print $5}')"
else
    echo "❌ Dieharder binary not found"
fi

echo
echo "Checking Python packages..."
python3 -c "import flask, cryptography; print('✅ Flask and cryptography installed')" || {
    echo "❌ Python packages missing"
    exit 1
}

echo
echo "============================================"
echo "  ✅ Setup Complete!"
echo "============================================"
echo
echo "To run the web demo:"
echo "  source .env/bin/activate  # if not already activated"
echo "  python3 web_demo_app.py"
echo
echo "Or use the convenience script:"
echo "  ./start_web_demo.sh"
echo
