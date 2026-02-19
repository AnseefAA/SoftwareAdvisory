#!/bin/bash

# Start script for Advisory Intelligence API

set -e  # Exit on error

echo "Starting Advisory Intelligence API..."

# Required Python version
REQUIRED_PYTHON_VERSION="3.10.12"
if [ -f ".python-version" ]; then
    REQUIRED_PYTHON_VERSION=$(cat .python-version)
fi

echo "Required Python version: $REQUIRED_PYTHON_VERSION"

# Function to install pyenv
install_pyenv() {
    echo "Installing pyenv..."
    if [[ "$OSTYPE" == "darwin"* ]]; then
        # macOS
        if command -v brew &> /dev/null; then
            brew install pyenv
        else
            echo "Homebrew not found. Installing pyenv via curl..."
            curl https://pyenv.run | bash
        fi
    else
        # Linux
        curl https://pyenv.run | bash
    fi
    
    # Add pyenv to PATH for current session
    export PYENV_ROOT="$HOME/.pyenv"
    export PATH="$PYENV_ROOT/bin:$PATH"
    eval "$(pyenv init -)"
    
    echo ""
    echo "⚠️  IMPORTANT: Add the following to your ~/.bashrc or ~/.zshrc:"
    echo "export PYENV_ROOT=\"\$HOME/.pyenv\""
    echo "export PATH=\"\$PYENV_ROOT/bin:\$PATH\""
    echo "eval \"\$(pyenv init -)\""
    echo ""
}

# Function to check if pyenv is installed
check_pyenv() {
    if ! command -v pyenv &> /dev/null; then
        echo "pyenv not found."
        read -p "Would you like to install pyenv? (y/n) " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            install_pyenv
        else
            echo "ERROR: pyenv is required to manage Python versions."
            echo "Please install pyenv manually: https://github.com/pyenv/pyenv#installation"
            exit 1
        fi
    else
        echo "✓ pyenv is installed"
        # Initialize pyenv for current session
        export PYENV_ROOT="$HOME/.pyenv"
        export PATH="$PYENV_ROOT/bin:$PATH"
        eval "$(pyenv init -)"
    fi
}

# Function to check and install required Python version
check_python_version() {
    echo "Checking Python version..."
    
    # Check if required version is installed via pyenv
    if ! pyenv versions --bare | grep -q "^${REQUIRED_PYTHON_VERSION}$"; then
        echo "Python $REQUIRED_PYTHON_VERSION not found in pyenv."
        read -p "Would you like to install Python $REQUIRED_PYTHON_VERSION? (y/n) " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            echo "Installing Python $REQUIRED_PYTHON_VERSION..."
            pyenv install $REQUIRED_PYTHON_VERSION
        else
            echo "ERROR: Python $REQUIRED_PYTHON_VERSION is required."
            exit 1
        fi
    else
        echo "✓ Python $REQUIRED_PYTHON_VERSION is installed"
    fi
    
    # Set local Python version
    pyenv local $REQUIRED_PYTHON_VERSION
    echo "✓ Using Python $REQUIRED_PYTHON_VERSION"
}

# Check if .env file exists
if [ ! -f ".env" ]; then
    echo "ERROR: .env file not found!"
    echo "Please create a .env file with the required environment variables."
    echo "You can copy .env.example to .env and update the values:"
    echo "  cp .env.example .env"
    echo "See README.md for details."
    exit 1
fi

# Load environment variables from .env file
echo "Loading environment variables from .env..."
set -a
source .env
set +a
echo "✓ Environment variables loaded"

# Check and setup pyenv
check_pyenv

# Check and install required Python version
check_python_version

# Get the Python executable from pyenv
PYTHON_BIN=$(pyenv which python)
echo "Using Python: $PYTHON_BIN"
echo "Python version: $($PYTHON_BIN --version)"

# Create virtual environment if it doesn't exist
if [ ! -d ".venv" ]; then
    echo "Creating virtual environment..."
    $PYTHON_BIN -m venv .venv
    echo "✓ Virtual environment created"
else
    echo "✓ Virtual environment already exists"
fi

# Activate virtual environment and upgrade pip
echo "Activating virtual environment and upgrading pip..."
source .venv/bin/activate
pip install --upgrade pip --quiet
echo "✓ pip upgraded"

# Install dependencies
echo "Installing dependencies (this may take a few minutes)..."
pip install -r requirements.txt
echo "✓ Dependencies installed"

# Create data directories if they don't exist
echo "Creating data directories..."
mkdir -p app/data/intelligence
mkdir -p app/data/intelligence_db
echo "✓ Data directories created"

# Start the application
echo ""
echo "=========================================="
echo "Starting uvicorn server..."
echo "API will be available at:"
echo "  - http://localhost:8000"
echo "  - http://localhost:8000/docs (Swagger UI)"
echo "  - http://localhost:8000/redoc (ReDoc)"
echo "  - http://localhost:8000/health (Health Check)"
echo "=========================================="
echo ""
echo "Available APIs:"
echo "  1. POST /api/v1/advisory/remediation/generate"
echo "  2. POST /api/v1/intelligence/assess"
echo "  3. POST /api/v1/intelligence/structured"
echo "  4. POST /api/v1/intelligence/fetch"
echo "=========================================="
echo ""

uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload

# Made with Bob
