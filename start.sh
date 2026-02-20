#!/bin/bash

# AdvisoryIntelligence - Start Script
# Starts the FastAPI application with uvicorn

echo "Starting AdvisoryIntelligence API Server..."
echo "=========================================="

# Check if .env file exists
if [ ! -f .env ]; then
    echo "ERROR: .env file not found!"
    echo "Please copy .env.example to .env and configure your settings:"
    echo "  cp .env.example .env"
    exit 1
fi

# Check if virtual environment exists
if [ ! -d ".venv" ]; then
    echo "Virtual environment not found. Creating one..."
    python3 -m venv .venv
    source .venv/bin/activate
    echo "Installing dependencies..."
    pip install -r requirements.txt
else
    source .venv/bin/activate
fi

# Check if required packages are installed
python -c "import fastapi" 2>/dev/null
if [ $? -ne 0 ]; then
    echo "Installing dependencies..."
    pip install -r requirements.txt
fi

echo ""
echo "Starting server on http://0.0.0.0:8000"
echo "API Documentation: http://0.0.0.0:8000/docs"
echo "Available Endpoint:"
echo "  POST /api/v1/advisory/remediation/generate-targeted"
echo ""
echo "Press Ctrl+C to stop the server"
echo "=========================================="
echo ""

# Start the FastAPI application with uvicorn
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload

# Made with Bob
