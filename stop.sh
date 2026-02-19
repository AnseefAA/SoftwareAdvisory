#!/bin/bash

# Stop script for Advisory Intelligence API

echo "Stopping Advisory Intelligence API..."

# Find and kill the uvicorn process
PID=$(ps aux | grep "uvicorn app.main:app" | grep -v grep | awk '{print $2}')

if [ -z "$PID" ]; then
    echo "No running uvicorn process found."
else
    echo "Found uvicorn process with PID: $PID"
    kill -15 $PID
    echo "Sent SIGTERM to process $PID"
    
    # Wait a moment and check if process is still running
    sleep 2
    if ps -p $PID > /dev/null 2>&1; then
        echo "Process still running, forcing kill..."
        kill -9 $PID
        echo "Process forcefully terminated."
    else
        echo "Process stopped successfully."
    fi
fi

# Deactivate virtual environment if active
if [ -n "$VIRTUAL_ENV" ]; then
    echo "Deactivating virtual environment..."
    deactivate
fi

echo "Application stopped."

# Made with Bob
