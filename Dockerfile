# Use an official Python runtime as the base image
FROM python:3.10-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

# Set the working directory in the container
WORKDIR /app

# Install system dependencies required for building Python packages
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Create a virtual environment and install Python dependencies
ENV VENV_PATH="/app/venv"
RUN python -m venv ${VENV_PATH}
ENV PATH="${VENV_PATH}/bin:$PATH"

# Upgrade pip to ensure compatibility with modern packages
RUN pip install --upgrade pip

# Pre-install pyarrow to avoid runtime errors
RUN pip install --no-cache-dir pyarrow

# Copy requirements.txt to leverage Docker caching
COPY requirements.txt /app/

# Install Python dependencies in the virtual environment
RUN pip install --no-cache-dir -r requirements.txt

# Copy the application code
COPY . /app/

# Expose the port that FastAPI will run on
EXPOSE 8000

# Command to run the FastAPI app using Gunicorn
CMD ["gunicorn", "-w", "3", "-k", "uvicorn.workers.UvicornWorker", "app.main:app", "--bind", "0.0.0.0:8000", "--log-level", "debug", "--timeout", "90"]