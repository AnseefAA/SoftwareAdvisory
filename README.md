# Concert GenAI POC - FastAPI Application

A FastAPI-based application for CVE analysis and vulnerability management using IBM WatsonX AI.

## Prerequisites

- **pyenv** (Python version manager) - Will be installed automatically by start script if not present
- **Python 3.10.12** (specified in `.python-version`) - Will be installed via pyenv if not present
- **Git**
- **Homebrew** (macOS only, optional) - For easier pyenv installation

The start script will automatically check for and install pyenv and the required Python version if needed.

## Environment Variables

Create a `.env` file in the root directory with the following variables:

```bash
# IBM WatsonX Configuration
WATSONX_URL=https://us-south.ml.cloud.ibm.com
WATSONX_API_KEY=your_watsonx_api_key_here
WATSONX_API_PROJECT_ID=your_project_id_here
```

### Required Environment Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `WATSONX_URL` | IBM WatsonX API endpoint URL | `https://us-south.ml.cloud.ibm.com` |
| `WATSONX_API_KEY` | Your IBM WatsonX API key | `your_api_key_here` |
| `WATSONX_API_PROJECT_ID` | Your WatsonX project ID | `your_project_id_here` |

## Setup Instructions

### Option 1: Using the Start Script (Recommended)

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd concert-genai-poc
   ```

2. **Create the `.env` file**
   ```bash
   cp .env.example .env
   # Edit .env and add your actual credentials
   ```

3. **Run the start script**
   ```bash
   ./start.sh
   ```

   The start script will automatically:
   - Check if pyenv is installed (install if missing)
   - Check if required Python version (3.10.12) is installed (install if missing)
   - Set the local Python version using pyenv
   - Create a Python virtual environment (`.venv`)
   - Upgrade pip to the latest version
   - Install all dependencies from `requirements.txt`
   - Start the FastAPI application on `http://0.0.0.0:8000`

   **Note:** If pyenv is newly installed, you may need to restart your terminal or source your shell configuration file after the first run.

### Option 2: Manual Setup

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd concert-genai-poc
   ```

2. **Create and activate virtual environment**
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   ```

3. **Upgrade pip**
   ```bash
   pip install --upgrade pip
   ```

4. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

5. **Create the `.env` file**
   ```bash
   cp .env.example .env
   # Edit .env and add your actual credentials
   ```

6. **Run the application**
   ```bash
   uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
   ```

## Running the Application

### Start the Application
```bash
./start.sh
```

The application will be available at:
- **API**: http://localhost:8000
- **Interactive API Documentation (Swagger)**: http://localhost:8000/docs
- **Alternative API Documentation (ReDoc)**: http://localhost:8000/redoc

### Stop the Application
```bash
./stop.sh
```

This will gracefully terminate the uvicorn process and deactivate the virtual environment.

