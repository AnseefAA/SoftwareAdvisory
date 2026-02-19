# Quick Setup Guide

## Prerequisites

- Python 3.9 or higher
- pip (Python package manager)
- IBM WatsonX AI account with API credentials

## Installation Steps

### 1. Navigate to Project Directory

```bash
cd Advisory_Intelligence
```

### 2. Create Virtual Environment

```bash
python -m venv .venv
```

### 3. Activate Virtual Environment

**On macOS/Linux:**
```bash
source .venv/bin/activate
```

**On Windows:**
```bash
.venv\Scripts\activate
```

### 4. Install Dependencies

```bash
pip install -r requirements.txt
```

### 5. Configure Environment Variables

```bash
cp .env.example .env
```

Edit `.env` file and add your credentials:

```env
# WatsonX AI Configuration
WATSONX_URL=https://us-south.ml.cloud.ibm.com
WATSONX_API_KEY=your_actual_api_key_here
WATSONX_API_PROJECT_ID=your_actual_project_id_here

# Database Configuration (SQLite for development)
DB_TYPE=sqlite
DB_NAME=./advisory_intelligence.db

# For PostgreSQL (production), use:
# DB_TYPE=postgresql
# DB_HOST=localhost
# DB_PORT=5432
# DB_NAME=advisory_intelligence
# DB_USERNAME=postgres
# DB_PASSWORD=your_password_here
```

### 6. Start the Server

**Using the start script (recommended):**
```bash
./start.sh
```

**Or manually:**
```bash
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

### 7. Verify Installation

Open your browser and navigate to:
- **API Documentation**: http://localhost:8000/docs
- **Health Check**: http://localhost:8000/health

You should see the Swagger UI with all 4 APIs listed.

## Stopping the Server

**Using the stop script:**
```bash
./stop.sh
```

**Or manually:**
Press `CTRL+C` in the terminal where the server is running.

## Testing the APIs

### Test 1: Health Check

```bash
curl http://localhost:8000/health
```

Expected response:
```json
{
  "status": "healthy",
  "service": "Advisory Intelligence API"
}
```

### Test 2: Fetch Intelligence

```bash
curl -X POST "http://localhost:8000/api/v1/intelligence/fetch" \
  -H "Content-Type: application/json" \
  -d '{"cveId": "CVE-2024-21626"}'
```

### Test 3: Assess Intelligence

```bash
curl -X POST "http://localhost:8000/api/v1/intelligence/assess" \
  -H "Content-Type: application/json" \
  -d '{"cveId": "CVE-2024-21626"}'
```

### Test 4: Get Structured Intelligence

```bash
curl -X POST "http://localhost:8000/api/v1/intelligence/structured" \
  -H "Content-Type: application/json" \
  -d '{"cveId": "CVE-2024-21626"}'
```

### Test 5: Generate Advisory Remediation (requires database setup)

```bash
curl -X POST "http://localhost:8000/api/v1/advisory/remediation/generate" \
  -H "Content-Type: application/json" \
  -d '{"advisory_id": "RHSA-2024:1234"}'
```

## Troubleshooting

### Issue: Module not found errors

**Solution:** Make sure you're in the virtual environment and all dependencies are installed:
```bash
source .venv/bin/activate  # or .venv\Scripts\activate on Windows
pip install -r requirements.txt
```

### Issue: WatsonX API authentication errors

**Solution:** Verify your credentials in `.env` file:
- Check that `WATSONX_API_KEY` is correct
- Verify `WATSONX_API_PROJECT_ID` is valid
- Ensure `WATSONX_URL` matches your region

### Issue: Database connection errors

**Solution:** For development, use SQLite (default):
```env
DB_TYPE=sqlite
DB_NAME=./advisory_intelligence.db
```

For production with PostgreSQL:
```env
DB_TYPE=postgresql
DB_HOST=localhost
DB_PORT=5432
DB_NAME=advisory_intelligence
DB_USERNAME=your_username
DB_PASSWORD=your_password
```

### Issue: Port 8000 already in use

**Solution:** Either stop the existing process or use a different port:
```bash
uvicorn app.main:app --reload --host 0.0.0.0 --port 8001
```

## Project Structure

```
Advisory_Intelligence/
├── app/
│   ├── core/              # Configuration
│   ├── db/                # Database models & operations
│   ├── routes/v1/         # API endpoints
│   ├── services/ai/       # AI/LLM services
│   ├── utils/             # Helper functions
│   ├── data/              # Data storage
│   └── main.py            # FastAPI app
├── start.sh               # Start server script
├── stop.sh                # Stop server script
├── requirements.txt       # Python dependencies
├── .env.example          # Environment template
└── README.md             # Full documentation
```

## Next Steps

1. ✅ Verify all APIs work using the Swagger UI at http://localhost:8000/docs
2. ✅ Test with real CVE IDs to fetch intelligence
3. ✅ Set up your database if using PostgreSQL
4. ✅ Review the README.md for detailed API documentation
5. ✅ Customize the prompts in `app/services/ai/prompts.py` if needed

## Support

For detailed API documentation, see [README.md](README.md)

For issues, check the logs in `app.log` file.