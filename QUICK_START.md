# AdvisoryIntelligence - Quick Start Guide

Get up and running with AdvisoryIntelligence in 5 minutes!

## Prerequisites Checklist

- [ ] Python 3.9+ installed
- [ ] PostgreSQL database running
- [ ] IBM WatsonX AI credentials
- [ ] Advisory data populated (from Advisory_Intelligence project)

## Step-by-Step Setup

### 1. Environment Setup (2 minutes)

```bash
# Navigate to project directory
cd AdvisoryIntelligence

# Create virtual environment
python3 -m venv .venv

# Activate virtual environment
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Database Configuration (1 minute)

```bash
# Copy environment template
cp .env.example .env

# Edit .env file with your settings
nano .env  # or use your preferred editor
```

Required settings in `.env`:
```env
DATABASE_URL=postgresql://user:password@localhost:5432/dbname
WATSONX_API_KEY=your_api_key_here
WATSONX_PROJECT_ID=your_project_id_here
WATSONX_URL=https://us-south.ml.cloud.ibm.com
```

### 3. Database Schema (1 minute)

```bash
# Run database schema
psql -U your_user -d your_database -f db.sql
```

### 4. Start the Server (30 seconds)

```bash
# Make start script executable (if not already)
chmod +x start.sh

# Start the server
./start.sh
```

The server will start on http://0.0.0.0:8000

### 5. Test the API (30 seconds)

Open your browser and go to:
- **API Documentation**: http://0.0.0.0:8000/docs
- **Health Check**: http://0.0.0.0:8000/health

## Quick Test

### Using cURL

```bash
curl -X POST "http://0.0.0.0:8000/api/v1/advisory/remediation/generate-targeted" \
  -H "Content-Type: application/json" \
  -d '{
    "advisory_id": "ALAS-2024-1234",
    "product": "Amazon Linux 2",
    "package": "runc"
  }'
```

### Using Swagger UI

1. Go to http://0.0.0.0:8000/docs
2. Click on the POST endpoint
3. Click "Try it out"
4. Enter request body:
   ```json
   {
     "advisory_id": "ALAS-2024-1234",
     "product": "Amazon Linux 2",
     "package": "runc"
   }
   ```
5. Click "Execute"

## Common Issues

### Issue: "Advisory not found in database"

**Solution**: Populate the database first using Advisory_Intelligence:

```bash
# In Advisory_Intelligence project
curl -X POST "http://0.0.0.0:8000/api/v1/intelligence/assess" \
  -H "Content-Type: application/json" \
  -d '{"advisory_id": "ALAS-2024-1234"}'
```

### Issue: "Database connection error"

**Solution**: Check PostgreSQL is running:

```bash
sudo systemctl status postgresql
```

### Issue: "WatsonX AI error"

**Solution**: Verify credentials in `.env`:
- Check API key is correct
- Verify project ID
- Ensure WatsonX service is accessible

## Next Steps

1. **Populate Database**: Use Advisory_Intelligence to populate advisory data
2. **Test Different Advisories**: Try various advisory IDs
3. **Integrate**: Use the API in your automation workflows
4. **Monitor**: Check logs for any issues

## API Endpoint

**POST** `/api/v1/advisory/remediation/generate-targeted`

**Request:**
```json
{
  "advisory_id": "string",
  "product": "string",
  "package": "string"
}
```

**Response:** Comprehensive remediation steps with metadata

## Support

- **Documentation**: See README.md for detailed information
- **API Docs**: http://0.0.0.0:8000/docs
- **Logs**: Check console output for debugging

---

**Made with Bob** 🤖