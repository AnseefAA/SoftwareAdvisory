from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from logging.config import dictConfig
from app.core.config import LOGGING_CONFIG
from dotenv import load_dotenv
import os

# Load environment variables from .env file
load_dotenv()

# Apply Logging Configuration
dictConfig(LOGGING_CONFIG)

app = FastAPI(
    title="Advisory Intelligence API",
    description="Targeted Remediation API for Security Advisories",
    version="1.0.0"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Import and include only advisory routes
from app.routes.v1 import advisory_routes

app.include_router(advisory_routes.router, prefix="/api/v1", tags=["Advisory Remediation"])

@app.get("/")
async def root():
    """Root endpoint with API information."""
    return {
        "name": "Advisory Intelligence API",
        "version": "1.0.0",
        "description": "Targeted remediation API for security advisories",
        "endpoints": {
            "docs": "/docs",
            "remediation": {
                "generate_targeted": "/api/v1/advisory/remediation/generate-targeted"
            }
        }
    }

@app.on_event("startup")
async def startup_event():
    """Log startup information"""
    import logging
    logger = logging.getLogger(__name__)
    
    # Log database configuration
    db_type = os.getenv("DB_TYPE", "sqlite")
    if db_type == "postgresql":
        db_host = os.getenv("DB_HOST", "localhost")
        db_name = os.getenv("DB_NAME", "advisory_intelligence")
        logger.info(f"🗄️  Database: PostgreSQL at {db_host}/{db_name}")
    else:
        db_name = os.getenv("DB_NAME", "./advisory_intelligence.db")
        logger.info(f"🗄️  Database: SQLite at {db_name}")
    
    logger.info("✅ Advisory Intelligence API started successfully")

@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy", "service": "Advisory Intelligence API"}

# Made with Bob
