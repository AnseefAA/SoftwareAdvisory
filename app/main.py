from fastapi import FastAPI
from app.routes.v1 import cve_routes, exposures, advisory_routes
from langchain.globals import set_verbose, set_debug
from fastapi.middleware.cors import CORSMiddleware
from logging.config import dictConfig
from app.core.config import LOGGING_CONFIG

# Apply Logging Configuration
dictConfig(LOGGING_CONFIG)

# Enable/Disable LangChain verbose
set_debug(False)
set_verbose(False)

app = FastAPI(
    title="Concert GenAI POC",
    description="Vulnerability Intelligence Platform with AI-powered analysis and GraphQL API",
    version="1.0.0"
)

# Allows all origins, methods and headers
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow all origins
    allow_credentials=True,
    allow_methods=["*"],  # Allow all methods
    allow_headers=["*"],  # Allow all headers
)

# Include REST API routers
app.include_router(cve_routes.router)
app.include_router(exposures.router)
app.include_router(advisory_routes.router, prefix="/api/v1", tags=["Advisory Remediation"])

# Add GraphQL endpoint
try:
    from strawberry.fastapi import GraphQLRouter
    from app.graphql.schema import schema
    
    graphql_app = GraphQLRouter(schema)
    app.include_router(graphql_app, prefix="/graphql")
    print("✅ GraphQL endpoint enabled at /graphql")
except ImportError:
    print("⚠️  Strawberry GraphQL not installed. Run: pip install strawberry-graphql[fastapi]")
except Exception as e:
    print(f"⚠️  GraphQL setup failed: {str(e)}")

@app.get("/")
async def root():
    """Root endpoint with API information."""
    return {
        "name": "Concert GenAI POC",
        "version": "1.0.0",
        "endpoints": {
            "rest_api": "/docs",
            "graphql": "/graphql",
            "graphql_playground": "/graphql (interactive)"
        }
    }

@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy", "service": "Concert GenAI POC"}