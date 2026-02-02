"""
Main FastAPI application for the CaaS (Crypto as a Service) prototype.

This module initializes and configures the FastAPI application with all
necessary middleware, routers, and startup/shutdown events.
"""

from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
import logging
import sys
import uuid
import os

from app.config import settings
from app.api.v1.router import api_router
from app.db.session import init_db


# Configure logging
logging.basicConfig(
    level=getattr(logging, settings.log_level.upper()),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
    ]
)

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Lifespan context manager for startup and shutdown events.

    Startup:
    - Initialize database (create tables if needed)
    - Log application startup

    Shutdown:
    - Log application shutdown
    - Clean up resources
    """
    # Startup
    logger.info(f"Starting {settings.app_name} v{settings.app_version}")
    logger.info(f"Environment: {settings.environment}")
    logger.info(f"Debug mode: {settings.debug}")

    # Initialize database
    try:
        init_db()
        logger.info("Database initialized successfully")
    except Exception as e:
        logger.error(f"Failed to initialize database: {e}")
        raise

    logger.info(f"[START] {settings.app_name} started successfully!")

    yield

    # Shutdown
    logger.info(f"Shutting down {settings.app_name}...")


# Create FastAPI application
app = FastAPI(
    title=settings.app_name,
    description="Crypto as a Service (CaaS) - A prototype REST API for cryptographic operations",
    version=settings.app_version,
    lifespan=lifespan,
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
)


# ============================================================================
# Middleware Configuration
# ============================================================================

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Request ID Middleware
@app.middleware("http")
async def add_request_id_middleware(request: Request, call_next):
    """
    Add a unique request ID to each request for tracing.
    """
    # Generate or extract request ID
    request_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))
    request.state.request_id = request_id

    # Process request
    response = await call_next(request)

    # Add request ID to response headers
    response.headers["X-Request-ID"] = request_id

    return response


# Logging Middleware
@app.middleware("http")
async def logging_middleware(request: Request, call_next):
    """
    Log all requests and responses.
    """
    # Get request ID
    request_id = getattr(request.state, "request_id", "unknown")

    # Log request
    logger.info(
        f"Request [{request_id}]: {request.method} {request.url.path} "
        f"from {request.client.host if request.client else 'unknown'}"
    )

    # Process request
    try:
        response = await call_next(request)

        # Log response
        logger.info(
            f"Response [{request_id}]: {response.status_code} "
            f"for {request.method} {request.url.path}"
        )

        return response

    except Exception as e:
        logger.error(
            f"Error [{request_id}]: {str(e)} "
            f"for {request.method} {request.url.path}"
        )
        raise


# ============================================================================
# Exception Handlers
# ============================================================================

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """
    Global exception handler for unhandled exceptions.
    """
    request_id = getattr(request.state, "request_id", "unknown")

    logger.error(
        f"Unhandled exception [{request_id}]: {str(exc)}",
        exc_info=True
    )

    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "error": {
                "code": "INTERNAL_SERVER_ERROR",
                "message": "An internal server error occurred",
                "request_id": request_id
            }
        }
    )


@app.exception_handler(ValueError)
async def value_error_handler(request: Request, exc: ValueError):
    """
    Handle ValueError exceptions.
    """
    request_id = getattr(request.state, "request_id", "unknown")

    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content={
            "error": {
                "code": "VALIDATION_ERROR",
                "message": str(exc),
                "request_id": request_id
            }
        }
    )


# ============================================================================
# Include API Routes
# ============================================================================

app.include_router(api_router)


# ============================================================================
# Root Endpoint
# ============================================================================

@app.get(
    "/",
    tags=["Root"],
    summary="Root endpoint",
    description="Welcome message and API information"
)
async def root():
    """
    Root endpoint providing basic API information.
    """
    return {
        "message": f"Welcome to {settings.app_name}",
        "version": settings.app_version,
        "environment": settings.environment,
        "docs": "/api/docs",
        "health": "/api/health",
        "web_interface": "/web"
    }


@app.get(
    "/web",
    tags=["Root"],
    summary="Web Interface",
    description="Serve the web interface for the CaaS API"
)
async def web_interface():
    """
    Serve the web interface HTML file.
    """
    web_file = os.path.join(os.path.dirname(os.path.dirname(__file__)), "web", "index.html")
    if os.path.exists(web_file):
        return FileResponse(web_file, media_type="text/html")
    else:
        return JSONResponse(
            status_code=404,
            content={"error": "Web interface not found"}
        )


# ============================================================================
# Application Info
# ============================================================================

if __name__ == "__main__":
    import uvicorn

    logger.info(f"Starting {settings.app_name} in development mode...")

    uvicorn.run(
        "app.main:app",
        host=settings.host,
        port=settings.port,
        reload=settings.debug,
        log_level=settings.log_level.lower(),
    )
