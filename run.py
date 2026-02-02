"""
Application runner script for CaaS Prototype.

This script starts the FastAPI application using uvicorn.
"""

import uvicorn
import sys
import os

# Add the project root to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.config import settings


def main():
    """
    Main function to run the application.
    """
    print(f"[START] Starting {settings.app_name} v{settings.app_version}")
    print(f"[ENV] Environment: {settings.environment}")
    print(f"[SERVER] Server: http://{settings.host}:{settings.port}")
    print(f"[DOCS] API Docs: http://{settings.host}:{settings.port}/api/docs")
    print(f"[HEALTH] Health Check: http://{settings.host}:{settings.port}/api/health")
    print("\n" + "="*60 + "\n")

    # Run the application
    uvicorn.run(
        "app.main:app",
        host=settings.host,
        port=settings.port,
        reload=settings.debug and settings.environment == "development",
        workers=1 if settings.debug else settings.workers,
        log_level=settings.log_level.lower(),
        access_log=True,
    )


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[EXIT] Shutting down gracefully...")
        sys.exit(0)
    except Exception as e:
        print(f"\n\n[ERROR] Error starting application: {e}")
        sys.exit(1)
