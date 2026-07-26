"""Main FastAPI application."""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from src.config import get_settings
from src.database.db import db_manager
from src.api.routes import router
from src.api.feeds_routes import router as feeds_router
from src.api.enrichment_routes import router as enrichment_router
from loguru import logger
import sys


def create_app() -> FastAPI:
    """Create and configure FastAPI application."""
    
    settings = get_settings()
    
    # Configure logging
    logger.remove()
    logger.add(
        sys.stderr,
        level=settings.log_level,
        format="<level>{level: <8}</level> | <cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - <level>{message}</level>"
    )
    
    # Initialize database
    db_manager.init_db()
    logger.info("Database initialized")
    
    # Create FastAPI app
    app = FastAPI(
        title="Threat Intelligence Tracker",
        description="Live adversary infrastructure tracking with C2 monitoring, pDNS, and threat feed ingestion",
        version="1.0.0"
    )
    
    # Add CORS middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    
    # Include routers
    app.include_router(router)
    app.include_router(feeds_router)
    app.include_router(enrichment_router)
    
    @app.on_event("startup")
    async def startup_event():
        logger.info("Threat Intelligence Tracker API starting up")
    
    @app.on_event("shutdown")
    async def shutdown_event():
        db_manager.close()
        logger.info("Threat Intelligence Tracker API shutting down")
    
    return app


app = create_app()
