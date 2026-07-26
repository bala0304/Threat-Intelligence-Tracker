"""Feed ingestion API routes."""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from src.database.db import get_db
from src.feeds.orchestrator import FeedOrchestrator
from src.api.schemas import IngestionStatus
from loguru import logger

router = APIRouter(prefix="/api/v1/feeds", tags=["feed-ingestion"])


@router.post("/ingest/all", response_model=dict)
def ingest_all_feeds(db: Session = Depends(get_db)):
    """Ingest from all available threat intelligence feeds."""
    try:
        orchestrator = FeedOrchestrator(db)
        result = orchestrator.ingest_all()
        return result
    except Exception as e:
        logger.error(f"Feed ingestion error: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Feed ingestion failed: {str(e)}"
        )


@router.post("/ingest/{feed_name}", response_model=IngestionStatus)
def ingest_specific_feed(
    feed_name: str,
    db: Session = Depends(get_db)
):
    """Ingest from a specific threat intelligence feed."""
    try:
        orchestrator = FeedOrchestrator(db)
        result = orchestrator.ingest_specific(feed_name)
        
        if result.get('status') == 'error':
            raise HTTPException(status_code=400, detail=result.get('message', result.get('error')))
        
        return IngestionStatus(
            feed=feed_name,
            status=result.get('status', 'unknown'),
            records_ingested=result.get('records_ingested', 0),
            records_updated=result.get('records_updated', 0),
            errors=result.get('errors', 0)
        )
    except Exception as e:
        logger.error(f"Feed ingestion error for {feed_name}: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Feed ingestion failed: {str(e)}"
        )


@router.get("/available")
def get_available_feeds():
    """Get list of available feeds."""
    return {
        'feeds': [
            {
                'name': 'threatfox',
                'description': 'Live C2 IOCs from abuse.ch',
                'type': 'c2_indicators',
                'frequency': 'real-time'
            },
            {
                'name': 'urlhaus',
                'description': 'Malware distribution URLs',
                'type': 'malware_urls',
                'frequency': 'hourly'
            }
        ]
    }
