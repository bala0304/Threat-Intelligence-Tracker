"""Orchestrator for managing all feed ingestions."""
from typing import Dict, Any
from datetime import datetime
from sqlalchemy.orm import Session
from loguru import logger
from src.feeds.threatfox_ingestor import ThreatFoxIngestor
from src.feeds.urlhaus_ingestor import URLhausIngestor


class FeedOrchestrator:
    """Orchestrate ingestion of multiple threat intelligence feeds."""
    
    def __init__(self, db_session: Session):
        self.db_session = db_session
        self.ingestors = {
            'threatfox': ThreatFoxIngestor(db_session),
            'urlhaus': URLhausIngestor(db_session),
        }
    
    def ingest_all(self) -> Dict[str, Any]:
        """Ingest from all available feeds."""
        logger.info("Starting ingestion of all feeds...")
        
        results = {
            'start_time': datetime.utcnow().isoformat(),
            'feeds': {},
            'total_ingested': 0,
            'total_updated': 0,
            'total_errors': 0,
        }
        
        for feed_name, ingestor in self.ingestors.items():
            try:
                logger.info(f"Ingesting {feed_name}...")
                result = ingestor.ingest()
                results['feeds'][feed_name] = result
                
                results['total_ingested'] += result.get('records_ingested', 0)
                results['total_updated'] += result.get('records_updated', 0)
                results['total_errors'] += result.get('errors', 0)
            
            except Exception as e:
                logger.error(f"Failed to ingest {feed_name}: {str(e)}")
                results['feeds'][feed_name] = {
                    'status': 'error',
                    'error': str(e)
                }
                results['total_errors'] += 1
        
        results['end_time'] = datetime.utcnow().isoformat()
        
        logger.info(
            f"Ingestion complete. Total: {results['total_ingested']}, "
            f"Updated: {results['total_updated']}, Errors: {results['total_errors']}"
        )
        
        return results
    
    def ingest_specific(self, feed_name: str) -> Dict[str, Any]:
        """Ingest from a specific feed."""
        if feed_name not in self.ingestors:
            return {
                'status': 'error',
                'message': f'Unknown feed: {feed_name}',
                'available_feeds': list(self.ingestors.keys())
            }
        
        try:
            logger.info(f"Ingesting {feed_name}...")
            return self.ingestors[feed_name].ingest()
        
        except Exception as e:
            logger.error(f"Failed to ingest {feed_name}: {str(e)}")
            return {
                'status': 'error',
                'error': str(e),
                'feed': feed_name
            }
