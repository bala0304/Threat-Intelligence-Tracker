"""ThreatFox feed ingestor for C2 IOCs."""
import requests
from typing import List, Dict, Any
from datetime import datetime
from sqlalchemy.orm import Session
from loguru import logger
from src.feeds.base import BaseFeedIngestor
from src.feeds.http import abusech_headers, create_feed_session
from src.config import get_settings
from src.database.models import ThreatIndicator
from src.feeds.c2_sync import upsert_c2_from_indicator


class ThreatFoxIngestor(BaseFeedIngestor):
    """Ingestor for ThreatFox C2 feeds."""
    
    API_URL = "https://threatfox-api.abuse.ch/api/v1/"
    FEED_SOURCE = "threatfox"
    
    def __init__(self, db_session: Session):
        super().__init__(db_session)
        settings = get_settings()
        self.feed_source = self.FEED_SOURCE
        self.api_url = settings.threatfox_api_url.rstrip("/") + "/"
        self.auth_key = settings.resolved_abusech_auth_key
        self.http = create_feed_session()
    
    def fetch(self) -> List[Dict[str, Any]]:
        """Fetch latest IOCs from ThreatFox."""
        self.start_time = datetime.utcnow()
        
        try:
            if not self.auth_key:
                error = (
                    "abuse.ch Auth-Key is missing. Set THREATFOX_AUTH_KEY or "
                    "ABUSECH_AUTH_KEY in .env (get one free at https://auth.abuse.ch/)."
                )
                logger.error(error)
                self.errors.append(error)
                return []

            payload = {
                'query': 'get_iocs',
                'days': 1,
            }
            
            response = self.http.post(
                self.api_url,
                json=payload,
                headers=abusech_headers(self.auth_key),
                timeout=30
            )
            response.raise_for_status()
            
            data = response.json()
            if data.get('query_status') == 'ok':
                logger.info(f"Fetched {len(data.get('data', []))} indicators from ThreatFox")
                return data.get('data', [])
            else:
                error = data.get('error', 'Unknown error')
                logger.error(f"ThreatFox API error: {error}")
                self.errors.append(f"API error: {error}")
                return []
        
        except requests.HTTPError as e:
            detail = str(e)
            if e.response is not None and e.response.status_code == 401:
                detail = (
                    "ThreatFox API returned 401 Unauthorized. "
                    "Verify THREATFOX_AUTH_KEY in .env and make sure it is an Auth-Key "
                    "from https://auth.abuse.ch/."
                )
            logger.error(f"Failed to fetch ThreatFox data: {detail}")
            self.errors.append(f"Fetch error: {detail}")
            return []
        except Exception as e:
            logger.error(f"Failed to fetch ThreatFox data: {str(e)}")
            self.errors.append(f"Fetch error: {str(e)}")
            return []
    
    def parse(self, raw_data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Parse ThreatFox JSON data."""
        parsed = []
        
        for item in raw_data:
            try:
                indicator_obj = {
                    'indicator': item.get('ioc'),
                    'indicator_type': item.get('ioc_type'),  # ip, domain, url, etc.
                    'threat_type': 'c2',
                    'description': item.get('threat_type_desc', ''),
                    'confidence_score': float(item.get('confidence_level') or 100.0),
                    'severity': 'critical',
                    'tags': {
                        'malware': item.get('malware', ''),
                        'malware_printable': item.get('malware_printable', ''),
                        'first_seen': item.get('first_seen', ''),
                        'last_seen': item.get('last_seen', ''),
                    },
                    'associated_malware': [item.get('malware', '')],
                    'source': self.FEED_SOURCE,
                }
                
                # Add URL if available
                if item.get('reference'):
                    indicator_obj['tags']['reference'] = item['reference']
                
                parsed.append(indicator_obj)
            
            except Exception as e:
                logger.warning(f"Failed to parse ThreatFox item: {str(e)}")
                self.errors.append(f"Parse error: {str(e)}")
        
        return parsed
    
    def ingest(self) -> Dict[str, Any]:
        """Ingest parsed data into database."""
        try:
            raw_data = self.fetch()
            if not raw_data:
                self.log_ingestion("failed")
                message = self.errors[-1] if self.errors else 'No data fetched'
                return {
                    'status': 'failed',
                    'message': message,
                    'records_ingested': 0,
                    'records_updated': self.records_updated,
                    'errors': len(self.errors),
                    'error_details': self.errors,
                }
            
            parsed_data = self.parse(raw_data)
            seen_indicators = set()
            
            for item in parsed_data:
                indicator_value = item.get('indicator')
                if not indicator_value:
                    self.errors.append("Skipped ThreatFox item without an indicator value")
                    continue

                if indicator_value in seen_indicators:
                    self.records_updated += 1
                    continue
                seen_indicators.add(indicator_value)

                # ThreatIndicator.indicator is globally unique in the schema.
                existing = self.db_session.query(ThreatIndicator).filter_by(
                    indicator=indicator_value
                ).first()
                
                if existing:
                    existing.last_seen = datetime.utcnow()
                    existing.indicator_type = item['indicator_type']
                    existing.threat_type = item['threat_type']
                    existing.description = item['description']
                    existing.confidence_score = item['confidence_score']
                    existing.severity = item['severity']
                    existing.tags = item['tags']
                    existing.associated_malware = item['associated_malware']
                    sources = set(existing.sources or [])
                    sources.add(self.FEED_SOURCE)
                    existing.sources = sorted(sources)
                    upsert_c2_from_indicator(self.db_session, item, self.FEED_SOURCE)
                    self.records_updated += 1
                else:
                    # Create new indicator
                    new_indicator = ThreatIndicator(
                        indicator=indicator_value,
                        indicator_type=item['indicator_type'],
                        threat_type=item['threat_type'],
                        description=item['description'],
                        confidence_score=item['confidence_score'],
                        severity=item['severity'],
                        tags=item['tags'],
                        associated_malware=item['associated_malware'],
                        sources=[self.FEED_SOURCE],
                    )
                    self.db_session.add(new_indicator)
                    upsert_c2_from_indicator(self.db_session, item, self.FEED_SOURCE)
                    self.records_ingested += 1
            
            self.db_session.commit()
            self.end_time = datetime.utcnow()
            self.log_ingestion("success")
            
            return {
                'status': 'success',
                'records_ingested': self.records_ingested,
                'records_updated': self.records_updated,
                'errors': len(self.errors)
            }
        
        except Exception as e:
            logger.error(f"Ingestion failed: {str(e)}")
            self.errors.append(str(e))
            self.db_session.rollback()
            self.end_time = datetime.utcnow()
            self.log_ingestion("failed")
            
            return {
                'status': 'failed',
                'error': str(e),
                'records_ingested': self.records_ingested,
                'records_updated': self.records_updated,
                'errors': len(self.errors),
                'error_details': self.errors,
            }
