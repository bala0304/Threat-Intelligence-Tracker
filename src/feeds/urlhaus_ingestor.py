"""URLhaus feed ingestor for malware distribution URLs."""
import requests
from typing import List, Dict, Any, Optional
from datetime import datetime
from sqlalchemy.orm import Session
from loguru import logger
from src.feeds.base import BaseFeedIngestor
from src.feeds.http import abusech_headers, create_feed_session
from src.config import get_settings
from src.database.models import URLhaus, ThreatIndicator


class URLhausIngestor(BaseFeedIngestor):
    """Ingestor for URLhaus malware distribution feeds."""
    
    FEED_SOURCE = "urlhaus"
    
    def __init__(self, db_session: Session):
        super().__init__(db_session)
        settings = get_settings()
        self.feed_source = self.FEED_SOURCE
        self.api_url = settings.urlhaus_api_url.rstrip("/") + "/"
        self.auth_key = settings.resolved_abusech_auth_key
        self.http = create_feed_session()

    @staticmethod
    def _parse_datetime(value: Optional[str]) -> Optional[datetime]:
        if not value:
            return None
        normalized = value.strip()
        if normalized.endswith(" UTC"):
            normalized = normalized[:-4]
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
            try:
                return datetime.strptime(normalized, fmt)
            except ValueError:
                continue
        logger.warning(f"Could not parse URLhaus datetime value: {value}")
        return None
    
    def fetch(self) -> List[Dict[str, Any]]:
        """Fetch recent URLs from URLhaus."""
        self.start_time = datetime.utcnow()
        
        try:
            if not self.auth_key:
                error = (
                    "abuse.ch Auth-Key is missing. Set URLHAUS_AUTH_KEY, THREATFOX_AUTH_KEY, "
                    "or ABUSECH_AUTH_KEY in .env (get one free at https://auth.abuse.ch/)."
                )
                logger.error(error)
                self.errors.append(error)
                return []

            response = self.http.get(
                f"{self.api_url}urls/recent/",
                params={'limit': 100},
                headers=abusech_headers(self.auth_key),
                timeout=30
            )
            response.raise_for_status()
            
            data = response.json()
            if data.get('query_status') == 'ok':
                logger.info(f"Fetched {len(data.get('urls', []))} URLs from URLhaus")
                return data.get('urls', [])
            else:
                error = data.get('query_status', 'Unknown error')
                logger.error(f"URLhaus API error: {error}")
                self.errors.append(f"API error: {error}")
                return []

        except requests.HTTPError as e:
            detail = str(e)
            if e.response is not None and e.response.status_code == 401:
                detail = (
                    "URLhaus API returned 401 Unauthorized. Verify your abuse.ch Auth-Key "
                    "in .env and make sure it is from https://auth.abuse.ch/."
                )
            logger.error(f"Failed to fetch URLhaus data: {detail}")
            self.errors.append(f"Fetch error: {detail}")
            return []
        except Exception as e:
            logger.error(f"Failed to fetch URLhaus data: {str(e)}")
            self.errors.append(f"Fetch error: {str(e)}")
            return []
    
    def parse(self, raw_data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Parse URLhaus JSON data."""
        parsed = []
        
        for item in raw_data:
            try:
                url_entry = {
                    'url': item.get('url'),
                    'url_status': item.get('url_status'),
                    'host': item.get('host'),
                    'date_added': self._parse_datetime(item.get('date_added')),
                    'threat': item.get('threat'),
                    'tags': item.get('tags') or [],
                    'urlhaus_reference': item.get('urlhaus_reference'),
                    'payload_urls': item.get('payload') or [],
                }
                
                # Extract malware family from tags
                malware_family = None
                for tag in url_entry['tags']:
                    if tag not in ['malware', 'exploit', 'phishing']:
                        malware_family = tag
                        break
                
                url_entry['malware_family'] = malware_family
                parsed.append(url_entry)
            
            except Exception as e:
                logger.warning(f"Failed to parse URLhaus item: {str(e)}")
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
            
            for item in parsed_data:
                if not item.get('url'):
                    self.errors.append("Skipped URLhaus item without a URL value")
                    continue

                # Check if URL already exists
                existing = self.db_session.query(URLhaus).filter_by(
                    url=item['url']
                ).first()
                
                if existing:
                    # Update existing URL entry
                    existing.url_status = item['url_status']
                    existing.last_checked = datetime.utcnow()
                    self.records_updated += 1
                else:
                    # Create new URL entry
                    new_url = URLhaus(
                        url=item['url'],
                        url_status=item['url_status'],
                        host=item['host'],
                        date_added=item['date_added'],
                        threat_type=item.get('threat'),
                        malware_family=item['malware_family'],
                        payload_urls=item['payload_urls'],
                        tags=item['tags'],
                        urlhaus_reference=item['urlhaus_reference'],
                    )
                    self.db_session.add(new_url)
                    self.records_ingested += 1
                    
                    # Also create a ThreatIndicator for the URL
                    indicator = ThreatIndicator(
                        indicator=item['url'],
                        indicator_type='url',
                        threat_type='malware_distribution',
                        description=f"Malware distribution URL: {item['malware_family']}",
                        confidence_score=95.0,
                        severity='high',
                        tags={'malware_family': item['malware_family']},
                        associated_malware=[item['malware_family']] if item['malware_family'] else [],
                        sources=[self.FEED_SOURCE],
                    )
                    self.db_session.add(indicator)
            
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
