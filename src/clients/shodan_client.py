"""Shodan API client for scanning internet-connected devices."""
import requests
from typing import Optional, Dict, List, Any
from loguru import logger
from src.clients.base import BaseAPIClient


class ShodanClient(BaseAPIClient):
    """Client for Shodan API."""
    
    BASE_URL = "https://api.shodan.io"
    
    def __init__(self, api_key: str):
        super().__init__(api_key)
        if not api_key:
            raise ValueError("Shodan API key is required")
    
    def search(self, query: str, page: int = 1, limit: int = 100) -> Dict[str, Any]:
        """Search Shodan for devices matching query."""
        self._check_rate_limit()
        
        params = {
            'query': query,
            'page': page,
            'limit': min(limit, 100),  # Max 100 per request
            'key': self.api_key
        }
        
        try:
            from src.config import get_settings

            session = requests.Session()
            session.trust_env = get_settings().http_trust_env
            response = session.get(
                f"{self.BASE_URL}/shodan/host/search",
                params=params,
                timeout=self.timeout,
            )
            response.raise_for_status()
            self._update_rate_limit(response.headers)
            return response.json()
        except Exception as e:
            logger.error(f"Shodan search error: {str(e)}")
            raise
    
    def get_host(self, ip: str) -> Dict[str, Any]:
        """Get details about a specific IP."""
        self._check_rate_limit()

        try:
            from src.config import get_settings

            session = requests.Session()
            session.trust_env = get_settings().http_trust_env
            response = session.get(
                f"{self.BASE_URL}/shodan/host/{ip}",
                params={'key': self.api_key},
                timeout=self.timeout,
            )
            response.raise_for_status()
            self._update_rate_limit(response.headers)
            return response.json()
        except Exception as e:
            logger.error(f"Shodan host lookup error for {ip}: {str(e)}")
            raise
    
    def search_for_c2(self, malware_family: str = None) -> List[Dict[str, Any]]:
        """Search for C2 infrastructure."""
        queries = []
        
        if malware_family:
            queries = [
                f'{malware_family} C2',
                f'{malware_family} server',
                f'{malware_family} beacon',
            ]
        else:
            # Generic C2 queries
            queries = [
                'C2 callback',
                'command and control',
                'botnet panel',
                'malware server',
            ]
        
        results = []
        for query in queries:
            try:
                result = self.search(query)
                results.extend(result.get('matches', []))
            except Exception as e:
                logger.warning(f"Error searching Shodan for '{query}': {str(e)}")
        
        return results
    
    def get_dns_records(self, domain: str) -> Dict[str, Any]:
        """Get DNS records for a domain."""
        self._check_rate_limit()
        
        params = {
            'domain': domain,
            'key': self.api_key
        }
        
        try:
            response = requests.get(
                f"{self.BASE_URL}/dns/resolve",
                params=params,
                timeout=self.timeout
            )
            response.raise_for_status()
            self._update_rate_limit(response.headers)
            return response.json()
        except Exception as e:
            logger.error(f"Shodan DNS lookup error for {domain}: {str(e)}")
            raise
    
    def get_account_info(self) -> Dict[str, Any]:
        """Get account information and credit balance."""
        self._check_rate_limit()
        
        params = {'key': self.api_key}
        
        try:
            response = requests.get(
                f"{self.BASE_URL}/account/profile",
                params=params,
                timeout=self.timeout
            )
            response.raise_for_status()
            self._update_rate_limit(response.headers)
            return response.json()
        except Exception as e:
            logger.error(f"Shodan account info error: {str(e)}")
            raise
