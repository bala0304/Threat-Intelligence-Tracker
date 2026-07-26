"""Binary Edge API client for internet reconnaissance."""
import requests
from typing import Optional, Dict, List, Any
from loguru import logger
from src.clients.base import BaseAPIClient


class BinaryEdgeClient(BaseAPIClient):
    """Client for Binary Edge API."""
    
    BASE_URL = "https://api.binaryedge.io/v2"
    
    def __init__(self, api_key: str):
        super().__init__(api_key)
        if not api_key:
            raise ValueError("Binary Edge API key is required")
    
    def search_query(self, query: str, page: int = 1) -> Dict[str, Any]:
        """Search using Binary Edge query language."""
        self._check_rate_limit()
        
        headers = {
            'X-Key': self.api_key,
            'Content-Type': 'application/json'
        }
        
        payload = {
            'query': query,
            'page': page
        }
        
        try:
            response = requests.post(
                f"{self.BASE_URL}/query/search",
                json=payload,
                headers=headers,
                timeout=self.timeout
            )
            response.raise_for_status()
            self._update_rate_limit(response.headers)
            return response.json()
        except Exception as e:
            logger.error(f"Binary Edge search error: {str(e)}")
            raise
    
    def get_ip(self, ip: str) -> Dict[str, Any]:
        """Get IP information and associated data."""
        self._check_rate_limit()
        
        headers = {'X-Key': self.api_key}
        
        try:
            response = requests.get(
                f"{self.BASE_URL}/query/ip/{ip}",
                headers=headers,
                timeout=self.timeout
            )
            response.raise_for_status()
            self._update_rate_limit(response.headers)
            return response.json()
        except Exception as e:
            logger.error(f"Binary Edge IP lookup error for {ip}: {str(e)}")
            raise
    
    def get_domain(self, domain: str) -> Dict[str, Any]:
        """Get domain information."""
        self._check_rate_limit()
        
        headers = {'X-Key': self.api_key}
        
        try:
            response = requests.get(
                f"{self.BASE_URL}/query/domain/{domain}",
                headers=headers,
                timeout=self.timeout
            )
            response.raise_for_status()
            self._update_rate_limit(response.headers)
            return response.json()
        except Exception as e:
            logger.error(f"Binary Edge domain lookup error for {domain}: {str(e)}")
            raise
    
    def search_for_c2(self) -> List[Dict[str, Any]]:
        """Search for C2 infrastructure patterns."""
        queries = [
            'port:4444 product:"Cobalt Strike"',
            'port:50050 product:"Empire"',
            'http.title:"command and control"',
        ]
        
        results = []
        for query in queries:
            try:
                result = self.search_query(query)
                results.extend(result.get('events', []))
            except Exception as e:
                logger.warning(f"Error searching Binary Edge for '{query}': {str(e)}")
        
        return results
