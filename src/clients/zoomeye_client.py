"""Zoomeye API client for cyberspace search engine."""
import requests
from typing import Optional, Dict, List, Any
from loguru import logger
from src.clients.base import BaseAPIClient


class ZoomeyeClient(BaseAPIClient):
    """Client for Zoomeye API."""
    
    BASE_URL = "https://api.zoomeye.org"
    
    def __init__(self, api_key: str):
        super().__init__(api_key)
        if not api_key:
            raise ValueError("Zoomeye API key is required")
        self.access_token = None
        self._authenticate()
    
    def _authenticate(self):
        """Authenticate and get access token."""
        try:
            response = requests.post(
                f"{self.BASE_URL}/user/login",
                json={'apikey': self.api_key},
                timeout=self.timeout
            )
            response.raise_for_status()
            self.access_token = response.json().get('access_token')
            logger.info("Zoomeye authentication successful")
        except Exception as e:
            logger.error(f"Zoomeye authentication failed: {str(e)}")
            raise
    
    def _get_headers(self) -> Dict[str, str]:
        """Get headers with authorization."""
        return {
            'Authorization': self.access_token,
            'Content-Type': 'application/json'
        }
    
    def search_host(self, query: str, page: int = 1, limit: int = 20) -> Dict[str, Any]:
        """Search for hosts."""
        self._check_rate_limit()
        
        params = {
            'query': query,
            'page': page,
            'pagesize': min(limit, 20)
        }
        
        try:
            response = requests.get(
                f"{self.BASE_URL}/host/search",
                params=params,
                headers=self._get_headers(),
                timeout=self.timeout
            )
            response.raise_for_status()
            self._update_rate_limit(response.headers)
            return response.json()
        except Exception as e:
            logger.error(f"Zoomeye host search error: {str(e)}")
            raise
    
    def search_web(self, query: str, page: int = 1, limit: int = 20) -> Dict[str, Any]:
        """Search for web services."""
        self._check_rate_limit()
        
        params = {
            'query': query,
            'page': page,
            'pagesize': min(limit, 20)
        }
        
        try:
            response = requests.get(
                f"{self.BASE_URL}/web/search",
                params=params,
                headers=self._get_headers(),
                timeout=self.timeout
            )
            response.raise_for_status()
            self._update_rate_limit(response.headers)
            return response.json()
        except Exception as e:
            logger.error(f"Zoomeye web search error: {str(e)}")
            raise
    
    def get_host_info(self, ip: str) -> Dict[str, Any]:
        """Get detailed information about a host."""
        self._check_rate_limit()
        
        params = {'ip': ip}
        
        try:
            response = requests.get(
                f"{self.BASE_URL}/host/ip",
                params=params,
                headers=self._get_headers(),
                timeout=self.timeout
            )
            response.raise_for_status()
            self._update_rate_limit(response.headers)
            return response.json()
        except Exception as e:
            logger.error(f"Zoomeye IP lookup error for {ip}: {str(e)}")
            raise
    
    def search_for_c2(self) -> List[Dict[str, Any]]:
        """Search for C2 infrastructure."""
        queries = [
            'Cobalt Strike',
            'Empire C2',
            'Mythic',
            'Sliver C2',
        ]
        
        results = []
        for query in queries:
            try:
                result = self.search_host(query)
                results.extend(result.get('list', []))
            except Exception as e:
                logger.warning(f"Error searching Zoomeye for '{query}': {str(e)}")
        
        return results
