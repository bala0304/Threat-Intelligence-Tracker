"""Censys API client for scanning internet-connected services."""
import requests
from typing import Optional, Dict, List, Any
from loguru import logger
import base64
from src.clients.base import BaseAPIClient


class CensysClient(BaseAPIClient):
    """Client for Censys API."""
    
    BASE_URL = "https://api.censys.io/api/v2"
    
    def __init__(
        self,
        api_token: Optional[str] = None,
        uid: Optional[str] = None,
        secret: Optional[str] = None,
    ):
        super().__init__(api_token or secret)
        self.api_token = api_token
        self.uid = uid
        self.secret = secret

        if self.api_token:
            return

        if not self.uid or not self.secret:
            raise ValueError(
                "Censys API token or UID and SECRET are required"
            )
    
    def _get_auth_header(self) -> Dict[str, str]:
        """Generate authorization header for Censys."""
        if self.api_token:
            return {'Authorization': f'Bearer {self.api_token}'}

        credentials = base64.b64encode(f"{self.uid}:{self.secret}".encode()).decode()
        return {'Authorization': f'Basic {credentials}'}
    
    def search_ipv4(self, query: str, page: int = 1, limit: int = 100) -> Dict[str, Any]:
        """Search IPv4 data."""
        self._check_rate_limit()
        
        headers = self._get_auth_header()
        headers['Content-Type'] = 'application/json'
        
        params = {
            'q': query,
            'per_page': min(limit, 100),
            'page': page
        }
        
        try:
            response = requests.get(
                f"{self.BASE_URL}/ipv4/search",
                params=params,
                headers=headers,
                timeout=self.timeout
            )
            response.raise_for_status()
            self._update_rate_limit(response.headers)
            return response.json()
        except Exception as e:
            logger.error(f"Censys IPv4 search error: {str(e)}")
            raise
    
    def get_ipv4(self, ip: str, include_raw: bool = False) -> Dict[str, Any]:
        """Get detailed information about an IPv4 address."""
        self._check_rate_limit()
        
        headers = self._get_auth_header()
        
        params = {}
        if include_raw:
            params['include_raw'] = 'true'
        
        try:
            response = requests.get(
                f"{self.BASE_URL}/ipv4/{ip}",
                params=params,
                headers=headers,
                timeout=self.timeout
            )
            response.raise_for_status()
            self._update_rate_limit(response.headers)
            return response.json()
        except Exception as e:
            logger.error(f"Censys IPv4 lookup error for {ip}: {str(e)}")
            raise
    
    def search_certificates(self, query: str, page: int = 1) -> Dict[str, Any]:
        """Search SSL/TLS certificates."""
        self._check_rate_limit()
        
        headers = self._get_auth_header()
        headers['Content-Type'] = 'application/json'
        
        params = {
            'q': query,
            'page': page,
        }
        
        try:
            response = requests.get(
                f"{self.BASE_URL}/certificates/search",
                params=params,
                headers=headers,
                timeout=self.timeout
            )
            response.raise_for_status()
            self._update_rate_limit(response.headers)
            return response.json()
        except Exception as e:
            logger.error(f"Censys certificate search error: {str(e)}")
            raise
    
    def get_certificate(self, fingerprint: str) -> Dict[str, Any]:
        """Get certificate details by fingerprint."""
        self._check_rate_limit()
        
        headers = self._get_auth_header()
        
        try:
            response = requests.get(
                f"{self.BASE_URL}/certificates/{fingerprint}",
                headers=headers,
                timeout=self.timeout
            )
            response.raise_for_status()
            self._update_rate_limit(response.headers)
            return response.json()
        except Exception as e:
            logger.error(f"Censys certificate lookup error: {str(e)}")
            raise
    
    def search_for_c2(self, malware_family: str = None) -> List[Dict[str, Any]]:
        """Search for C2 infrastructure."""
        queries = []
        
        if malware_family:
            queries = [
                f'services.http.response.html_title: {malware_family}',
                f'services.ssh.banner: {malware_family}',
            ]
        else:
            queries = [
                'services.http.response.html_title: "Command and Control"',
                'services.http.response.html_title: C2',
            ]
        
        results = []
        for query in queries:
            try:
                result = self.search_ipv4(query)
                results.extend(result.get('result', []))
            except Exception as e:
                logger.warning(f"Error searching Censys for '{query}': {str(e)}")
        
        return results
