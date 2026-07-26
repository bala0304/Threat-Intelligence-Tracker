"""Passive DNS client for historical DNS resolution data."""
import requests
import dns.resolver
import dns.query
import dns.zone
from typing import Optional, Dict, List, Any
from datetime import datetime
from loguru import logger
import socket


class PassiveDNSClient:
    """Client for passive DNS lookups."""
    
    # Public PDNS sources
    SOURCES = {
        'abuseip': 'https://api.abuseipdb.com/api/v2/',
        'circl': 'https://pdns.circl.lu/api/',
        'threatstream': 'https://api.threatstream.com/api/v2/',
    }
    
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key
        self.timeout = 30
    
    def resolve_domain(self, domain: str) -> List[str]:
        """Resolve domain to IP addresses."""
        try:
            answers = dns.resolver.resolve(domain, 'A')
            return [str(rdata) for rdata in answers]
        except Exception as e:
            logger.warning(f"DNS resolution failed for {domain}: {str(e)}")
            return []
    
    def reverse_lookup(self, ip: str) -> Optional[str]:
        """Reverse DNS lookup."""
        try:
            result = socket.gethostbyaddr(ip)
            return result[0]
        except Exception as e:
            logger.warning(f"Reverse DNS lookup failed for {ip}: {str(e)}")
            return None
    
    def get_mx_records(self, domain: str) -> List[Dict[str, Any]]:
        """Get MX records for a domain."""
        try:
            mx_records = dns.resolver.resolve(domain, 'MX')
            return [
                {
                    'priority': str(rdata.preference),
                    'exchange': str(rdata.exchange).rstrip('.')
                }
                for rdata in mx_records
            ]
        except Exception as e:
            logger.warning(f"MX lookup failed for {domain}: {str(e)}")
            return []
    
    def get_ns_records(self, domain: str) -> List[str]:
        """Get NS records for a domain."""
        try:
            ns_records = dns.resolver.resolve(domain, 'NS')
            return [str(rdata).rstrip('.') for rdata in ns_records]
        except Exception as e:
            logger.warning(f"NS lookup failed for {domain}: {str(e)}")
            return []
    
    def get_txt_records(self, domain: str) -> List[str]:
        """Get TXT records for a domain."""
        try:
            txt_records = dns.resolver.resolve(domain, 'TXT')
            return [str(rdata) for rdata in txt_records]
        except Exception as e:
            logger.warning(f"TXT lookup failed for {domain}: {str(e)}")
            return []
    
    def query_circl_pdns(self, query_param: str) -> List[Dict[str, Any]]:
        """Query CIRCL Passive DNS database."""
        if not self.api_key:
            logger.warning("API key not provided for CIRCL PDNS")
            return []
        
        try:
            headers = {'Authorization': f'Bearer {self.api_key}'}
            # query_param can be IP or domain
            response = requests.get(
                f"{self.SOURCES['circl']}/query/{query_param}",
                headers=headers,
                timeout=self.timeout
            )
            response.raise_for_status()
            return response.json().get('rrsets', [])
        except Exception as e:
            logger.warning(f"CIRCL PDNS query failed for {query_param}: {str(e)}")
            return []
    
    def get_dns_history(self, domain: str) -> Dict[str, Any]:
        """Get historical DNS data for a domain."""
        return {
            'domain': domain,
            'a_records': self.resolve_domain(domain),
            'mx_records': self.get_mx_records(domain),
            'ns_records': self.get_ns_records(domain),
            'txt_records': self.get_txt_records(domain),
            'lookup_date': datetime.utcnow().isoformat()
        }
