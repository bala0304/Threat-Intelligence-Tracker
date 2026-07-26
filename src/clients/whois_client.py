"""WHOIS client for domain registration information."""
import whois
from typing import Dict, Any, Optional
from datetime import datetime
from loguru import logger
import re


class WHOISClient:
    """Client for WHOIS lookups and history tracking."""
    
    def __init__(self):
        self.timeout = 30
    
    def lookup(self, domain: str) -> Dict[str, Any]:
        """Perform WHOIS lookup for a domain."""
        try:
            whois_data = whois.whois(domain)
            return self._parse_whois_data(whois_data, domain)
        except Exception as e:
            logger.warning(f"WHOIS lookup failed for {domain}: {str(e)}")
            return {
                'domain': domain,
                'error': str(e),
                'lookup_date': datetime.utcnow().isoformat()
            }
    
    def _parse_whois_data(self, whois_data: Any, domain: str) -> Dict[str, Any]:
        """Parse WHOIS data into structured format."""
        def to_list(value):
            """Convert value to list if needed."""
            if isinstance(value, list):
                return value
            elif value is None:
                return []
            else:
                return [value] if value else []
        
        return {
            'domain': domain,
            'registrar': str(whois_data.registrar) if hasattr(whois_data, 'registrar') else None,
            'registrant_name': str(whois_data.registrant_name) if hasattr(whois_data, 'registrant_name') else None,
            'registrant_email': str(whois_data.registrant_email) if hasattr(whois_data, 'registrant_email') else None,
            'registrant_phone': str(whois_data.registrant_phone) if hasattr(whois_data, 'registrant_phone') else None,
            'registrant_organization': str(whois_data.registrant_organization) if hasattr(whois_data, 'registrant_organization') else None,
            'registrant_country': str(whois_data.registrant_country) if hasattr(whois_data, 'registrant_country') else None,
            'admin_email': str(whois_data.admin_email) if hasattr(whois_data, 'admin_email') else None,
            'admin_name': str(whois_data.admin_name) if hasattr(whois_data, 'admin_name') else None,
            'tech_email': str(whois_data.tech_email) if hasattr(whois_data, 'tech_email') else None,
            'tech_name': str(whois_data.tech_name) if hasattr(whois_data, 'tech_name') else None,
            'name_servers': to_list(whois_data.name_servers) if hasattr(whois_data, 'name_servers') else [],
            'creation_date': whois_data.creation_date.isoformat() if hasattr(whois_data, 'creation_date') and whois_data.creation_date else None,
            'expiration_date': whois_data.expiration_date.isoformat() if hasattr(whois_data, 'expiration_date') and whois_data.expiration_date else None,
            'updated_date': whois_data.updated_date.isoformat() if hasattr(whois_data, 'updated_date') and whois_data.updated_date else None,
            'status': to_list(whois_data.status) if hasattr(whois_data, 'status') else [],
            'dnssec': str(whois_data.dnssec) if hasattr(whois_data, 'dnssec') else None,
            'lookup_date': datetime.utcnow().isoformat(),
        }
    
    def track_changes(self, domain: str, previous: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """Track WHOIS changes for a domain."""
        current = self.lookup(domain)
        
        changes = {
            'domain': domain,
            'changed_at': datetime.utcnow().isoformat(),
            'previous': previous,
            'current': current,
            'differences': []
        }
        
        if not previous:
            return changes
        
        # Compare key fields
        fields_to_compare = [
            'registrar',
            'registrant_email',
            'registrant_organization',
            'admin_email',
            'tech_email',
            'name_servers',
            'expiration_date'
        ]
        
        for field in fields_to_compare:
            if previous.get(field) != current.get(field):
                changes['differences'].append({
                    'field': field,
                    'old_value': previous.get(field),
                    'new_value': current.get(field)
                })
        
        return changes
    
    def is_suspicious(self, whois_data: Dict[str, Any]) -> bool:
        """Check if WHOIS data shows signs of suspicion."""
        suspicious_indicators = [
            'privacy',
            'redacted',
            'withheld',
            'protected',
        ]
        
        # Check for common privacy protection services
        registrar = str(whois_data.get('registrar', '')).lower()
        registrant_org = str(whois_data.get('registrant_organization', '')).lower()
        
        for indicator in suspicious_indicators:
            if indicator in registrar or indicator in registrant_org:
                return True
        
        # Check for generic/suspicious registrant info
        registrant_name = str(whois_data.get('registrant_name', '')).lower()
        if any(word in registrant_name for word in ['test', 'admin', 'abuse', 'noreply']):
            return True
        
        return False
