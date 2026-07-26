"""Utility functions for threat intelligence operations."""
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
import ipaddress
import re


def is_valid_ip(ip_string: str) -> bool:
    """Check if string is a valid IP address."""
    try:
        ipaddress.ip_address(ip_string)
        return True
    except ValueError:
        return False


def is_valid_domain(domain: str) -> bool:
    """Check if string is a valid domain."""
    pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    return re.match(pattern, domain) is not None


def is_valid_url(url: str) -> bool:
    """Check if string is a valid URL."""
    pattern = r'^https?://[^\s/$.?#].[^\s]*$'
    return re.match(pattern, url) is not None


def extract_domain_from_url(url: str) -> Optional[str]:
    """Extract domain from URL."""
    try:
        from urllib.parse import urlparse
        parsed = urlparse(url)
        return parsed.netloc
    except:
        return None


def calculate_age_in_days(timestamp: datetime) -> int:
    """Calculate days since timestamp."""
    return (datetime.utcnow() - timestamp).days


def classify_severity(confidence_score: float, threat_type: str) -> str:
    """Classify threat severity based on confidence and type."""
    critical_threats = ['ransomware', 'wiper', 'backdoor', 'c2']
    
    if confidence_score >= 95:
        return 'critical'
    elif confidence_score >= 80:
        return 'high' if threat_type in critical_threats else 'medium'
    elif confidence_score >= 60:
        return 'medium'
    else:
        return 'low'


def normalize_indicator(indicator: str) -> str:
    """Normalize threat indicator for consistent storage."""
    return indicator.lower().strip()


def batch_list(items: List[Any], batch_size: int) -> List[List[Any]]:
    """Split list into batches."""
    for i in range(0, len(items), batch_size):
        yield items[i:i + batch_size]


def merge_dicts(base_dict: Dict, update_dict: Dict) -> Dict:
    """Deep merge dictionaries."""
    result = base_dict.copy()
    for key, value in update_dict.items():
        if isinstance(value, dict) and key in result and isinstance(result[key], dict):
            result[key] = merge_dicts(result[key], value)
        else:
            result[key] = value
    return result


def get_ioc_type(ioc: str) -> str:
    """Detect IOC type automatically."""
    ioc_lower = ioc.lower()
    
    if is_valid_ip(ioc):
        return 'ip'
    elif is_valid_domain(ioc):
        return 'domain'
    elif is_valid_url(ioc):
        return 'url'
    elif re.match(r'^[a-fA-F0-9]{32}$', ioc):
        return 'md5'
    elif re.match(r'^[a-fA-F0-9]{40}$', ioc):
        return 'sha1'
    elif re.match(r'^[a-fA-F0-9]{64}$', ioc):
        return 'sha256'
    else:
        return 'unknown'
