"""HTTP helpers for threat feed ingestors."""
from typing import Dict, Optional

import requests

from src.config import get_settings


def create_feed_session() -> requests.Session:
    """Create a requests session configured for feed API calls."""
    settings = get_settings()
    session = requests.Session()
    session.trust_env = settings.http_trust_env
    return session


def abusech_headers(auth_key: Optional[str] = None) -> Dict[str, str]:
    """Build Auth-Key headers for abuse.ch APIs."""
    key = (auth_key or get_settings().abusech_auth_key or "").strip()
    if not key or key == "your_threatfox_auth_key":
        return {}
    return {"Auth-Key": key}
