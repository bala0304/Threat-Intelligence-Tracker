"""Base client for API operations."""
import time
from typing import Any, Dict, Optional

import requests
from loguru import logger


class BaseAPIClient:
    """Base class for API clients with common functionality."""

    def __init__(self, api_key: Optional[str], timeout: int = 30):
        self.api_key = api_key
        self.timeout = timeout
        self.rate_limit_reset = 0
        self.rate_limit_remaining = float("inf")
        self.session = None

    def _check_rate_limit(self):
        """Check and wait for rate limits if necessary."""
        if self.rate_limit_reset > time.time():
            wait_time = self.rate_limit_reset - time.time() + 1
            logger.warning(f"Rate limit reached, waiting {wait_time:.1f} seconds")
            time.sleep(wait_time)

    def _update_rate_limit(self, headers: Dict[str, Any]):
        """Update rate limit information from response headers."""
        if "X-Rate-Limit-Reset" in headers:
            self.rate_limit_reset = int(headers["X-Rate-Limit-Reset"])
        if "X-Rate-Limit-Remaining" in headers:
            self.rate_limit_remaining = int(headers["X-Rate-Limit-Remaining"])

    def _handle_error(self, response: requests.Response, service_name: str):
        """Handle API errors consistently."""
        try:
            error_data = response.json()
            error_msg = error_data.get(
                "message",
                error_data.get("error", "Unknown error"),
            )
        except ValueError:
            error_msg = response.text

        logger.error(f"{service_name} error ({response.status_code}): {error_msg}")

        if response.status_code == 401:
            raise ValueError(f"{service_name}: Invalid credentials")
        if response.status_code == 403:
            raise PermissionError(f"{service_name}: Access forbidden")
        if response.status_code == 429:
            raise RuntimeError(f"{service_name}: Rate limited")
        if response.status_code >= 500:
            raise RuntimeError(f"{service_name}: Service unavailable")

        return None
