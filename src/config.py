"""Configuration management for Threat Intel Tracker."""
from typing import Optional
from pydantic_settings import BaseSettings
from functools import lru_cache


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    # Database
    database_url: str = (
        "postgresql://threat_intel_user:threat_intel_password@localhost:5432/threat_intel_db"
    )

    # API Keys
    shodan_api_key: Optional[str] = None
    censys_api_token: Optional[str] = None
    censys_pat: Optional[str] = None
    censys_uid: Optional[str] = None
    censys_secret: Optional[str] = None
    binary_edge_api_key: Optional[str] = None
    zoomeye_api_key: Optional[str] = None
    passive_dns_api_key: Optional[str] = None
    abusech_auth_key: Optional[str] = None
    threatfox_auth_key: Optional[str] = None
    urlhaus_auth_key: Optional[str] = None

    # Threat Intelligence Feeds
    threatfox_api_url: str = "https://threatfox-api.abuse.ch/api/v1/"
    urlhaus_api_url: str = "https://urlhaus-api.abuse.ch/v1/"

    # Application Settings
    log_level: str = "INFO"
    api_host: str = "0.0.0.0"
    api_port: int = 8000
    dashboard_port: int = 8501
    http_trust_env: bool = False

    # Real-time Processing
    enable_realtime: bool = False
    update_interval_minutes: int = 60

    model_config = {
        "env_file": ".env",
        "case_sensitive": False,
        "extra": "ignore",
    }

    @property
    def resolved_abusech_auth_key(self) -> str:
        """Return the abuse.ch Auth-Key used by ThreatFox and URLhaus."""
        for candidate in (
            self.abusech_auth_key,
            self.threatfox_auth_key,
            self.urlhaus_auth_key,
        ):
            value = (candidate or "").strip()
            if value and value != "your_threatfox_auth_key":
                return value
        return ""

    @property
    def resolved_censys_token(self) -> str:
        """Return a usable Censys PAT if configured."""
        for candidate in (self.censys_pat, self.censys_api_token):
            value = (candidate or "").strip()
            if value and value != "your_censys_personal_access_token_here":
                return value
        return ""


@lru_cache()
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings()
