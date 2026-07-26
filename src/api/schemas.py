"""Pydantic models for API request/response validation."""
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
from datetime import datetime


# C2 Infrastructure Models
class C2InfrastructureBase(BaseModel):
    ip_address: str
    port: Optional[int] = None
    protocol: Optional[str] = None
    domain: Optional[str] = None
    country: Optional[str] = None
    tags: Optional[Dict[str, Any]] = None
    source: Optional[str] = None


class C2InfrastructureResponse(C2InfrastructureBase):
    id: int
    asn: Optional[str]
    isp: Optional[str]
    first_seen: datetime
    last_seen: datetime
    confidence_score: float
    is_active: bool
    
    class Config:
        from_attributes = True


# Threat Indicator Models
class ThreatIndicatorBase(BaseModel):
    indicator: str
    indicator_type: str  # ip, domain, url, file_hash
    threat_type: str
    description: Optional[str] = None
    severity: Optional[str] = None


class ThreatIndicatorResponse(ThreatIndicatorBase):
    id: int
    first_seen: datetime
    last_seen: datetime
    confidence_score: float
    sources: List[str]
    tags: Dict[str, Any]
    
    class Config:
        from_attributes = True


# Domain Intelligence Models
class DomainIntelligenceBase(BaseModel):
    domain: str
    registrar: Optional[str] = None
    is_malicious: Optional[bool] = False
    confidence_score: Optional[float] = 0.0


class DomainIntelligenceResponse(DomainIntelligenceBase):
    id: int
    creation_date: Optional[datetime]
    expiration_date: Optional[datetime]
    last_updated: datetime
    
    class Config:
        from_attributes = True


# Passive DNS Models
class PassiveDNSRecordBase(BaseModel):
    domain: str
    ip_address: str
    record_type: str


class PassiveDNSRecordResponse(PassiveDNSRecordBase):
    id: int
    first_seen: datetime
    last_seen: datetime
    source: str
    
    class Config:
        from_attributes = True


# WHOIS Models
class WHOISHistoryResponse(BaseModel):
    domain: str
    registrar: Optional[str]
    registrant_name: Optional[str]
    registrant_email: Optional[str]
    registrant_organization: Optional[str]
    name_servers: Optional[List[str]]
    creation_date: Optional[str]
    expiration_date: Optional[str]
    snapshot_date: datetime
    
    class Config:
        from_attributes = True


# URLhaus Models
class URLhausResponse(BaseModel):
    id: int
    url: str
    url_status: str
    host: str
    malware_family: Optional[str]
    threat_type: Optional[str]
    first_seen: datetime
    last_checked: datetime
    
    class Config:
        from_attributes = True


# Search Models
class SearchRequest(BaseModel):
    query: str
    limit: int = 50


class C2SearchRequest(BaseModel):
    country: Optional[str] = None
    is_active: Optional[bool] = True
    min_confidence: Optional[float] = 0.0
    limit: int = 50


class IndicatorSearchRequest(BaseModel):
    indicator_type: Optional[str] = None
    threat_type: Optional[str] = None
    severity: Optional[str] = None
    limit: int = 50


# Feed Ingestion Models
class IngestionStatus(BaseModel):
    feed: str
    status: str
    records_ingested: Optional[int]
    records_updated: Optional[int]
    errors: Optional[int]


# Response Models
class SearchResponse(BaseModel):
    query: str
    results: List[Dict[str, Any]]
    total_found: int


class ErrorResponse(BaseModel):
    error: str
    detail: Optional[str] = None
    status_code: int
