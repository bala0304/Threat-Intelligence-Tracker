"""API routes for threat intelligence operations."""
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from sqlalchemy import and_, or_, desc
from datetime import datetime, timedelta
from typing import List
from loguru import logger

from src.database.db import get_db
from src.database.models import (
    C2Infrastructure, DomainIntelligence, PassiveDNSRecord, 
    ThreatIndicator, WHOISHistory, URLhaus, MalwareAssociation
)
from src.api.schemas import (
    C2InfrastructureResponse, ThreatIndicatorResponse, 
    DomainIntelligenceResponse, PassiveDNSRecordResponse,
    WHOISHistoryResponse, URLhausResponse, C2SearchRequest,
    IndicatorSearchRequest
)

router = APIRouter(prefix="/api/v1", tags=["threat-intelligence"])


# C2 Infrastructure Endpoints
@router.get("/c2/all", response_model=List[C2InfrastructureResponse])
def get_all_c2_infrastructure(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=500),
    db: Session = Depends(get_db)
):
    """Get all tracked C2 infrastructure."""
    query = db.query(C2Infrastructure).order_by(desc(C2Infrastructure.last_seen))
    total = query.count()
    
    results = query.offset(skip).limit(limit).all()
    return results


@router.post("/c2/search", response_model=List[C2InfrastructureResponse])
def search_c2_infrastructure(
    request: C2SearchRequest,
    db: Session = Depends(get_db)
):
    """Search C2 infrastructure with filters."""
    query = db.query(C2Infrastructure)
    
    if request.country:
        query = query.filter(C2Infrastructure.country == request.country)
    
    if request.is_active is not None:
        query = query.filter(C2Infrastructure.is_active == request.is_active)
    
    if request.min_confidence > 0:
        query = query.filter(C2Infrastructure.confidence_score >= request.min_confidence)
    
    results = query.order_by(desc(C2Infrastructure.confidence_score)).limit(request.limit).all()
    return results


@router.get("/c2/ip/{ip}", response_model=C2InfrastructureResponse)
def get_c2_by_ip(ip: str, db: Session = Depends(get_db)):
    """Get C2 infrastructure details by IP."""
    result = db.query(C2Infrastructure).filter_by(ip_address=ip).first()
    if not result:
        raise HTTPException(status_code=404, detail="IP not found")
    return result


@router.get("/c2/ip/{ip}/domains")
def get_c2_associated_domains(ip: str, db: Session = Depends(get_db)):
    """Get domains associated with C2 IP."""
    c2 = db.query(C2Infrastructure).filter_by(ip_address=ip).first()
    if not c2:
        raise HTTPException(status_code=404, detail="IP not found")
    
    domains = db.query(DomainIntelligence).filter_by(c2_ip_id=c2.id).all()
    return {
        'ip': ip,
        'domains': [d.domain for d in domains],
        'total': len(domains)
    }


@router.get("/c2/ip/{ip}/dns-history")
def get_c2_dns_history(ip: str, db: Session = Depends(get_db)):
    """Get passive DNS history for C2 IP."""
    c2 = db.query(C2Infrastructure).filter_by(ip_address=ip).first()
    if not c2:
        raise HTTPException(status_code=404, detail="IP not found")
    
    dns_records = db.query(PassiveDNSRecord).filter_by(infrastructure_id=c2.id).all()
    return {
        'ip': ip,
        'dns_records': [
            {
                'domain': record.domain,
                'record_type': record.record_type,
                'first_seen': record.first_seen,
                'last_seen': record.last_seen
            }
            for record in dns_records
        ],
        'total': len(dns_records)
    }


# Threat Indicators Endpoints
@router.get("/indicators", response_model=List[ThreatIndicatorResponse])
def get_indicators(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=500),
    db: Session = Depends(get_db)
):
    """Get all threat indicators."""
    results = db.query(ThreatIndicator).order_by(
        desc(ThreatIndicator.confidence_score)
    ).offset(skip).limit(limit).all()
    return results


@router.post("/indicators/search", response_model=List[ThreatIndicatorResponse])
def search_indicators(
    request: IndicatorSearchRequest,
    db: Session = Depends(get_db)
):
    """Search threat indicators."""
    query = db.query(ThreatIndicator)
    
    if request.indicator_type:
        query = query.filter(ThreatIndicator.indicator_type == request.indicator_type)
    
    if request.threat_type:
        query = query.filter(ThreatIndicator.threat_type == request.threat_type)
    
    if request.severity:
        query = query.filter(ThreatIndicator.severity == request.severity)
    
    results = query.order_by(
        desc(ThreatIndicator.confidence_score)
    ).limit(request.limit).all()
    
    return results


@router.get("/indicators/{indicator}", response_model=ThreatIndicatorResponse)
def get_indicator(indicator: str, db: Session = Depends(get_db)):
    """Get details about a specific indicator."""
    result = db.query(ThreatIndicator).filter_by(indicator=indicator).first()
    if not result:
        raise HTTPException(status_code=404, detail="Indicator not found")
    return result


# Domain Intelligence Endpoints
@router.get("/domains", response_model=List[DomainIntelligenceResponse])
def get_malicious_domains(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=500),
    db: Session = Depends(get_db)
):
    """Get malicious domains."""
    results = db.query(DomainIntelligence).filter_by(
        is_malicious=True
    ).order_by(
        desc(DomainIntelligence.confidence_score)
    ).offset(skip).limit(limit).all()
    return results


@router.get("/domains/{domain}", response_model=DomainIntelligenceResponse)
def get_domain(domain: str, db: Session = Depends(get_db)):
    """Get domain intelligence."""
    result = db.query(DomainIntelligence).filter_by(domain=domain).first()
    if not result:
        raise HTTPException(status_code=404, detail="Domain not found")
    return result


# Passive DNS Endpoints
@router.get("/pdns/{query}", response_model=List[PassiveDNSRecordResponse])
def get_passive_dns(
    query: str,
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    db: Session = Depends(get_db)
):
    """Query passive DNS records by domain or IP."""
    results = db.query(PassiveDNSRecord).filter(
        or_(
            PassiveDNSRecord.domain == query,
            PassiveDNSRecord.ip_address == query
        )
    ).order_by(
        desc(PassiveDNSRecord.last_seen)
    ).offset(skip).limit(limit).all()
    
    return results


# URLhaus Endpoints
@router.get("/urlhaus", response_model=List[URLhausResponse])
def get_malware_urls(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=500),
    db: Session = Depends(get_db)
):
    """Get malware distribution URLs."""
    results = db.query(URLhaus).order_by(
        desc(URLhaus.first_seen)
    ).offset(skip).limit(limit).all()
    return results


@router.get("/urlhaus/host/{host}", response_model=List[URLhausResponse])
def get_urls_by_host(
    host: str,
    db: Session = Depends(get_db)
):
    """Get all malware URLs hosted on a specific host."""
    results = db.query(URLhaus).filter_by(host=host).all()
    return results


# Statistics and Analytics
@router.get("/stats/overview")
def get_statistics(db: Session = Depends(get_db)):
    """Get threat intelligence overview statistics."""
    return {
        'c2_total': db.query(C2Infrastructure).count(),
        'c2_active': db.query(C2Infrastructure).filter_by(is_active=True).count(),
        'indicators_total': db.query(ThreatIndicator).count(),
        'malicious_domains': db.query(DomainIntelligence).filter_by(is_malicious=True).count(),
        'malware_urls': db.query(URLhaus).count(),
        'pdns_records': db.query(PassiveDNSRecord).count(),
        'last_updated': datetime.utcnow().isoformat()
    }


@router.get("/stats/c2-by-country")
def get_c2_by_country(db: Session = Depends(get_db)):
    """Get C2 infrastructure distribution by country."""
    from sqlalchemy import func
    
    results = db.query(
        C2Infrastructure.country,
        func.count(C2Infrastructure.id).label('count')
    ).group_by(C2Infrastructure.country).all()
    
    return {
        'countries': [
            {'country': r[0] or 'Unknown', 'count': r[1]} for r in results
        ]
    }


@router.get("/stats/threats-by-severity")
def get_threats_by_severity(db: Session = Depends(get_db)):
    """Get threat distribution by severity."""
    from sqlalchemy import func
    
    results = db.query(
        ThreatIndicator.severity,
        func.count(ThreatIndicator.id).label('count')
    ).group_by(ThreatIndicator.severity).all()
    
    return {
        'severities': [
            {'severity': r[0] or 'unknown', 'count': r[1]} for r in results
        ]
    }


# Health Check
@router.get("/health")
def health_check():
    """API health check."""
    return {
        'status': 'healthy',
        'timestamp': datetime.utcnow().isoformat()
    }
