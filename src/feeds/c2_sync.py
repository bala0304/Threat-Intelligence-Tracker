"""Sync C2 infrastructure records from threat indicator data."""
from datetime import datetime
from typing import Any, Dict, Optional, Tuple

from loguru import logger
from sqlalchemy.orm import Session

from src.database.models import C2Infrastructure, DomainIntelligence, ThreatIndicator

IP_IOC_TYPES = {"ip", "ip:port", "ip_port"}


def parse_ip_port(ioc: str) -> Tuple[Optional[str], Optional[int]]:
    """Parse ThreatFox-style ip:port values into host and port."""
    if not ioc:
        return None, None

    if ioc.count(":") == 1 and not ioc.startswith("["):
        host, port_str = ioc.rsplit(":", 1)
        try:
            return host, int(port_str)
        except ValueError:
            return ioc, None

    return ioc, None


def upsert_c2_from_indicator(
    db_session: Session,
    item: Dict[str, Any],
    source: str = "threatfox",
) -> bool:
    """Create or update a C2Infrastructure row from a parsed indicator."""
    ioc_type = (item.get("indicator_type") or "").lower()
    ioc = item.get("indicator")
    if not ioc:
        return False

    ip_address: Optional[str] = None
    port: Optional[int] = None
    domain: Optional[str] = None

    if ioc_type in IP_IOC_TYPES:
        ip_address, port = parse_ip_port(ioc)
    elif ioc_type == "domain":
        domain = ioc
    else:
        return False

    tags = item.get("tags") or {}
    malware = tags.get("malware") or ""
    if not malware and item.get("associated_malware"):
        malware = item["associated_malware"][0]

    confidence = float(item.get("confidence_score") or 0.0)

    if ip_address:
        existing = db_session.query(C2Infrastructure).filter_by(
            ip_address=ip_address
        ).first()
        tag_payload = {"malware": malware} if malware else {}

        if existing:
            existing.port = port or existing.port
            existing.last_seen = datetime.utcnow()
            existing.confidence_score = max(existing.confidence_score or 0.0, confidence)
            existing.is_active = True
            existing.source = source
            merged_tags = dict(existing.tags or {})
            merged_tags.update(tag_payload)
            existing.tags = merged_tags
            if domain:
                existing.domain = domain
            db_session.flush()
            return True

        db_session.add(
            C2Infrastructure(
                ip_address=ip_address,
                port=port,
                domain=domain,
                confidence_score=confidence,
                is_active=True,
                source=source,
                tags=tag_payload,
            )
        )
        db_session.flush()
        return True

    if domain:
        existing_domain = db_session.query(DomainIntelligence).filter_by(
            domain=domain
        ).first()
        if existing_domain:
            existing_domain.is_malicious = True
            existing_domain.confidence_score = max(
                existing_domain.confidence_score or 0.0,
                confidence,
            )
            existing_domain.last_updated = datetime.utcnow()
            sources = set(existing_domain.sources or [])
            sources.add(source)
            existing_domain.sources = sorted(sources)
            return True

        db_session.add(
            DomainIntelligence(
                domain=domain,
                is_malicious=True,
                confidence_score=confidence,
                sources=[source],
            )
        )
        db_session.flush()
        return True

    return False


def sync_c2_from_existing_indicators(
    db_session: Session,
    source: str = "threatfox",
) -> Dict[str, int]:
    """Backfill C2/domain rows from indicators already stored in the database."""
    indicators = db_session.query(ThreatIndicator).filter(
        ThreatIndicator.threat_type == "c2",
        ThreatIndicator.indicator_type.in_(list(IP_IOC_TYPES) + ["domain"]),
    ).all()

    synced = 0
    for indicator in indicators:
        item = {
            "indicator": indicator.indicator,
            "indicator_type": indicator.indicator_type,
            "confidence_score": indicator.confidence_score,
            "tags": indicator.tags or {},
            "associated_malware": indicator.associated_malware or [],
        }
        if upsert_c2_from_indicator(db_session, item, source=source):
            synced += 1

    db_session.commit()
    logger.info(f"Synced {synced} C2/domain records from existing indicators")
    return {"synced": synced, "candidates": len(indicators)}
