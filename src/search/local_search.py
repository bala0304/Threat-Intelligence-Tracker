"""Apply Shodan-style queries against local intelligence data."""
import json
from typing import Any, Dict, List, Optional

from sqlalchemy import or_, cast, String
from sqlalchemy.orm import Session

from src.database.models import (
    C2Infrastructure,
    DomainIntelligence,
    ScanResult,
    ThreatIndicator,
    URLhaus,
)
from src.search.shodan_query import ParsedQuery, parse_shodan_query


def _text_matches(value: Optional[str], needle: str) -> bool:
    if not value or not needle:
        return False
    return needle.lower() in value.lower()


def _scan_matches_free_text(scan: ScanResult, needle: str) -> bool:
    if not needle:
        return False
    haystacks = [
        json.dumps(scan.banners or {}),
        json.dumps(scan.services or {}),
        json.dumps(scan.http_headers or {}),
        json.dumps(scan.raw_data or {}),
        json.dumps(scan.ports or []),
    ]
    needle_lower = needle.lower()
    return any(needle_lower in h.lower() for h in haystacks)


def _apply_c2_filters(query, parsed: ParsedQuery):
    filters = parsed.filters

    if "ip" in filters:
        query = query.filter(C2Infrastructure.ip_address == filters["ip"])
    if "net" in filters:
        prefix = filters["net"].split("/")[0]
        query = query.filter(C2Infrastructure.ip_address.like(f"{prefix}%"))
    if "country" in filters:
        query = query.filter(
            C2Infrastructure.country.ilike(filters["country"])
        )
    if "port" in filters:
        try:
            query = query.filter(C2Infrastructure.port == int(filters["port"]))
        except ValueError:
            pass
    if "org" in filters or "isp" in filters:
        org = filters.get("org") or filters.get("isp")
        query = query.filter(C2Infrastructure.isp.ilike(f"%{org}%"))
    if "asn" in filters:
        asn = filters["asn"].upper().replace("AS", "")
        query = query.filter(C2Infrastructure.asn.ilike(f"%{asn}%"))
    if "hostname" in filters or "domain" in filters:
        host = filters.get("hostname") or filters.get("domain")
        query = query.filter(
            or_(
                C2Infrastructure.domain.ilike(f"%{host}%"),
                C2Infrastructure.ip_address.ilike(f"%{host}%"),
            )
        )
    if "source" in filters:
        query = query.filter(C2Infrastructure.source.ilike(f"%{filters['source']}%"))
    if "tag" in filters or "malware" in filters:
        tag = filters.get("tag") or filters.get("malware")
        query = query.filter(cast(C2Infrastructure.tags, String).ilike(f"%{tag}%"))

    if parsed.free_text:
        needle = parsed.free_text
        query = query.filter(
            or_(
                C2Infrastructure.ip_address.ilike(f"%{needle}%"),
                C2Infrastructure.domain.ilike(f"%{needle}%"),
                C2Infrastructure.isp.ilike(f"%{needle}%"),
                cast(C2Infrastructure.tags, String).ilike(f"%{needle}%"),
            )
        )
    return query


def search_local_intelligence(
    db: Session,
    query: str,
    limit: int = 100,
) -> List[Dict[str, Any]]:
    """Search local DB using Shodan-style query syntax."""
    parsed = parse_shodan_query(query)
    if not parsed.raw:
        return []

    results: List[Dict[str, Any]] = []
    seen_keys = set()

    def add_result(row: Dict[str, Any]):
        key = (row["Entity"], row["Value"])
        if key in seen_keys:
            return
        seen_keys.add(key)
        results.append(row)

    # C2 infrastructure
    c2_query = _apply_c2_filters(db.query(C2Infrastructure), parsed)
    for row in c2_query.order_by(C2Infrastructure.last_seen.desc()).limit(limit).all():
        add_result(
            {
                "Entity": "C2 Infrastructure",
                "Value": row.ip_address,
                "IP": row.ip_address,
                "Type": f"port:{row.port}" if row.port else "ip",
                "Country": row.country or "-",
                "Port": row.port,
                "Severity": "critical" if row.is_active else "inactive",
                "Confidence": row.confidence_score,
                "Source": row.source or "unknown",
                "Last Seen": row.last_seen,
                "Details": row.isp or row.domain or "-",
                "Enrichable": True,
            }
        )

    # Scan results (banner / product / http filters)
    scan_query = db.query(ScanResult)
    if "ip" in parsed.filters:
        scan_query = scan_query.filter(
            ScanResult.ip_address == parsed.filters["ip"]
        )
    if "port" in parsed.filters:
        scan_query = scan_query.filter(
            cast(ScanResult.ports, String).ilike(f"%{parsed.filters['port']}%")
        )
    if "product" in parsed.filters:
        scan_query = scan_query.filter(
            cast(ScanResult.services, String).ilike(
                f"%{parsed.filters['product']}%"
            )
        )
    for http_key in ("http.title", "http.html", "http.server", "http.status"):
        if http_key in parsed.filters:
            scan_query = scan_query.filter(
                cast(ScanResult.services, String).ilike(
                    f"%{parsed.filters[http_key]}%"
                )
            )

    scans = scan_query.order_by(ScanResult.scan_date.desc()).limit(limit * 2).all()
    for row in scans:
        if parsed.free_text and not _scan_matches_free_text(row, parsed.free_text):
            if not parsed.has_filters:
                continue
        add_result(
            {
                "Entity": "Scan Result",
                "Value": row.ip_address,
                "IP": row.ip_address,
                "Type": row.scan_source or "scan",
                "Country": "-",
                "Port": None,
                "Severity": "info",
                "Confidence": 100.0,
                "Source": row.scan_source or "scan",
                "Last Seen": row.scan_date,
                "Details": f"ports: {row.ports}",
                "Enrichable": True,
            }
        )

    # Threat indicators
    indicator_query = db.query(ThreatIndicator)
    if "ip" in parsed.filters:
        indicator_query = indicator_query.filter(
            ThreatIndicator.indicator.ilike(f"%{parsed.filters['ip']}%")
        )
    if "type" in parsed.filters:
        indicator_query = indicator_query.filter(
            ThreatIndicator.indicator_type == parsed.filters["type"]
        )
    if "severity" in parsed.filters:
        indicator_query = indicator_query.filter(
            ThreatIndicator.severity == parsed.filters["severity"]
        )
    if "malware" in parsed.filters:
        indicator_query = indicator_query.filter(
            cast(ThreatIndicator.associated_malware, String).ilike(
                f"%{parsed.filters['malware']}%"
            )
        )
    if parsed.free_text and not parsed.has_filters:
        indicator_query = indicator_query.filter(
            or_(
                ThreatIndicator.indicator.ilike(f"%{parsed.free_text}%"),
                ThreatIndicator.description.ilike(f"%{parsed.free_text}%"),
                cast(ThreatIndicator.tags, String).ilike(f"%{parsed.free_text}%"),
            )
        )
    elif parsed.free_text:
        indicator_query = indicator_query.filter(
            or_(
                ThreatIndicator.indicator.ilike(f"%{parsed.free_text}%"),
                ThreatIndicator.description.ilike(f"%{parsed.free_text}%"),
            )
        )

    for row in indicator_query.order_by(
        ThreatIndicator.last_seen.desc()
    ).limit(limit).all():
        enrichable = (row.indicator_type or "").startswith("ip")
        add_result(
            {
                "Entity": "Threat Indicator",
                "Value": row.indicator,
                "IP": row.indicator.split(":")[0] if enrichable else None,
                "Type": row.indicator_type,
                "Country": "-",
                "Port": None,
                "Severity": row.severity or "unknown",
                "Confidence": row.confidence_score,
                "Source": ", ".join(row.sources or []),
                "Last Seen": row.last_seen,
                "Details": row.threat_type,
                "Enrichable": enrichable,
            }
        )

    # Malware URLs
    if "hostname" in parsed.filters or "domain" in parsed.filters:
        host = parsed.filters.get("hostname") or parsed.filters.get("domain")
        url_rows = (
            db.query(URLhaus)
            .filter(
                or_(
                    URLhaus.host.ilike(f"%{host}%"),
                    URLhaus.url.ilike(f"%{host}%"),
                )
            )
            .order_by(URLhaus.first_seen.desc())
            .limit(limit)
            .all()
        )
        for row in url_rows:
            add_result(
                {
                    "Entity": "Malware URL",
                    "Value": row.url,
                    "IP": None,
                    "Type": row.url_status,
                    "Country": "-",
                    "Port": None,
                    "Severity": "high",
                    "Confidence": 95.0,
                    "Source": "urlhaus",
                    "Last Seen": row.first_seen,
                    "Details": row.malware_family or "-",
                    "Enrichable": False,
                }
            )

    return results[:limit]
