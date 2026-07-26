"""On-demand IP enrichment via Shodan and optional Censys."""
import re
from datetime import datetime
from typing import Any, Dict, List, Optional

from loguru import logger
from sqlalchemy.orm import Session

from src.clients.censys_client import CensysClient
from src.clients.shodan_client import ShodanClient
from src.config import get_settings
from src.database.models import C2Infrastructure, ScanResult

IP_PATTERN = re.compile(
    r"^(?:\d{1,3}\.){3}\d{1,3}$"
)


def normalize_ip(value: str) -> Optional[str]:
    """Extract a bare IPv4 address from ip or ip:port values."""
    if not value:
        return None
    candidate = value.strip().split(":")[0]
    if IP_PATTERN.match(candidate):
        return candidate
    return None


def _extract_shodan_scan(host: Dict[str, Any]) -> Dict[str, Any]:
    ports = host.get("ports") or []
    services = []
    banners = []
    http_headers = []

    for item in host.get("data") or []:
        services.append(
            {
                "port": item.get("port"),
                "transport": item.get("transport"),
                "product": item.get("product"),
                "version": item.get("version"),
                "banner": item.get("data"),
                "http": item.get("http"),
            }
        )
        if item.get("data"):
            banners.append(item["data"])
        http = item.get("http") or {}
        if http.get("headers"):
            http_headers.append(http["headers"])

    return {
        "ports": ports,
        "services": services,
        "banners": banners,
        "http_headers": http_headers,
        "certificates": host.get("ssl") or host.get("certificates"),
        "raw_data": host,
    }


def _apply_shodan_to_c2(c2: C2Infrastructure, host: Dict[str, Any]) -> None:
    c2.country = host.get("country_code") or c2.country
    c2.isp = host.get("isp") or host.get("org") or c2.isp
    if host.get("asn"):
        c2.asn = f"AS{host['asn']}"
    if host.get("hostnames"):
        c2.domain = c2.domain or host["hostnames"][0]
    if host.get("ports") and not c2.port:
        c2.port = host["ports"][0]
    c2.last_seen = datetime.utcnow()
    tags = dict(c2.tags or {})
    tags["shodan_enriched"] = datetime.utcnow().isoformat()
    if host.get("tags"):
        tags["shodan_tags"] = host["tags"]
    c2.tags = tags


def enrich_ip(
    db_session: Session,
    ip_or_indicator: str,
    use_shodan: bool = True,
    use_censys: bool = False,
) -> Dict[str, Any]:
    """
    Enrich a single IP using configured external APIs.
    Uses one Shodan host lookup (1 query credit) when enabled.
    """
    ip = normalize_ip(ip_or_indicator)
    if not ip:
        raise ValueError(f"Not a valid IPv4 address: {ip_or_indicator}")

    settings = get_settings()
    result: Dict[str, Any] = {
        "ip": ip,
        "sources": [],
        "errors": [],
        "c2_updated": False,
    }

    c2 = db_session.query(C2Infrastructure).filter_by(ip_address=ip).first()

    if use_shodan and settings.shodan_api_key:
        try:
            client = ShodanClient(settings.shodan_api_key)
            host = client.get_host(ip)
            scan_payload = _extract_shodan_scan(host)

            db_session.add(
                ScanResult(
                    ip_address=ip,
                    scan_source="shodan",
                    scan_date=datetime.utcnow(),
                    ports=scan_payload["ports"],
                    services=scan_payload["services"],
                    certificates=scan_payload["certificates"],
                    http_headers=scan_payload["http_headers"],
                    banners=scan_payload["banners"],
                    raw_data=scan_payload["raw_data"],
                )
            )

            if c2:
                _apply_shodan_to_c2(c2, host)
            else:
                c2 = C2Infrastructure(
                    ip_address=ip,
                    country=host.get("country_code"),
                    isp=host.get("isp") or host.get("org"),
                    asn=f"AS{host['asn']}" if host.get("asn") else None,
                    port=host["ports"][0] if host.get("ports") else None,
                    domain=host["hostnames"][0] if host.get("hostnames") else None,
                    confidence_score=80.0,
                    is_active=True,
                    source="shodan",
                    tags={"shodan_enriched": datetime.utcnow().isoformat()},
                )
                db_session.add(c2)

            result["sources"].append("shodan")
            result["shodan"] = {
                "country": host.get("country_code"),
                "isp": host.get("isp"),
                "asn": host.get("asn"),
                "ports": host.get("ports", []),
                "hostnames": host.get("hostnames", []),
                "tags": host.get("tags", []),
            }
            result["c2_updated"] = True
        except Exception as exc:
            logger.error(f"Shodan enrichment failed for {ip}: {exc}")
            result["errors"].append(f"shodan: {exc}")
    elif use_shodan:
        result["errors"].append("shodan: SHODAN_API_KEY not configured")

    censys_token = settings.resolved_censys_token
    censys_ready = bool(censys_token)
    if use_censys and censys_ready:
        try:
            client = CensysClient(api_token=censys_token)
            host = client.get_ipv4(ip)
            result["sources"].append("censys")
            result["censys"] = host
        except Exception as exc:
            logger.error(f"Censys enrichment failed for {ip}: {exc}")
            result["errors"].append(f"censys: {exc}")
    elif use_censys:
        result["errors"].append("censys: CENSYS_PAT not configured")

    if not result["sources"] and result["errors"]:
        db_session.rollback()
        raise RuntimeError("; ".join(result["errors"]))

    db_session.commit()
    return result


def search_shodan_live(query: str, limit: int = 10) -> Dict[str, Any]:
    """Run a live Shodan search (consumes query credits)."""
    settings = get_settings()
    if not settings.shodan_api_key:
        raise ValueError("SHODAN_API_KEY is not configured")

    client = ShodanClient(settings.shodan_api_key)
    response = client.search(query, limit=min(limit, 100))
    matches = response.get("matches", [])[:limit]

    rows = []
    for match in matches:
        rows.append(
            {
                "Entity": "Shodan Live",
                "Value": match.get("ip_str") or match.get("ip"),
                "IP": match.get("ip_str") or match.get("ip"),
                "Type": f"port:{match.get('port')}" if match.get("port") else "host",
                "Country": match.get("location", {}).get("country_code", "-"),
                "Port": match.get("port"),
                "Severity": "info",
                "Confidence": 100.0,
                "Source": "shodan_live",
                "Last Seen": match.get("timestamp"),
                "Details": (match.get("data") or "")[:120],
                "Enrichable": True,
            }
        )

    return {
        "total": response.get("total", 0),
        "matches": rows,
    }
