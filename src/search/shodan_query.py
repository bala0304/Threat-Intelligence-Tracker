"""Parse Shodan-style search queries into structured filters and free text."""
import re
from dataclasses import dataclass, field
from typing import Dict, List

# Filters we understand for local DB search (unknown keys stay in free text).
KNOWN_FILTERS = {
    "port",
    "country",
    "ip",
    "net",
    "hostname",
    "domain",
    "org",
    "isp",
    "asn",
    "city",
    "product",
    "os",
    "ssl",
    "version",
    "hash",
    "vuln",
    "tag",
    "source",
    "malware",
    "severity",
    "type",
    "http.title",
    "http.html",
    "http.status",
    "http.component",
    "http.server",
}

FILTER_PATTERN = re.compile(
    r'([\w.]+):("(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|[^\s]+)'
)


@dataclass
class ParsedQuery:
    """Structured representation of a Shodan-style query."""

    filters: Dict[str, str] = field(default_factory=dict)
    free_text: str = ""
    raw: str = ""

    @property
    def has_filters(self) -> bool:
        return bool(self.filters)

    @property
    def has_free_text(self) -> bool:
        return bool(self.free_text.strip())


def _strip_quotes(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        return value[1:-1]
    return value


def parse_shodan_query(query: str) -> ParsedQuery:
    """
    Parse queries like:
      port:443 country:US org:"Digital Ocean"
      HTTP/1.1 200 OK Server: nginx/1.1.19
      ip:8.8.8.8 product:nginx
    """
    raw = (query or "").strip()
    if not raw:
        return ParsedQuery(raw=raw)

    filters: Dict[str, str] = {}
    consumed_spans: List[tuple[int, int]] = []

    for match in FILTER_PATTERN.finditer(raw):
        key = match.group(1).lower()
        if key not in KNOWN_FILTERS:
            continue
        value = _strip_quotes(match.group(2))
        filters[key] = value
        consumed_spans.append(match.span())

    free_parts: List[str] = []
    cursor = 0
    for start, end in sorted(consumed_spans):
        if start > cursor:
            free_parts.append(raw[cursor:start])
        cursor = end
    if cursor < len(raw):
        free_parts.append(raw[cursor:])

    free_text = " ".join(" ".join(free_parts).split())
    return ParsedQuery(filters=filters, free_text=free_text, raw=raw)
