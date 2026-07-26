# Usage Examples

## 📋 Table of Contents
1. [CLI Examples](#cli-examples)
2. [REST API Examples](#rest-api-examples)
3. [Python SDK Examples](#python-sdk-examples)
4. [Dashboard Features](#dashboard-features)
5. [Advanced Scenarios](#advanced-scenarios)

## CLI Examples

### Feed Management

```bash
# Ingest all threat intelligence feeds
python main.py cli feeds ingest-all

# Ingest specific feed
python main.py cli feeds ingest threatfox
python main.py cli feeds ingest urlhaus

# Output
# ✓ Ingestion complete!
#   Total records ingested: 450
#   Total records updated: 150
#   Errors: 0
```

### C2 Infrastructure Search

```bash
# List active C2 infrastructure
python main.py cli c2 list

# List with custom limit
python main.py cli c2 list --limit 50

# Output
# Active C2 Infrastructure:
# ┌─────────────────┬──────┬─────────┬──────────────────┬──────┬──────────────────┬────────┐
# │ IP              │ Port │ Country │ ISP              │ Conf │ Last Seen        │ Source │
# ├─────────────────┼──────┼─────────┼──────────────────┼──────┼──────────────────┼────────┤
# │ 192.168.1.1     │ 4444 │ US      │ Example ISP Inc. │ 95.5 │ 2024-06-16 10:30 │ shodan │
# │ 10.0.0.1        │ 8080 │ CN      │ Unknown          │ 87.2 │ 2024-06-16 09:45 │ censys │
# └─────────────────┴──────┴─────────┴──────────────────┴──────┴──────────────────┴────────┘
```

```bash
# Get detailed C2 information
python main.py cli c2 lookup 192.168.1.1

# Output
# 📊 C2 Infrastructure Details: 192.168.1.1
# ──────────────────────────────────────────────────
# Port: 4444
# Protocol: TCP
# Country: US
# ISP: Example ISP Inc.
# ASN: AS12345
# Confidence Score: 95.5%
# Active: Yes
# First Seen: 2024-06-01 00:00:00
# Last Seen: 2024-06-16 10:30:00
# Source: shodan
# Tags:
#   malware: emotet
#   campaign: 2024-Q2
```

### Threat Indicators Search

```bash
# Search all critical severity threats
python main.py cli indicators search --severity critical

# Search by type
python main.py cli indicators search --type ip --limit 50

# Search by threat type and limit results
python main.py cli indicators search --threat-type malware --limit 100

# Output
# Threat Indicators:
# ┌──────────────────┬────────┬──────────┬──────────┬────────┬──────────────┐
# │ Indicator        │ Type   │ Threat   │ Severity │ Conf   │ Last Seen    │
# ├──────────────────┼────────┼──────────┼──────────┼────────┼──────────────┤
# │ 192.168.1.1      │ ip     │ c2       │ critical │ 98.5%  │ 2024-06-16   │
# │ evil.com         │ domain │ c2       │ high     │ 95.0%  │ 2024-06-16   │
# └──────────────────┴────────┴──────────┴──────────┴────────┴──────────────┘
```

### URLhaus Malware URLs

```bash
# List all malware URLs (default: online only)
python main.py cli urlhaus list

# List offline/suspended URLs
python main.py cli urlhaus list --status offline

# Output
# Malware Distribution URLs:
# ┌────────────────────────────────────────┬────────┬──────────────┬──────────────┬──────────────┐
# │ URL                                    │ Status │ Host         │ Malware      │ First Seen   │
# ├────────────────────────────────────────┼────────┼──────────────┼──────────────┼──────────────┤
# │ http://malware.com/payload.exe         │ online │ malware.com  │ emotet       │ 2024-06-01   │
# │ https://evil.xyz/payload/trojan.zip    │ online │ evil.xyz     │ trickbot     │ 2024-06-02   │
# └────────────────────────────────────────┴────────┴──────────────┴──────────────┴──────────────┘
```

### Statistics

```bash
# Get overview statistics
python main.py cli stats overview

# Output
# 📈 Threat Intelligence Overview
# ────────────────────────────────────────
# C2 Infrastructure (Total): 1500
# C2 Infrastructure (Active): 450
# Threat Indicators: 50000
# Malware URLs: 10000
```

## REST API Examples

### Using cURL

```bash
# Health check
curl http://localhost:8000/api/v1/health

# Get all active C2 infrastructure (limit 10)
curl "http://localhost:8000/api/v1/c2/all?limit=10"

# Search C2 by country
curl -X POST http://localhost:8000/api/v1/c2/search \
  -H "Content-Type: application/json" \
  -d '{
    "country": "US",
    "is_active": true,
    "min_confidence": 80.0,
    "limit": 20
  }'

# Get specific IP details
curl http://localhost:8000/api/v1/c2/ip/192.168.1.1

# Get associated domains
curl http://localhost:8000/api/v1/c2/ip/192.168.1.1/domains

# Get DNS history
curl http://localhost:8000/api/v1/c2/ip/192.168.1.1/dns-history

# Search critical indicators
curl -X POST http://localhost:8000/api/v1/indicators/search \
  -H "Content-Type: application/json" \
  -d '{
    "severity": "critical",
    "limit": 50
  }'

# Query specific indicator
curl "http://localhost:8000/api/v1/indicators/192.168.1.1"

# Query passive DNS
curl "http://localhost:8000/api/v1/pdns/example.com"

# Get malware URLs
curl "http://localhost:8000/api/v1/urlhaus?limit=50"

# Get stats overview
curl http://localhost:8000/api/v1/stats/overview

# Get C2 by country
curl http://localhost:8000/api/v1/stats/c2-by-country

# Trigger feed ingestion
curl -X POST http://localhost:8000/api/v1/feeds/ingest/all

# Ingest specific feed
curl -X POST "http://localhost:8000/api/v1/feeds/ingest/threatfox"

# Get available feeds
curl http://localhost:8000/api/v1/feeds/available
```

## Python SDK Examples

### Basic Setup

```python
from src.database.db import db_manager
from src.database.models import C2Infrastructure, ThreatIndicator, URLhaus
from sqlalchemy import desc

db = db_manager.get_session()

try:
    # Your queries here
    pass
finally:
    db.close()
```

### Query C2 Infrastructure

```python
# Get all active C2
c2_list = db.query(C2Infrastructure).filter_by(is_active=True).all()
for c2 in c2_list:
    print(f"{c2.ip_address}: {c2.confidence_score}% confidence")

# Get C2 by country
us_c2 = db.query(C2Infrastructure).filter_by(
    country='US',
    is_active=True
).order_by(desc(C2Infrastructure.confidence_score)).limit(10).all()

# Find high-confidence C2
critical_c2 = db.query(C2Infrastructure).filter(
    C2Infrastructure.confidence_score >= 90.0
).all()
```

### Query Threat Indicators

```python
# Get critical indicators
critical = db.query(ThreatIndicator).filter_by(severity='critical').all()

# Get specific indicator type
ip_indicators = db.query(ThreatIndicator).filter_by(indicator_type='ip').all()

# Search by threat type
c2_indicators = db.query(ThreatIndicator).filter_by(threat_type='c2').all()

# Get recently updated
recent = db.query(ThreatIndicator).order_by(
    desc(ThreatIndicator.last_seen)
).limit(100).all()
```

### Query Malware URLs

```python
# Get all active malware URLs
active_urls = db.query(URLhaus).filter_by(url_status='online').all()

# Get by malware family
emotet_urls = db.query(URLhaus).filter_by(malware_family='emotet').all()

# Get by host
host_urls = db.query(URLhaus).filter_by(host='malware.com').all()
```

### Feed Ingestion

```python
from src.feeds.orchestrator import FeedOrchestrator

orchestrator = FeedOrchestrator(db)

# Ingest all feeds
result = orchestrator.ingest_all()
print(f"Ingested: {result['total_ingested']}")
print(f"Updated: {result['total_updated']}")
print(f"Errors: {result['total_errors']}")

# Ingest specific feed
threatfox_result = orchestrator.ingest_specific('threatfox')
```

### API Clients

```python
from src.clients.shodan_client import ShodanClient
from src.config import get_settings

settings = get_settings()

# Search Shodan
if settings.shodan_api_key:
    shodan = ShodanClient(settings.shodan_api_key)
    
    # Search for devices
    results = shodan.search('Cobalt Strike')
    
    # Get host details
    host = shodan.get_host('192.168.1.1')
    
    # Search for C2
    c2_results = shodan.search_for_c2(malware_family='emotet')
```

```python
from src.clients.passive_dns import PassiveDNSClient

pdns = PassiveDNSClient()

# Resolve domain
ips = pdns.resolve_domain('example.com')

# Reverse lookup
domain = pdns.reverse_lookup('192.168.1.1')

# Get MX records
mx = pdns.get_mx_records('example.com')

# Get DNS history
history = pdns.get_dns_history('example.com')
```

```python
from src.clients.whois_client import WHOISClient

whois = WHOISClient()

# Lookup domain
data = whois.lookup('example.com')

# Check if suspicious
is_suspicious = whois.is_suspicious(data)

# Track changes
previous = {...}  # previous lookup
changes = whois.track_changes('example.com', previous)
```

## Dashboard Features

### Overview Tab
- Real-time statistics (C2 count, indicators, URLs)
- Recent activity feeds
- Quick summary charts

### C2 Infrastructure Tab
- Filter by country, active status, confidence
- Country distribution chart
- Data source pie chart
- Sortable table view

### Threat Indicators Tab
- Filter by type, severity, confidence
- Severity distribution
- Indicator type breakdown
- Real-time updates

### Malware URLs Tab
- Filter by status, search URLs
- Status distribution
- Top malware families
- Host tracking

### Feed Management Tab
- Manual feed ingestion triggers
- Feed status monitoring
- Available feeds listing
- Ingestion logs

## Advanced Scenarios

### Scenario 1: Monitor New Threats

```python
from src.database.models import ThreatIndicator
from src.database.db import db_manager
from datetime import datetime, timedelta

db = db_manager.get_session()

# Get threats added in last 24 hours
cutoff = datetime.utcnow() - timedelta(hours=24)
new_threats = db.query(ThreatIndicator).filter(
    ThreatIndicator.first_seen >= cutoff
).order_by(desc(ThreatIndicator.confidence_score)).all()

for threat in new_threats:
    print(f"New {threat.threat_type}: {threat.indicator}")
    print(f"  Confidence: {threat.confidence_score}%")
    print(f"  Severity: {threat.severity}")
    print()
```

### Scenario 2: Track Domain Changes

```python
from src.clients.whois_client import WHOISClient

whois = WHOISClient()

# Track domain changes
domain = 'suspicious.com'
current = whois.lookup(domain)

if whois.is_suspicious(current):
    print(f"⚠️  {domain} shows suspicious indicators!")
    print(f"   Registrar: {current['registrar']}")
    print(f"   Email: {current['registrant_email']}")
```

### Scenario 3: Correlate Threats

```python
from src.database.models import C2Infrastructure, PassiveDNSRecord, URLhaus
from sqlalchemy import and_

# Find malware URLs hosted on C2 infrastructure
c2 = db.query(C2Infrastructure).filter_by(ip_address='192.168.1.1').first()

if c2:
    # Get domains pointing to this C2
    domains = db.query(PassiveDNSRecord).filter_by(ip_address=c2.ip_address).all()
    
    # Get malware URLs from those domains
    for dns in domains:
        urls = db.query(URLhaus).filter_by(host=dns.domain).all()
        print(f"Found {len(urls)} malware URLs on {dns.domain}")
```

### Scenario 4: Generate Threat Report

```python
from src.database.models import ThreatIndicator, C2Infrastructure
from src.database.db import db_manager
from datetime import datetime

db = db_manager.get_session()

# Generate daily report
report = {
    'timestamp': datetime.utcnow().isoformat(),
    'summary': {
        'total_c2': db.query(C2Infrastructure).count(),
        'active_c2': db.query(C2Infrastructure).filter_by(is_active=True).count(),
        'total_indicators': db.query(ThreatIndicator).count(),
    },
    'critical_threats': db.query(ThreatIndicator).filter_by(severity='critical').count(),
    'by_country': {},
}

# Top countries
countries = db.query(C2Infrastructure.country, func.count()).group_by(C2Infrastructure.country).all()
for country, count in countries:
    report['by_country'][country or 'Unknown'] = count

print(report)
```

### Scenario 5: Continuous Monitoring

```python
from src.feeds.orchestrator import FeedOrchestrator
from src.database.db import db_manager
import time

db = db_manager.get_session()
orchestrator = FeedOrchestrator(db)

while True:
    print(f"[{datetime.now()}] Running feed ingestion...")
    result = orchestrator.ingest_all()
    
    print(f"  Ingested: {result['total_ingested']}")
    print(f"  Updated: {result['total_updated']}")
    
    # Wait 1 hour before next run
    time.sleep(3600)
```

