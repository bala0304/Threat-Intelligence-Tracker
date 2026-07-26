# API Documentation

## Overview

The Threat Intelligence Tracker provides a comprehensive REST API for accessing threat intelligence data. All endpoints are available at `/api/v1/`.

## Base URL

```
http://localhost:8000/api/v1
```

## Authentication

Currently, all endpoints are open (CORS enabled for all origins). For production, add API key authentication:

```python
# In future implementation
Authorization: Bearer YOUR_API_KEY
```

## Response Format

All responses are JSON with the following structure:

### Success Response
```json
{
  "data": {...},
  "status": "success",
  "timestamp": "2024-06-16T10:30:00Z"
}
```

### Error Response
```json
{
  "error": "Error message",
  "detail": "Detailed error description",
  "status_code": 400,
  "timestamp": "2024-06-16T10:30:00Z"
}
```

## Endpoints

### C2 Infrastructure

#### Get All C2 Infrastructure
```
GET /c2/all
```

**Parameters:**
- `skip` (query, int, default: 0) - Offset for pagination
- `limit` (query, int, default: 50, max: 500) - Number of results

**Response:**
```json
[
  {
    "id": 1,
    "ip_address": "192.168.1.1",
    "port": 4444,
    "protocol": "TCP",
    "domain": "evil.com",
    "country": "US",
    "asn": "AS12345",
    "isp": "Example ISP",
    "first_seen": "2024-06-01T00:00:00",
    "last_seen": "2024-06-16T10:00:00",
    "confidence_score": 95.5,
    "is_active": true,
    "source": "shodan"
  }
]
```

#### Search C2 Infrastructure
```
POST /c2/search
```

**Request Body:**
```json
{
  "country": "US",
  "is_active": true,
  "min_confidence": 80.0,
  "limit": 50
}
```

**Response:** Same as GET /c2/all

#### Get C2 by IP
```
GET /c2/ip/{ip}
```

**Path Parameters:**
- `ip` (string, required) - IP address

**Response:** Single C2Infrastructure object (see above)

#### Get Associated Domains
```
GET /c2/ip/{ip}/domains
```

**Response:**
```json
{
  "ip": "192.168.1.1",
  "domains": [
    "evil.com",
    "c2-server.xyz"
  ],
  "total": 2
}
```

#### Get DNS History
```
GET /c2/ip/{ip}/dns-history
```

**Response:**
```json
{
  "ip": "192.168.1.1",
  "dns_records": [
    {
      "domain": "evil.com",
      "record_type": "A",
      "first_seen": "2024-06-01T00:00:00",
      "last_seen": "2024-06-16T10:00:00"
    }
  ],
  "total": 5
}
```

### Threat Indicators

#### Get All Indicators
```
GET /indicators
```

**Parameters:**
- `skip` (query, int, default: 0)
- `limit` (query, int, default: 50, max: 500)

**Response:**
```json
[
  {
    "id": 1,
    "indicator": "192.168.1.1",
    "indicator_type": "ip",
    "threat_type": "c2",
    "description": "Known C2 server",
    "first_seen": "2024-06-01T00:00:00",
    "last_seen": "2024-06-16T10:00:00",
    "confidence_score": 98.5,
    "severity": "critical",
    "sources": ["threatfox", "shodan"],
    "tags": {
      "malware": "emotet",
      "campaign": "2024-Q2"
    }
  }
]
```

#### Search Indicators
```
POST /indicators/search
```

**Request Body:**
```json
{
  "indicator_type": "ip",
  "threat_type": "c2",
  "severity": "critical",
  "limit": 50
}
```

**Response:** Array of ThreatIndicator objects

#### Get Specific Indicator
```
GET /indicators/{indicator}
```

**Path Parameters:**
- `indicator` (string, required) - The IOC value

**Response:** Single ThreatIndicator object

### Domains

#### Get Malicious Domains
```
GET /domains
```

**Parameters:**
- `skip` (query, int, default: 0)
- `limit` (query, int, default: 50, max: 500)

**Response:**
```json
[
  {
    "id": 1,
    "domain": "evil.com",
    "registrar": "GoDaddy",
    "is_malicious": true,
    "confidence_score": 95.0,
    "creation_date": "2024-01-01T00:00:00",
    "expiration_date": "2025-01-01T00:00:00",
    "last_updated": "2024-06-16T10:00:00"
  }
]
```

#### Get Domain Details
```
GET /domains/{domain}
```

**Path Parameters:**
- `domain` (string, required) - Domain name

**Response:** Single DomainIntelligence object

### Passive DNS

#### Query Passive DNS
```
GET /pdns/{query}
```

**Path Parameters:**
- `query` (string, required) - Domain or IP address

**Query Parameters:**
- `skip` (query, int, default: 0)
- `limit` (query, int, default: 100, max: 1000)

**Response:**
```json
[
  {
    "id": 1,
    "domain": "evil.com",
    "ip_address": "192.168.1.1",
    "record_type": "A",
    "first_seen": "2024-06-01T00:00:00",
    "last_seen": "2024-06-16T10:00:00",
    "source": "passivedns"
  }
]
```

### URLhaus

#### Get Malware URLs
```
GET /urlhaus
```

**Parameters:**
- `skip` (query, int, default: 0)
- `limit` (query, int, default: 50, max: 500)

**Response:**
```json
[
  {
    "id": 1,
    "url": "http://malware.com/payload.exe",
    "url_status": "online",
    "host": "malware.com",
    "malware_family": "emotet",
    "threat_type": "malware",
    "first_seen": "2024-06-01T00:00:00",
    "last_checked": "2024-06-16T10:00:00"
  }
]
```

#### Get URLs by Host
```
GET /urlhaus/host/{host}
```

**Path Parameters:**
- `host` (string, required) - Hosting domain

**Response:** Array of URLhaus objects

### Statistics

#### Get Overview
```
GET /stats/overview
```

**Response:**
```json
{
  "c2_total": 1500,
  "c2_active": 450,
  "indicators_total": 50000,
  "malicious_domains": 5000,
  "malware_urls": 10000,
  "pdns_records": 100000,
  "last_updated": "2024-06-16T10:30:00Z"
}
```

#### Get C2 by Country
```
GET /stats/c2-by-country
```

**Response:**
```json
{
  "countries": [
    {"country": "US", "count": 450},
    {"country": "CN", "count": 350},
    {"country": "RU", "count": 200}
  ]
}
```

#### Get Threats by Severity
```
GET /stats/threats-by-severity
```

**Response:**
```json
{
  "severities": [
    {"severity": "critical", "count": 5000},
    {"severity": "high", "count": 15000},
    {"severity": "medium", "count": 20000},
    {"severity": "low", "count": 10000}
  ]
}
```

### Feed Management

#### Ingest All Feeds
```
POST /feeds/ingest/all
```

**Response:**
```json
{
  "start_time": "2024-06-16T10:30:00Z",
  "end_time": "2024-06-16T10:35:00Z",
  "feeds": {
    "threatfox": {
      "status": "success",
      "records_ingested": 150,
      "records_updated": 50,
      "errors": 0
    },
    "urlhaus": {
      "status": "success",
      "records_ingested": 300,
      "records_updated": 100,
      "errors": 0
    }
  },
  "total_ingested": 450,
  "total_updated": 150,
  "total_errors": 0
}
```

#### Ingest Specific Feed
```
POST /feeds/ingest/{feed_name}
```

**Path Parameters:**
- `feed_name` (string, required) - Feed identifier (threatfox, urlhaus)

**Response:**
```json
{
  "feed": "threatfox",
  "status": "success",
  "records_ingested": 150,
  "records_updated": 50,
  "errors": 0
}
```

#### Get Available Feeds
```
GET /feeds/available
```

**Response:**
```json
{
  "feeds": [
    {
      "name": "threatfox",
      "description": "Live C2 IOCs from abuse.ch",
      "type": "c2_indicators",
      "frequency": "real-time"
    },
    {
      "name": "urlhaus",
      "description": "Malware distribution URLs",
      "type": "malware_urls",
      "frequency": "hourly"
    }
  ]
}
```

### Health

#### Health Check
```
GET /health
```

**Response:**
```json
{
  "status": "healthy",
  "timestamp": "2024-06-16T10:30:00Z"
}
```

## Error Codes

| Code | Description |
|------|-------------|
| 200 | Success |
| 400 | Bad Request |
| 401 | Unauthorized |
| 403 | Forbidden |
| 404 | Not Found |
| 429 | Too Many Requests (Rate Limited) |
| 500 | Internal Server Error |
| 503 | Service Unavailable |

## Rate Limiting

Currently no rate limiting is implemented. For production, add:

```python
from slowapi import Limiter
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter

@app.get("/api/v1/c2/all")
@limiter.limit("100/minute")
def get_c2():
    ...
```

## Pagination

For endpoints returning multiple results, use `skip` and `limit`:

```
GET /api/v1/c2/all?skip=0&limit=50
```

## Filtering

Most list endpoints support filtering via query parameters or POST body:

```
POST /api/v1/c2/search
{
  "country": "US",
  "is_active": true,
  "min_confidence": 80.0,
  "limit": 50
}
```

## Examples

### Python Requests

```python
import requests

# Get all C2 infrastructure
response = requests.get(
    "http://localhost:8000/api/v1/c2/all",
    params={"limit": 20}
)
c2_list = response.json()

# Search indicators
response = requests.post(
    "http://localhost:8000/api/v1/indicators/search",
    json={
        "severity": "critical",
        "limit": 50
    }
)
indicators = response.json()

# Query pDNS
response = requests.get(
    "http://localhost:8000/api/v1/pdns/example.com"
)
dns_records = response.json()
```

### cURL

```bash
# Get C2 by IP
curl "http://localhost:8000/api/v1/c2/ip/192.168.1.1"

# Search indicators
curl -X POST "http://localhost:8000/api/v1/indicators/search" \
  -H "Content-Type: application/json" \
  -d '{"severity": "critical"}'

# Ingest feeds
curl -X POST "http://localhost:8000/api/v1/feeds/ingest/all"
```

## WebSocket Support (Future)

Real-time updates via WebSocket:

```javascript
ws = new WebSocket("ws://localhost:8000/api/v1/ws/alerts");
ws.onmessage = function(event) {
  console.log(JSON.parse(event.data));
};
```

