# Architecture & Technical Design

## 🏗️ System Architecture

### High-Level Overview

```
┌────────────────────────────────────────────────────────────────┐
│                    Threat Intelligence Tracker                  │
├────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │                    REST API Server (FastAPI)             │   │
│  │  /api/v1/c2, /api/v1/indicators, /api/v1/feeds, etc    │   │
│  └─────────────────────────────────────────────────────────┘   │
│                           │                                     │
│  ┌────────────────────────┼────────────────────────────────┐   │
│  │                        │                                 │   │
│  ▼                        ▼                                 ▼   │
│ ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐   │
│ │ REST Clients │  │ CLI Tool     │  │  Dashboard UI    │   │
│ │ (Python,     │  │ (Click-based)│  │ (Streamlit)      │   │
│ │ JavaScript)  │  │              │  │                  │   │
│ └──────────────┘  └──────────────┘  └──────────────────┘   │
│                                                                  │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │              Core Processing Layer                       │   │
│  │                                                           │   │
│  │  ┌──────────────────┐  ┌──────────────────────────┐   │
│  │  │  API Clients     │  │  Feed Ingestors          │   │
│  │  │  • Shodan        │  │  • ThreatFox             │   │
│  │  │  • Censys        │  │  • URLhaus               │   │
│  │  │  • Binary Edge   │  │  • Orchestrator          │   │
│  │  │  • Zoomeye       │  │                          │   │
│  │  │  • Passive DNS   │  │  ┌──────────────────────┐│   │
│  │  │  • WHOIS         │  │  │ Historical Tracking  ││   │
│  │  └──────────────────┘  │  │ • DNS History        ││   │
│  │                        │  │ • WHOIS Changes      ││   │
│  │                        │  │ • Malware URLs       ││   │
│  │                        │  └──────────────────────┘│   │
│  │                        └──────────────────────────┘   │
│  │                                                           │   │
│  │  ┌──────────────────────────────────────────────────┐   │
│  │  │          Utility & Helper Functions              │   │
│  │  │  • IOC Classification & Validation               │   │
│  │  │  • Data Normalization & Deduplication            │   │
│  │  │  • Threat Scoring & Severity Classification      │   │
│  │  │  • Batch Processing & Pagination                 │   │
│  │  └──────────────────────────────────────────────────┘   │
│  │                                                           │   │
│  └─────────────────────────────────────────────────────────┘   │
│                                                                  │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │           Data Access Layer (SQLAlchemy ORM)            │   │
│  └─────────────────────────────────────────────────────────┘   │
│                           │                                     │
│  ┌────────────────────────┼────────────────────────────────┐   │
│  │                        ▼                                 │   │
│  │  ┌──────────────────────────────────────────────────┐   │
│  │  │        PostgreSQL Database                        │   │
│  │  │                                                   │   │
│  │  │  Tables:                                         │   │
│  │  │  • c2_infrastructure (C2 servers, ports, IPs)    │   │
│  │  │  • domain_intelligence (Domain metadata)         │   │
│  │  │  • passive_dns_records (DNS history)             │   │
│  │  │  • whois_history (Registration data snapshots)   │   │
│  │  │  • threat_indicators (IOCs & correlations)       │   │
│  │  │  • malware_associations (Threat linkage)         │   │
│  │  │  • urlhaus_data (Malware distribution URLs)      │   │
│  │  │  • scan_results (Shodan/Censys data)             │   │
│  │  │  • ingestion_logs (Feed tracking & status)       │   │
│  │  │                                                   │   │
│  │  └──────────────────────────────────────────────────┘   │
│  │                                                           │   │
│  └─────────────────────────────────────────────────────────┘   │
│                                                                  │
└────────────────────────────────────────────────────────────────┘
```

## 📊 Data Model

### Core Entities

#### 1. C2Infrastructure
- **Primary Key**: IP address (unique)
- **Fields**: port, protocol, domain, country, ISP, ASN, confidence_score, is_active, tags, raw_data
- **Relationships**: domains, dns_records, malware_associations
- **Indexes**: country + is_active, source + last_seen
- **Purpose**: Track command and control servers

#### 2. ThreatIndicator
- **Primary Key**: indicator (unique per type)
- **Fields**: indicator_type, threat_type, description, confidence_score, severity, sources, tags, associated_malware
- **Purpose**: Store IOCs (IPs, domains, URLs, hashes)
- **Relationships**: malware_associations
- **Indexes**: indicator_type + threat_type, severity + confidence_score

#### 3. PassiveDNSRecord
- **Primary Key**: Composite (domain, IP, record_type)
- **Fields**: record_type, first_seen, last_seen, source
- **Purpose**: Maintain DNS resolution history
- **Relationships**: infrastructure, domain
- **Indexes**: domain + IP, domain + IP combo

#### 4. WHOISHistory
- **Primary Key**: Composite (domain, snapshot_date)
- **Fields**: registrar, registrant info, name servers, dates, raw WHOIS
- **Purpose**: Track domain registration changes
- **Indexes**: domain + snapshot_date
- **Use Case**: Detect domain hijacking, ownership changes

#### 5. URLhaus
- **Primary Key**: URL (unique)
- **Fields**: url_status, host, malware_family, threat_type, payload_urls, tags
- **Purpose**: Track malware distribution endpoints
- **Relationships**: threat_indicators
- **Indexes**: host + status, malware_family

#### 6. MalwareAssociation
- **Primary Key**: Composite (malware, C2, indicator)
- **Fields**: malware_name, confidence, first_associated, last_confirmed
- **Purpose**: Link malware families to infrastructure
- **Relationships**: c2_infrastructure, threat_indicator

## 🔄 Data Flow

### Feed Ingestion Flow

```
┌─────────────┐
│ ThreatFox   │
│ APIAbuse.ch)│
└──────┬──────┘
       │
       ▼
┌────────────────────┐      ┌──────────────────┐
│ ThreatFoxIngestor  │─────→│ Parse & Validate │
└────────────────────┘      └────────┬─────────┘
                                     │
       ┌─────────────┐               │
       │ URLhaus API │       ┌───────▼────────────┐
       │(Abuse.ch)   │      │  De-duplication    │
       └──────┬──────┘      │  & Enrichment      │
              │             └───────┬────────────┘
              ▼                     │
┌────────────────────┐             │
│ URLhausIngestor    │─────────────┤
└────────────────────┘             │
                                   ▼
                        ┌──────────────────────┐
                        │  Store in Database   │
                        │  Update Relationships│
                        │  Index Optimization  │
                        └──────────────────────┘
```

### Query Flow

```
┌────────────────┐
│ Client Request │
│ (API/CLI/UI)   │
└────────┬───────┘
         │
         ▼
┌──────────────────────┐
│ Route Handler        │
│ (Validate Input)     │
└────────┬─────────────┘
         │
         ▼
┌──────────────────────┐
│ Database Query       │
│ (SQLAlchemy ORM)     │
└────────┬─────────────┘
         │
         ▼
┌──────────────────────┐
│ Result Processing    │
│ (Serialize/Format)   │
└────────┬─────────────┘
         │
         ▼
┌────────────────────┐
│ Response to Client │
└────────────────────┘
```

## 🔌 API Client Architecture

### Base Client Pattern

```python
class BaseAPIClient:
    - Handles authentication
    - Rate limit management
    - Error handling
    - Request/response logging
    
    ├── ShodanClient
    ├── CensysClient
    ├── BinaryEdgeClient
    ├── ZoomeyeClient
    ├── PassiveDNSClient
    └── WHOISClient
```

### Client Responsibilities

**ShodanClient**
- Device scanning queries
- Host detail lookups
- DNS resolution
- C2 pattern detection

**CensysClient**
- IPv4 scanning data
- Certificate analysis
- Service identification
- Vulnerability mapping

**PassiveDNSClient**
- DNS resolution history
- Reverse lookups
- MX/NS record queries
- CIRCL pDNS integration

**WHOISClient**
- Domain registration data
- Change tracking
- Suspicious indicator detection
- Historical snapshots

## 📚 Feed Ingestor Architecture

### FeedOrchestrator

```python
FeedOrchestrator
├── ingest_all()
│   └── Iterate through all ingestors
│       └── Collect & aggregate results
│
└── ingest_specific(feed_name)
    └── Run specific ingestor
        ├── fetch() - Get data from API
        ├── parse() - Transform to standard format
        └── ingest() - Store in database
```

### Ingestor Lifecycle

1. **Fetch**: Retrieve data from source API
2. **Parse**: Normalize to internal data model
3. **Validate**: Check data quality & uniqueness
4. **Deduplicate**: Merge with existing records
5. **Store**: Persist to database
6. **Log**: Record ingestion metadata

## 🗄️ Database Design

### Schema Highlights

- **Temporal Tracking**: first_seen, last_seen for trend analysis
- **Confidence Scoring**: Data quality metrics
- **Source Tracking**: Multi-source attribution
- **Denormalization**: Performance optimization for common queries
- **Indexing**: Strategic indexes for fast lookups

### Performance Optimizations

```sql
-- Key indexes for fast lookups
CREATE INDEX idx_c2_country_active ON c2_infrastructure(country, is_active);
CREATE INDEX idx_indicator_type_threat ON threat_indicators(indicator_type, threat_type);
CREATE INDEX idx_pdns_domain_ip ON passive_dns_records(domain, ip_address);
CREATE INDEX idx_urlhaus_host_status ON urlhaus_data(host, url_status);

-- Composite indexes for common filter combinations
CREATE INDEX idx_c2_source_lastseen ON c2_infrastructure(source, last_seen);
CREATE INDEX idx_indicator_severity ON threat_indicators(severity, confidence_score);
```

## 🔐 Security Architecture

### Authentication & Authorization
- API key validation (future)
- Role-based access control (future)
- Database credential encryption

### Data Protection
- Environment-based secrets management
- No credentials in code/logs
- Input validation & sanitization
- SQL injection prevention (SQLAlchemy ORM)

## 🚀 Scalability Considerations

### Horizontal Scaling
- Stateless REST API (multiple instances)
- Load balancer for distribution
- Shared PostgreSQL backend

### Vertical Scaling
- Query optimization & indexing
- Connection pooling
- Caching layer (Redis)

### Data Growth
- Archival strategy for old records
- Partitioning by date range
- Read replicas for analytics

## 📊 Monitoring & Observability

### Logging
- Structured logging with loguru
- Log levels: DEBUG, INFO, WARNING, ERROR
- Feed ingestion audit trail

### Metrics (Future)
- Request latency
- Database query performance
- Feed ingestion rates
- API endpoint usage

### Alerting (Future)
- Anomaly detection
- Feed ingestion failures
- Database health
- API availability

## 🔄 Extension Points

### Adding New Feeds

```python
class NewFeedIngestor(BaseFeedIngestor):
    def fetch(self):
        # Retrieve data from source
        pass
    
    def parse(self, raw_data):
        # Normalize to internal format
        pass
    
    def ingest(self):
        # Store in database
        pass

# Register in FeedOrchestrator
self.ingestors['new_feed'] = NewFeedIngestor(db_session)
```

### Adding New API Clients

```python
class NewServiceClient(BaseAPIClient):
    def authenticate(self):
        # Handle authentication
        pass
    
    def search(self, query):
        # Execute search
        pass
    
    def parse_result(self, result):
        # Transform result to standard format
        pass
```

## 📈 Data Volume Estimates

| Entity | Typical Volume | Growth Rate |
|--------|---|---|
| C2 Infrastructure | 10K-50K | 5-10% monthly |
| Threat Indicators | 100K-500K | 10-20% monthly |
| pDNS Records | 1M-5M | 15-25% monthly |
| WHOIS History | 10K-100K | 5-10% monthly |
| URLhaus | 50K-500K | 10-15% monthly |

