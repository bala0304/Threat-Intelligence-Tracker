"""SQLAlchemy ORM models for threat intelligence data."""
from datetime import datetime
from sqlalchemy import (
    Column, Integer, String, Text, DateTime, Boolean, 
    Float, ForeignKey, Index, UniqueConstraint, JSON
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship

Base = declarative_base()


class C2Infrastructure(Base):
    """Model for C2 infrastructure tracking."""
    __tablename__ = "c2_infrastructure"
    
    id = Column(Integer, primary_key=True)
    ip_address = Column(String(45), nullable=False, unique=True, index=True)
    port = Column(Integer)
    protocol = Column(String(50))  # TCP, UDP, HTTP, HTTPS
    domain = Column(String(255), index=True)
    asn = Column(String(50))
    country = Column(String(2))
    isp = Column(String(255))
    last_seen = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    first_seen = Column(DateTime, default=datetime.utcnow)
    confidence_score = Column(Float, default=0.0)  # 0-100
    is_active = Column(Boolean, default=True)
    tags = Column(JSON, default=dict)  # Store tags like 'cobalt_strike', 'emotet', etc.
    source = Column(String(100))  # shodan, censys, threatfox, etc.
    raw_data = Column(JSON)
    
    # Relationships
    domains = relationship("DomainIntelligence", back_populates="c2_ip")
    dns_records = relationship("PassiveDNSRecord", back_populates="infrastructure")
    malware_associations = relationship("MalwareAssociation", back_populates="c2_infrastructure")
    
    __table_args__ = (
        Index("ix_c2_country_active", "country", "is_active"),
        Index("ix_c2_source_lastSeen", "source", "last_seen"),
    )


class DomainIntelligence(Base):
    """Model for domain tracking."""
    __tablename__ = "domain_intelligence"
    
    id = Column(Integer, primary_key=True)
    domain = Column(String(255), nullable=False, unique=True, index=True)
    registrar = Column(String(255))
    creation_date = Column(DateTime)
    expiration_date = Column(DateTime)
    registrant_email = Column(String(255))
    registrant_org = Column(String(255))
    name_servers = Column(JSON)
    is_malicious = Column(Boolean, default=False)
    confidence_score = Column(Float, default=0.0)
    last_updated = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    sources = Column(JSON, default=list)
    c2_ip_id = Column(Integer, ForeignKey("c2_infrastructure.id"))
    
    # Relationships
    c2_ip = relationship("C2Infrastructure", back_populates="domains")
    dns_records = relationship("PassiveDNSRecord", back_populates="domain_obj")
    
    __table_args__ = (
        Index("ix_domain_malicious", "domain", "is_malicious"),
    )


class PassiveDNSRecord(Base):
    """Model for passive DNS records."""
    __tablename__ = "passive_dns_records"
    
    id = Column(Integer, primary_key=True)
    domain = Column(String(255), nullable=False, index=True)
    ip_address = Column(String(45), nullable=False, index=True)
    record_type = Column(String(10))  # A, AAAA, MX, NS, CNAME, etc.
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    confidence = Column(Float)
    source = Column(String(100))  # passivedns, threatfox, etc.
    infrastructure_id = Column(Integer, ForeignKey("c2_infrastructure.id"))
    domain_id = Column(Integer, ForeignKey("domain_intelligence.id"))
    
    # Relationships
    infrastructure = relationship("C2Infrastructure", back_populates="dns_records")
    domain_obj = relationship("DomainIntelligence", back_populates="dns_records")
    
    __table_args__ = (
        UniqueConstraint("domain", "ip_address", "record_type", name="uq_pdns_record"),
        Index("ix_pdns_domain_ip", "domain", "ip_address"),
    )


class WHOISHistory(Base):
    """Model for WHOIS history tracking."""
    __tablename__ = "whois_history"
    
    id = Column(Integer, primary_key=True)
    domain = Column(String(255), nullable=False, index=True)
    registrar = Column(String(255))
    registrant_name = Column(String(255))
    registrant_email = Column(String(255))
    registrant_phone = Column(String(20))
    registrant_organization = Column(String(255))
    registrant_country = Column(String(2))
    admin_email = Column(String(255))
    tech_email = Column(String(255))
    name_servers = Column(JSON)
    creation_date = Column(DateTime)
    expiration_date = Column(DateTime)
    update_date = Column(DateTime)
    snapshot_date = Column(DateTime, default=datetime.utcnow, index=True)
    raw_whois = Column(Text)
    
    __table_args__ = (
        Index("ix_whois_domain_snapshot", "domain", "snapshot_date"),
    )


class ThreatIndicator(Base):
    """Model for individual threat indicators (IOCs)."""
    __tablename__ = "threat_indicators"
    
    id = Column(Integer, primary_key=True)
    indicator = Column(String(500), nullable=False, unique=True, index=True)
    indicator_type = Column(String(50))  # ip, domain, url, file_hash, email
    threat_type = Column(String(100))  # malware, c2, botnet, etc.
    description = Column(Text)
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    confidence_score = Column(Float, default=0.0)
    severity = Column(String(20))  # critical, high, medium, low
    sources = Column(JSON, default=list)  # threatfox, urlhaus, etc.
    tags = Column(JSON, default=dict)
    associated_malware = Column(JSON)  # List of malware families
    
    __table_args__ = (
        Index("ix_indicator_type_threat", "indicator_type", "threat_type"),
        Index("ix_indicator_severity", "severity", "confidence_score"),
    )


class MalwareAssociation(Base):
    """Model for linking malware to infrastructure."""
    __tablename__ = "malware_associations"
    
    id = Column(Integer, primary_key=True)
    malware_name = Column(String(255), nullable=False)
    malware_family = Column(String(255))
    c2_infrastructure_id = Column(Integer, ForeignKey("c2_infrastructure.id"))
    indicator_id = Column(Integer, ForeignKey("threat_indicators.id"))
    first_associated = Column(DateTime, default=datetime.utcnow)
    last_confirmed = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    confidence = Column(Float)
    source = Column(String(100))
    
    # Relationships
    c2_infrastructure = relationship("C2Infrastructure", back_populates="malware_associations")
    indicator = relationship("ThreatIndicator")
    
    __table_args__ = (
        Index("ix_malware_family", "malware_family"),
    )


class URLhaus(Base):
    """Model for URLhaus malware distribution URLs."""
    __tablename__ = "urlhaus_data"
    
    id = Column(Integer, primary_key=True)
    url = Column(String(2000), nullable=False, unique=True, index=True)
    url_status = Column(String(50))  # online, offline, suspended
    host = Column(String(255), index=True)
    date_added = Column(DateTime)
    threat_type = Column(String(100))  # phishing, malware, etc.
    malware_family = Column(String(255))
    payload_urls = Column(JSON)  # URLs hosting the actual malware
    tags = Column(JSON, default=list)
    urlhaus_reference = Column(String(255))
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_checked = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    __table_args__ = (
        Index("ix_urlhaus_host_status", "host", "url_status"),
        Index("ix_urlhaus_malware", "malware_family"),
    )


class ScanResult(Base):
    """Model for storing scan results from Shodan/Censys."""
    __tablename__ = "scan_results"
    
    id = Column(Integer, primary_key=True)
    ip_address = Column(String(45), nullable=False, index=True)
    scan_source = Column(String(50))  # shodan, censys, etc.
    scan_date = Column(DateTime, default=datetime.utcnow)
    ports = Column(JSON)  # Open ports and services
    services = Column(JSON)  # Service information
    certificates = Column(JSON)
    http_headers = Column(JSON)
    banners = Column(JSON)
    vulnerabilities = Column(JSON)
    raw_data = Column(JSON)
    
    __table_args__ = (
        Index("ix_scan_source_date", "scan_source", "scan_date"),
    )


class IngestionLog(Base):
    """Model for tracking feed ingestion."""
    __tablename__ = "ingestion_logs"
    
    id = Column(Integer, primary_key=True)
    feed_source = Column(String(100), nullable=False)
    feed_type = Column(String(50))  # threatfox, urlhaus, shodan, etc.
    ingestion_start = Column(DateTime, default=datetime.utcnow)
    ingestion_end = Column(DateTime)
    records_ingested = Column(Integer)
    records_updated = Column(Integer)
    errors_encountered = Column(Integer, default=0)
    status = Column(String(50))  # success, partial, failed
    error_details = Column(Text)
    next_scheduled_run = Column(DateTime)
    
    __table_args__ = (
        Index("ix_ingestion_source_date", "feed_source", "ingestion_start"),
    )
