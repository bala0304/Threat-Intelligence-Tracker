"""CLI tool for Threat Intelligence Tracker."""
import click
from sqlalchemy import text
from tabulate import tabulate
from src.database.db import db_manager
from src.feeds.orchestrator import FeedOrchestrator
from src.clients.shodan_client import ShodanClient
from src.clients.censys_client import CensysClient
from src.clients.binary_edge_client import BinaryEdgeClient
from src.clients.zoomeye_client import ZoomeyeClient
from src.clients.passive_dns import PassiveDNSClient
from src.clients.whois_client import WHOISClient
from src.config import get_settings
from src.database.models import C2Infrastructure, ThreatIndicator, URLhaus
from sqlalchemy import desc, and_
import json


def ensure_database_ready():
    """Verify PostgreSQL is reachable and schema exists before ingestion."""
    db = db_manager.get_session()
    try:
        db.execute(text("SELECT 1"))
        return db
    except Exception as exc:
        db.close()
        click.echo("✗ Database connection failed.")
        click.echo(f"  {exc}")
        click.echo("")
        click.echo("Start Postgres first:")
        click.echo("  docker compose up -d postgres")
        click.echo("")
        click.echo("Then initialize tables:")
        click.echo("  PYTHONPATH=. python -c \"from src.database.db import db_manager; db_manager.init_db(); print('Database initialized')\"")
        raise SystemExit(1) from exc


@click.group()
def cli():
    """Threat Intelligence Tracker CLI."""
    pass


# Feed Ingestion Commands
@click.group()
def feeds():
    """Manage threat intelligence feeds."""
    pass


@feeds.command()
def ingest_all():
    """Ingest from all threat intelligence feeds."""
    db = ensure_database_ready()
    try:
        click.echo("Starting feed ingestion...")
        orchestrator = FeedOrchestrator(db)
        result = orchestrator.ingest_all()
        
        click.echo(f"\n✓ Ingestion complete!")
        click.echo(f"  Total records ingested: {result['total_ingested']}")
        click.echo(f"  Total records updated: {result['total_updated']}")
        click.echo(f"  Errors: {result['total_errors']}")
        
        click.echo("\nFeed details:")
        for feed_name, status in result['feeds'].items():
            click.echo(f"  {feed_name}: {status.get('status', 'unknown')}")
    finally:
        db.close()


@feeds.command()
@click.argument('feed_name')
def ingest(feed_name):
    """Ingest from a specific feed."""
    db = ensure_database_ready()
    try:
        click.echo(f"Ingesting from {feed_name}...")
        orchestrator = FeedOrchestrator(db)
        result = orchestrator.ingest_specific(feed_name)
        
        if result.get('status') == 'success':
            click.echo(f"✓ Ingestion successful!")
            click.echo(f"  Records ingested: {result.get('records_ingested', 0)}")
            click.echo(f"  Records updated: {result.get('records_updated', 0)}")
        else:
            reason = result.get('error') or result.get('message') or 'Unknown error'
            click.echo(f"✗ Ingestion failed: {reason}")
    finally:
        db.close()


@feeds.command()
def sync_c2():
    """Backfill C2 infrastructure from existing ThreatFox indicators."""
    db = ensure_database_ready()
    try:
        from src.feeds.c2_sync import sync_c2_from_existing_indicators

        click.echo("Syncing C2 infrastructure from stored indicators...")
        result = sync_c2_from_existing_indicators(db)
        click.echo(
            f"✓ Sync complete: {result['synced']} records updated "
            f"from {result['candidates']} indicator candidates"
        )
    finally:
        db.close()


# C2 Infrastructure Commands
@click.group()
def c2():
    """Search and track C2 infrastructure."""
    pass


@c2.command()
@click.option('--limit', default=20, help='Number of results to show')
def list(limit):
    """List active C2 infrastructure."""
    db = db_manager.get_session()
    try:
        results = db.query(C2Infrastructure).filter_by(
            is_active=True
        ).order_by(
            desc(C2Infrastructure.confidence_score)
        ).limit(limit).all()
        
        if not results:
            click.echo("No active C2 infrastructure found.")
            return
        
        headers = ['IP', 'Port', 'Country', 'ISP', 'Confidence', 'Last Seen', 'Source']
        rows = [
            [
                r.ip_address,
                r.port or '-',
                r.country or '-',
                r.isp[:30] + '...' if r.isp and len(r.isp) > 30 else r.isp or '-',
                f"{r.confidence_score:.1f}%",
                r.last_seen.strftime('%Y-%m-%d %H:%M'),
                r.source or '-'
            ]
            for r in results
        ]
        
        click.echo("\nActive C2 Infrastructure:")
        click.echo(tabulate(rows, headers=headers, tablefmt="grid"))
    finally:
        db.close()


@c2.command()
@click.argument('ip')
def lookup(ip):
    """Get detailed C2 infrastructure information."""
    db = db_manager.get_session()
    try:
        c2 = db.query(C2Infrastructure).filter_by(ip_address=ip).first()
        
        if not c2:
            click.echo(f"C2 infrastructure for {ip} not found in database.")
            return
        
        click.echo(f"\n📊 C2 Infrastructure Details: {ip}")
        click.echo(f"{'─' * 50}")
        click.echo(f"Port: {c2.port or 'N/A'}")
        click.echo(f"Protocol: {c2.protocol or 'N/A'}")
        click.echo(f"Country: {c2.country or 'N/A'}")
        click.echo(f"ISP: {c2.isp or 'N/A'}")
        click.echo(f"ASN: {c2.asn or 'N/A'}")
        click.echo(f"Confidence Score: {c2.confidence_score:.1f}%")
        click.echo(f"Active: {'Yes' if c2.is_active else 'No'}")
        click.echo(f"First Seen: {c2.first_seen}")
        click.echo(f"Last Seen: {c2.last_seen}")
        click.echo(f"Source: {c2.source or 'N/A'}")
        click.echo(f"Tags: {json.dumps(c2.tags, indent=2) if c2.tags else 'None'}")
    finally:
        db.close()


# Threat Indicators Commands
@click.group()
def indicators():
    """Query threat indicators."""
    pass


@indicators.command()
@click.option('--type', 'indicator_type', help='Filter by indicator type (ip, domain, url, hash)')
@click.option('--severity', help='Filter by severity (critical, high, medium, low)')
@click.option('--limit', default=20, help='Number of results')
def search(indicator_type, severity, limit):
    """Search threat indicators."""
    db = db_manager.get_session()
    try:
        query = db.query(ThreatIndicator)
        
        if indicator_type:
            query = query.filter(ThreatIndicator.indicator_type == indicator_type)
        
        if severity:
            query = query.filter(ThreatIndicator.severity == severity)
        
        results = query.order_by(
            desc(ThreatIndicator.confidence_score)
        ).limit(limit).all()
        
        if not results:
            click.echo("No indicators found matching criteria.")
            return
        
        headers = ['Indicator', 'Type', 'Threat', 'Severity', 'Confidence', 'Last Seen']
        rows = [
            [
                r.indicator[:50] + '...' if len(r.indicator) > 50 else r.indicator,
                r.indicator_type,
                r.threat_type,
                r.severity or '-',
                f"{r.confidence_score:.1f}%",
                r.last_seen.strftime('%Y-%m-%d')
            ]
            for r in results
        ]
        
        click.echo("\nThreat Indicators:")
        click.echo(tabulate(rows, headers=headers, tablefmt="grid"))
    finally:
        db.close()


# URLhaus Commands
@click.group()
def urlhaus():
    """Query malware distribution URLs."""
    pass


@urlhaus.command()
@click.option('--limit', default=20, help='Number of results')
@click.option('--status', default='online', help='URL status filter')
def list(limit, status):
    """List malware distribution URLs."""
    db = db_manager.get_session()
    try:
        query = db.query(URLhaus)
        if status:
            query = query.filter(URLhaus.url_status == status)
        
        results = query.order_by(desc(URLhaus.first_seen)).limit(limit).all()
        
        if not results:
            click.echo("No URLs found.")
            return
        
        headers = ['URL', 'Status', 'Host', 'Malware Family', 'First Seen']
        rows = [
            [
                r.url[:60] + '...' if len(r.url) > 60 else r.url,
                r.url_status,
                r.host[:30] + '...' if len(r.host) > 30 else r.host,
                r.malware_family or '-',
                r.first_seen.strftime('%Y-%m-%d')
            ]
            for r in results
        ]
        
        click.echo("\nMalware Distribution URLs:")
        click.echo(tabulate(rows, headers=headers, tablefmt="grid"))
    finally:
        db.close()


# Statistics Commands
@click.group()
def stats():
    """View threat intelligence statistics."""
    pass


@stats.command()
def overview():
    """Get overview statistics."""
    db = db_manager.get_session()
    try:
        c2_total = db.query(C2Infrastructure).count()
        c2_active = db.query(C2Infrastructure).filter_by(is_active=True).count()
        indicators = db.query(ThreatIndicator).count()
        urls = db.query(URLhaus).count()
        
        click.echo("\n📈 Threat Intelligence Overview")
        click.echo(f"{'─' * 40}")
        click.echo(f"C2 Infrastructure (Total): {c2_total}")
        click.echo(f"C2 Infrastructure (Active): {c2_active}")
        click.echo(f"Threat Indicators: {indicators}")
        click.echo(f"Malware URLs: {urls}")
    finally:
        db.close()


@click.group()
def enrich():
    """Enrich IPs with external intelligence sources."""
    pass


@enrich.command("ip")
@click.argument("target")
@click.option("--censys", is_flag=True, help="Also query Censys (optional)")
def enrich_ip_cmd(target, censys):
    """Enrich a single IP via Shodan host lookup."""
    db = ensure_database_ready()
    try:
        from src.services.ip_enrichment import enrich_ip

        click.echo(f"Enriching {target}...")
        result = enrich_ip(db, target, use_shodan=True, use_censys=censys)
        click.echo(f"✓ Sources used: {', '.join(result.get('sources', []))}")
        if result.get("shodan"):
            shodan = result["shodan"]
            click.echo(f"  Country: {shodan.get('country')}")
            click.echo(f"  ISP: {shodan.get('isp')}")
            click.echo(f"  Ports: {shodan.get('ports')}")
        for err in result.get("errors", []):
            click.echo(f"  Warning: {err}")
    except Exception as exc:
        click.echo(f"✗ Enrichment failed: {exc}")
        raise SystemExit(1) from exc
    finally:
        db.close()


# Register command groups
cli.add_command(feeds)
cli.add_command(enrich)
cli.add_command(c2)
cli.add_command(indicators)
cli.add_command(urlhaus)
cli.add_command(stats)


if __name__ == '__main__':
    cli()
