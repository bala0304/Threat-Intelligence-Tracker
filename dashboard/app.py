"""Streamlit dashboard for threat intelligence visualization."""
import sys
from pathlib import Path

import streamlit as st
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
from datetime import datetime, timedelta
import requests
import json
from sqlalchemy import create_engine
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import sessionmaker

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.config import get_settings
from src.database.models import (
    C2Infrastructure, ThreatIndicator, URLhaus,
    PassiveDNSRecord, DomainIntelligence
)
from src.feeds.c2_sync import sync_c2_from_existing_indicators
from src.search.local_search import search_local_intelligence
from src.search.shodan_query import parse_shodan_query
from src.services.ip_enrichment import enrich_ip, normalize_ip, search_shodan_live

st.set_page_config(
    page_title="Threat Intelligence Tracker",
    page_icon="🛡️",
    layout="wide"
)

# ---------------------------------------------------------------------------
# Visual system (UI-only). Dark, minimal dashboard styling — Vercel/Linear
# flavour. No behaviour here: only CSS applied to Streamlit's DOM.
# ---------------------------------------------------------------------------
st.markdown(
    """
    <style>
      :root {
        --bg: #0A0A0A;
        --surface: #141414;
        --surface-raised: #1C1C1C;
        --border: #242424;
        --border-strong: #333333;
        --text: #EDEDED;
        --text-muted: #8A8A8A;
        --accent: #3B82F6;
        --accent-hover: #60A5FA;
        --radius-sm: 6px;
        --radius-md: 8px;
        --radius-lg: 12px;
        --ease: 180ms ease;
      }

      html, body, [class*="css"], .stApp {
        font-family: "Inter", -apple-system, BlinkMacSystemFont, "Segoe UI",
          Roboto, Helvetica, Arial, sans-serif;
        color: var(--text);
      }
      .stApp { background: var(--bg); }

      /* Tighten Streamlit's oversized default padding to an 8px scale */
      .block-container {
        padding-top: 2.5rem;
        padding-bottom: 3rem;
        max-width: 1400px;
      }

      /* --- Typography ------------------------------------------------------ */
      h1, .stMarkdown h1 {
        font-size: 1.75rem;
        font-weight: 600;
        letter-spacing: -0.02em;
        line-height: 1.2;
        margin-bottom: 0.25rem;
      }
      h2, .stMarkdown h2 {
        font-size: 1.25rem;
        font-weight: 600;
        letter-spacing: -0.01em;
        margin-top: 0.5rem;
      }
      h3, .stMarkdown h3 {
        font-size: 1rem;
        font-weight: 600;
        letter-spacing: 0.01em;
      }
      .stMarkdown p, .stMarkdown li { font-size: 0.875rem; line-height: 1.6; }
      .stCaption, [data-testid="stCaptionContainer"] {
        color: var(--text-muted) !important;
        font-size: 0.8rem;
      }

      /* --- Hairline dividers -------------------------------------------- */
      hr, [data-testid="stDivider"] {
        border-color: var(--border) !important;
        margin: 1.5rem 0 !important;
      }

      /* --- Metric cards ---------------------------------------------------- */
      [data-testid="stMetric"] {
        background: var(--surface);
        border: 1px solid var(--border);
        border-radius: var(--radius-lg);
        padding: 16px 18px;
        transition: border-color var(--ease), background var(--ease);
      }
      [data-testid="stMetric"]:hover { border-color: var(--border-strong); }
      [data-testid="stMetricLabel"] {
        color: var(--text-muted);
        font-size: 0.8rem;
        font-weight: 500;
        letter-spacing: 0.01em;
      }
      [data-testid="stMetricValue"] {
        font-size: 1.5rem;
        font-weight: 600;
        letter-spacing: -0.01em;
      }

      /* --- Buttons ------------------------------------------------------ */
      .stButton > button {
        border-radius: var(--radius-md);
        border: 1px solid var(--border-strong);
        background: var(--surface-raised);
        color: var(--text);
        font-weight: 500;
        font-size: 0.875rem;
        padding: 0.45rem 0.9rem;
        transition: background var(--ease), border-color var(--ease),
          transform var(--ease);
      }
      .stButton > button:hover {
        border-color: var(--accent);
        background: #202020;
      }
      .stButton > button:active { transform: translateY(1px); }
      .stButton > button:focus-visible {
        outline: 2px solid rgba(59, 130, 246, 0.45);
        outline-offset: 1px;
      }
      .stButton > button[kind="primary"],
      .stButton > button[data-testid="baseButton-primary"] {
        background: var(--accent);
        border-color: var(--accent);
        color: #ffffff;
      }
      .stButton > button[kind="primary"]:hover,
      .stButton > button[data-testid="baseButton-primary"]:hover {
        background: var(--accent-hover);
        border-color: var(--accent-hover);
      }
      .stButton > button:disabled { opacity: 0.4; cursor: not-allowed; }

      /* --- Inputs / selects ---------------------------------------------- */
      .stTextInput input,
      .stNumberInput input,
      .stSelectbox [data-baseweb="select"] > div,
      .stMultiSelect [data-baseweb="select"] > div {
        background: var(--surface) !important;
        border-radius: var(--radius-md) !important;
        border: 1px solid var(--border) !important;
        color: var(--text) !important;
        transition: border-color var(--ease), box-shadow var(--ease);
      }
      .stTextInput input:focus,
      .stNumberInput input:focus,
      .stSelectbox [data-baseweb="select"] > div:focus-within,
      .stMultiSelect [data-baseweb="select"] > div:focus-within {
        border-color: var(--accent) !important;
        box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.15) !important;
      }
      .stTextInput input::placeholder { color: #5c5c5c; }
      .stSlider [data-baseweb="slider"] [role="slider"] { background: var(--accent); }

      /* --- Tabs -------------------------------------------------------- */
      .stTabs [data-baseweb="tab-list"] {
        gap: 0.25rem;
        border-bottom: 1px solid var(--border);
      }
      .stTabs [data-baseweb="tab"] {
        color: var(--text-muted);
        font-size: 0.875rem;
        font-weight: 500;
        padding: 0.5rem 0.75rem;
        transition: color var(--ease);
      }
      .stTabs [data-baseweb="tab"]:hover { color: var(--text); }
      .stTabs [aria-selected="true"] { color: var(--text) !important; }
      .stTabs [data-baseweb="tab-highlight"] { background: var(--accent); }

      /* --- Dataframe ------------------------------------------------------ */
      [data-testid="stDataFrame"], [data-testid="stTable"] {
        border: 1px solid var(--border);
        border-radius: var(--radius-lg);
        overflow: hidden;
      }

      /* --- Expander ----------------------------------------------------- */
      [data-testid="stExpander"] {
        border: 1px solid var(--border);
        border-radius: var(--radius-md);
        background: var(--surface);
      }

      /* --- Callouts (info / warn / error / success) --------------------- */
      [data-testid="stNotification"], .stAlert {
        border-radius: var(--radius-md);
        border: 1px solid var(--border);
        border-left-width: 3px;
      }

      /* --- Search hero panel: the first bordered container ------------- */
      [data-testid="stVerticalBlockBorderWrapper"] {
        border-radius: var(--radius-lg) !important;
        border-color: var(--border) !important;
        background: var(--surface);
      }

      /* --- App header block ------------------------------------------- */
      .tit-header { margin-bottom: 0.25rem; }
      .tit-subtitle {
        color: var(--text-muted);
        font-size: 0.9rem;
        margin: 0 0 0.5rem;
      }
      .tit-footer {
        text-align: right;
        color: var(--text-muted);
        font-size: 0.78rem;
      }

      /* --- Responsive ------------------------------------------------- */
      @media (max-width: 640px) {
        .block-container { padding-top: 1.5rem; padding-left: 0.75rem;
          padding-right: 0.75rem; }
        h1, .stMarkdown h1 { font-size: 1.4rem; }
        [data-testid="stMetric"] { padding: 12px 14px; }
        [data-testid="stMetricValue"] { font-size: 1.25rem; }
      }
    </style>
    """,
    unsafe_allow_html=True,
)


# Shared Plotly styling so every chart reads as one system.
PLOTLY_TEMPLATE = "plotly_dark"
CATEGORICAL_COLORS = [
    "#3B82F6", "#8B5CF6", "#06B6D4", "#F59E0B",
    "#EC4899", "#10B981", "#64748B", "#F43F5E",
]
SEVERITY_COLORS = {
    "critical": "#F43F5E",
    "high": "#FB923C",
    "medium": "#FACC15",
    "low": "#4ADE80",
    "unknown": "#64748B",
}


def style_fig(fig):
    """Apply the dark visual system to a Plotly figure (presentation only)."""
    if fig is None:
        return None
    fig.update_layout(
        template=PLOTLY_TEMPLATE,
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(
            family='Inter, -apple-system, "Segoe UI", Roboto, sans-serif',
            size=12,
            color="#8A8A8A",
        ),
        title=dict(font=dict(size=14, color="#EDEDED"), x=0, xanchor="left"),
        margin=dict(l=8, r=8, t=44, b=8),
        legend=dict(
            font=dict(size=11, color="#8A8A8A"),
            bgcolor="rgba(0,0,0,0)",
        ),
        colorway=CATEGORICAL_COLORS,
    )
    fig.update_xaxes(
        gridcolor="#1F1F1F", zerolinecolor="#242424",
        linecolor="#242424", tickfont=dict(color="#8A8A8A"),
    )
    fig.update_yaxes(
        gridcolor="#1F1F1F", zerolinecolor="#242424",
        linecolor="#242424", tickfont=dict(color="#8A8A8A"),
    )
    return fig

# Initialize database connection
settings = get_settings()
engine = create_engine(settings.database_url)
SessionLocal = sessionmaker(bind=engine)


def get_db():
    """Get database session."""
    return SessionLocal()


def make_container(border=None):
    """Create a container compatible with older and newer Streamlit versions."""
    try:
        return st.container(border=border)
    except TypeError as exc:
        if border is not None and "unexpected keyword argument 'border'" in str(exc):
            return st.container()
        raise


def query_c2_infrastructure():
    """Query C2 infrastructure data."""
    db = get_db()
    try:
        results = db.query(C2Infrastructure).order_by(
            C2Infrastructure.last_seen.desc()
        ).limit(1000).all()

        return pd.DataFrame([
            {
                'IP': r.ip_address,
                'Country': r.country or 'Unknown',
                'Port': r.port or '-',
                'ISP': r.isp or 'Unknown',
                'Confidence': r.confidence_score,
                'Active': r.is_active,
                'Last Seen': r.last_seen,
                'Source': r.source or 'Unknown'
            }
            for r in results
        ])
    except (SQLAlchemyError, Exception):
        return pd.DataFrame(columns=['IP', 'Country', 'Port', 'ISP', 'Confidence', 'Active', 'Last Seen', 'Source'])
    finally:
        db.close()


def query_threat_indicators():
    """Query threat indicators."""
    db = get_db()
    try:
        results = db.query(ThreatIndicator).order_by(
            ThreatIndicator.last_seen.desc()
        ).limit(1000).all()

        return pd.DataFrame([
            {
                'Indicator': r.indicator,
                'Type': r.indicator_type,
                'Threat': r.threat_type,
                'Severity': r.severity or 'Unknown',
                'Confidence': r.confidence_score,
                'Last Seen': r.last_seen,
            }
            for r in results
        ])
    except (SQLAlchemyError, Exception):
        return pd.DataFrame(columns=['Indicator', 'Type', 'Threat', 'Severity', 'Confidence', 'Last Seen'])
    finally:
        db.close()


def query_malware_urls():
    """Query malware distribution URLs."""
    db = get_db()
    try:
        results = db.query(URLhaus).order_by(
            URLhaus.first_seen.desc()
        ).limit(1000).all()

        return pd.DataFrame([
            {
                'URL': r.url,
                'Host': r.host,
                'Status': r.url_status,
                'Malware': r.malware_family or 'Unknown',
                'First Seen': r.first_seen,
            }
            for r in results
        ])
    except (SQLAlchemyError, Exception):
        return pd.DataFrame(columns=['URL', 'Host', 'Status', 'Malware', 'First Seen'])
    finally:
        db.close()


def get_statistics():
    """Get overview statistics."""
    db = get_db()
    try:
        c2_total = db.query(C2Infrastructure).count()
        c2_active = db.query(C2Infrastructure).filter_by(is_active=True).count()
        indicators = db.query(ThreatIndicator).count()
        urls = db.query(URLhaus).count()
        domains = db.query(DomainIntelligence).filter_by(is_malicious=True).count()
        pdns = db.query(PassiveDNSRecord).count()

        return {
            'c2_total': c2_total,
            'c2_active': c2_active,
            'indicators': indicators,
            'urls': urls,
            'domains': domains,
            'pdns': pdns,
        }
    except (SQLAlchemyError, Exception):
        return {
            'c2_total': 0,
            'c2_active': 0,
            'indicators': 0,
            'urls': 0,
            'domains': 0,
            'pdns': 0,
        }


def plot_c2_by_country(df):
    """Plot C2 infrastructure by country."""
    if df.empty:
        return None

    country_counts = df.groupby('Country').size().reset_index(name='Count')
    fig = px.bar(
        country_counts,
        x='Country',
        y='Count',
        title='C2 Infrastructure by Country',
        color='Count',
        color_continuous_scale=['#1E293B', '#3B82F6']
    )
    return style_fig(fig)


def plot_threats_by_severity(df):
    """Plot threats by severity."""
    if df.empty:
        return None
    
    severity_counts = df.groupby('Severity').size().reset_index(name='Count')
    severity_order = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'unknown': 0}
    severity_counts['order'] = severity_counts['Severity'].map(
        lambda x: severity_order.get(x.lower(), -1)
    )
    severity_counts = severity_counts.sort_values('order', ascending=False)
    
    fig = px.bar(
        severity_counts,
        x='Severity',
        y='Count',
        title='Threat Indicators by Severity',
        color='Severity',
        color_discrete_map=SEVERITY_COLORS
    )
    return style_fig(fig)


def plot_indicators_by_type(df):
    """Plot indicator distribution by type."""
    if df.empty:
        return None

    type_counts = df.groupby('Type').size().reset_index(name='Count')
    return style_fig(px.bar(
        type_counts,
        x='Type',
        y='Count',
        title='Threat Indicators by Type',
        color='Type',
    ))


def run_intelligence_search(query: str, limit: int, shodan_live: bool):
    """Execute local and optional live Shodan search."""
    db = get_db()
    try:
        local_results = search_local_intelligence(db, query, limit=limit)
    finally:
        db.close()

    shodan_results = []
    shodan_total = 0
    if shodan_live and query.strip():
        try:
            live = search_shodan_live(query, limit=min(limit, 10))
            shodan_results = live.get("matches", [])
            shodan_total = live.get("total", 0)
        except Exception as exc:
            st.error(f"Shodan live search failed: {exc}")

    parsed = parse_shodan_query(query)
    return local_results, shodan_results, shodan_total, parsed


def render_enrich_panel(default_ip: str = "", key_prefix: str = "enrich"):
    """Render IP enrichment controls."""
    settings = get_settings()
    has_shodan = bool(settings.shodan_api_key)
    has_censys = bool(settings.resolved_censys_token)

    st.markdown("##### Enrich selected IP")
    if not has_shodan and not has_censys:
        st.caption("Add `SHODAN_API_KEY` to `.env` to enable enrichment (1 lookup per IP).")
        return

    col_ip, col_btn = st.columns([3, 1])
    with col_ip:
        ip_value = st.text_input(
            "IP address",
            value=default_ip,
            placeholder="1.2.3.4",
            key=f"{key_prefix}_ip_input",
            label_visibility="collapsed",
        )
    with col_btn:
        use_censys = st.checkbox("Also Censys", key=f"{key_prefix}_use_censys")
        enrich_clicked = st.button(
            "🔍 Enrich IP",
            key=f"{key_prefix}_btn",
            use_container_width=True,
        )

    if enrich_clicked:
        ip = normalize_ip(ip_value or "")
        if not ip:
            st.error("Enter a valid IPv4 address (or ip:port).")
            return

        with st.spinner(f"Enriching {ip} via Shodan..."):
            db = get_db()
            try:
                result = enrich_ip(
                    db,
                    ip,
                    use_shodan=has_shodan,
                    use_censys=use_censys and has_censys,
                )
            except Exception as exc:
                st.error(str(exc))
                return
            finally:
                db.close()

        st.success(f"Enriched {ip} using: {', '.join(result.get('sources', []))}")
        if result.get("shodan"):
            st.json(result["shodan"])
        if result.get("errors"):
            for err in result["errors"]:
                st.warning(err)


def render_search_results(local_results, shodan_results, shodan_total, parsed):
    """Display unified search results."""
    all_results = list(local_results) + list(shodan_results)

    if parsed.has_filters or parsed.has_free_text:
        filter_bits = [f"{k}:{v}" for k, v in parsed.filters.items()]
        summary = ", ".join(filter_bits) if filter_bits else "none"
        st.caption(
            f"Parsed filters: {summary} | "
            f"Free text: `{parsed.free_text or '(none)'}`"
        )

    if not all_results:
        st.warning(
            "No matches in local data. Try `port:`, `country:`, `ip:`, `org:`, "
            "or banner text like `\"HTTP/1.1 200 OK Server: nginx\"`. "
            "Enable **Shodan live** to query the internet (uses API credits)."
        )
        return

    st.subheader(
        f"{len(local_results)} local · "
        f"{len(shodan_results)} live"
        + (f" · {shodan_total:,} total on Shodan" if shodan_total else "")
    )

    display_df = pd.DataFrame(all_results)
    show_cols = [
        c for c in [
            "Entity", "Value", "Type", "Country", "Port",
            "Severity", "Confidence", "Source", "Details", "Last Seen",
        ]
        if c in display_df.columns
    ]
    st.dataframe(display_df[show_cols], use_container_width=True)

    enrichable_ips = sorted(
        {
            normalize_ip(row.get("IP") or row.get("Value", ""))
            for row in all_results
            if row.get("Enrichable") and normalize_ip(row.get("IP") or row.get("Value", ""))
        }
    )
    if enrichable_ips:
        selected = st.selectbox(
            "Enrich result IP",
            enrichable_ips,
            key="search_enrich_select",
        )
        render_enrich_panel(default_ip=selected, key_prefix="search")


# Main App
st.markdown(
    """
    <div class="tit-header">
      <h1>🛡️ Threat Intelligence Tracker</h1>
      <p class="tit-subtitle">Live adversary infrastructure monitoring — C2 tracking, pDNS, and threat feed ingestion</p>
    </div>
    """,
    unsafe_allow_html=True,
)

# Shodan-style global search bar
with make_container(border=True):
    st.markdown("**Intelligence Search** — Shodan-style syntax")
    search_col, btn_col, live_col = st.columns([5, 1, 1.2])
    with search_col:
        global_query = st.text_input(
            "Search",
            value=st.session_state.get("last_search_query", ""),
            placeholder=(
                'port:443 country:US org:"Digital Ocean" product:nginx '
                '"HTTP/1.1 200 OK Server: nginx/1.1.19"'
            ),
            label_visibility="collapsed",
            key="global_search_query",
        )
    with btn_col:
        search_clicked = st.button("Search", type="primary", use_container_width=True)
    with live_col:
        shodan_live = st.checkbox(
            "Shodan live",
            help="Query Shodan API (uses query credits). Default searches local DB only.",
        )

    with st.expander("Query syntax help", expanded=False):
        st.markdown(
            """
            **Filters:** `port:443` · `country:US` · `ip:1.2.3.4` · `net:192.168.0.0/24` ·
            `org:"Choopa"` · `isp:Amazon` · `asn:AS16509` · `hostname:evil.com` ·
            `product:nginx` · `malware:cobalt_strike` · `severity:critical` · `type:ip:port`

            **Banner / free text:** paste raw strings like
            `"HTTP/1.1 200 OK Server: nginx/1.1.19"` — matches enriched scan banners locally.

            **Combine:** `port:8443 country:DE cobalt strike`
            """
        )

    if search_clicked and global_query.strip():
        st.session_state["last_search_query"] = global_query.strip()
        local, live, live_total, parsed = run_intelligence_search(
            global_query.strip(),
            limit=100,
            shodan_live=shodan_live,
        )
        st.session_state["search_local"] = local
        st.session_state["search_live"] = live
        st.session_state["search_live_total"] = live_total
        st.session_state["search_parsed"] = parsed

    if st.session_state.get("last_search_query"):
        render_search_results(
            st.session_state.get("search_local", []),
            st.session_state.get("search_live", []),
            st.session_state.get("search_live_total", 0),
            st.session_state.get("search_parsed", parse_shodan_query("")),
        )

st.divider()

# Navigation
tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs([
    "📊 Overview",
    "🎯 C2 Infrastructure",
    "⚠️ Threat Indicators",
    "🔗 Malware URLs",
    "🔍 Domain Intel",
    "⚙️ Feed Management"
])

# Tab 1: Overview
with tab1:
    st.header("Threat Intelligence Overview")
    
    stats = get_statistics()
    
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("C2 Infrastructure (Active)", stats['c2_active'], stats['c2_total'])
    with col2:
        st.metric("Threat Indicators", stats['indicators'])
    with col3:
        st.metric("Malware URLs", stats['urls'])
    with col4:
        st.metric("Malicious Domains", stats['domains'])
    
    st.divider()

    df_indicators = query_threat_indicators()
    df_c2 = query_c2_infrastructure()

    if not df_indicators.empty:
        st.subheader("Intelligence Visualizations")
        col_chart1, col_chart2 = st.columns(2)
        with col_chart1:
            fig = plot_threats_by_severity(df_indicators)
            if fig:
                st.plotly_chart(fig, use_container_width=True, key="overview_severity")
        with col_chart2:
            fig = plot_indicators_by_type(df_indicators)
            if fig:
                st.plotly_chart(fig, use_container_width=True, key="overview_type")

    st.divider()

    # Recent Activity
    col_left, col_right = st.columns(2)
    
    with col_left:
        st.subheader("Recent C2 Infrastructure")
        if not df_c2.empty:
            st.dataframe(
                df_c2.head(10)[['IP', 'Country', 'Port', 'Confidence', 'Last Seen']],
                use_container_width=True
            )
        else:
            st.caption("No C2 rows yet. Run `feeds sync-c2` or re-ingest ThreatFox.")
    
    with col_right:
        st.subheader("Recent Threat Indicators")
        if not df_indicators.empty:
            st.dataframe(
                df_indicators.head(10)[['Indicator', 'Type', 'Severity', 'Confidence']],
                use_container_width=True
            )


# Tab 2: C2 Infrastructure
with tab2:
    st.header("C2 Infrastructure Tracking")
    
    df_c2 = query_c2_infrastructure()
    
    if not df_c2.empty:
        # Filter options
        col1, col2, col3 = st.columns(3)
        with col1:
            countries = ['All'] + sorted(df_c2[df_c2['Country'] != 'Unknown']['Country'].unique().tolist())
            selected_country = st.selectbox("Filter by Country", countries)
        
        with col2:
            active_filter = st.checkbox("Active Only", value=True)
        
        with col3:
            min_confidence = st.slider("Minimum Confidence", 0.0, 100.0, 0.0)
        
        # Apply filters
        filtered_df = df_c2.copy()
        if selected_country != 'All':
            filtered_df = filtered_df[filtered_df['Country'] == selected_country]
        if active_filter:
            filtered_df = filtered_df[filtered_df['Active'] == True]
        if min_confidence > 0:
            filtered_df = filtered_df[filtered_df['Confidence'] >= min_confidence]
        
        # Display data
        st.subheader(f"Found {len(filtered_df)} C2 Infrastructure entries")
        st.dataframe(
            filtered_df[['IP', 'Country', 'Port', 'ISP', 'Confidence', 'Source']],
            use_container_width=True
        )
        
        # Charts
        col1, col2 = st.columns(2)
        with col1:
            fig = plot_c2_by_country(df_c2)
            if fig:
                st.plotly_chart(fig, use_container_width=True, key="c2_by_country")

        with col2:
            source_counts = df_c2.groupby('Source').size().reset_index(name='Count')
            fig = px.pie(source_counts, names='Source', values='Count', title='C2 Data Sources')
            st.plotly_chart(style_fig(fig), use_container_width=True, key="c2_sources")

        st.divider()
        enrich_ips = sorted(filtered_df['IP'].unique().tolist())
        render_enrich_panel(
            default_ip=enrich_ips[0] if enrich_ips else "",
            key_prefix="c2_tab",
        )
    else:
        st.info(
            "No C2 infrastructure rows yet. ThreatFox indicators are stored separately — "
            "click below to derive C2 records from existing indicator data."
        )
        if st.button("🔄 Sync C2 from ThreatFox indicators", key="sync_c2_overview"):
            db = get_db()
            try:
                result = sync_c2_from_existing_indicators(db)
                st.success(
                    f"Synced {result['synced']} C2/domain records "
                    f"from {result['candidates']} candidates."
                )
                st.rerun()
            finally:
                db.close()


# Tab 3: Threat Indicators
with tab3:
    st.header("Threat Indicators")
    
    df_indicators = query_threat_indicators()
    
    if not df_indicators.empty:
        col1, col2, col3 = st.columns(3)
        
        with col1:
            indicator_types = ['All'] + sorted(df_indicators['Type'].unique().tolist())
            selected_type = st.selectbox("Filter by Type", indicator_types)
        
        with col2:
            severities = ['All'] + sorted(df_indicators[df_indicators['Severity'] != 'Unknown']['Severity'].unique().tolist())
            selected_severity = st.selectbox("Filter by Severity", severities)
        
        with col3:
            min_conf = st.slider("Minimum Confidence %", 0.0, 100.0, 0.0, key="indicator_confidence")
        
        # Apply filters
        filtered_df = df_indicators.copy()
        if selected_type != 'All':
            filtered_df = filtered_df[filtered_df['Type'] == selected_type]
        if selected_severity != 'All':
            filtered_df = filtered_df[filtered_df['Severity'] == selected_severity]
        if min_conf > 0:
            filtered_df = filtered_df[filtered_df['Confidence'] >= min_conf]
        
        st.subheader(f"Found {len(filtered_df)} Threat Indicators")
        st.dataframe(
            filtered_df[['Indicator', 'Type', 'Threat', 'Severity', 'Confidence']],
            use_container_width=True
        )
        
        # Charts
        col1, col2 = st.columns(2)
        with col1:
            fig = plot_threats_by_severity(df_indicators)
            if fig:
                st.plotly_chart(fig, use_container_width=True, key="indicators_severity")

        with col2:
            type_counts = df_indicators.groupby('Type').size().reset_index(name='Count')
            fig = px.bar(type_counts, x='Type', y='Count', title='Indicators by Type')
            st.plotly_chart(style_fig(fig), use_container_width=True, key="indicators_type")
    else:
        st.info("No threat indicator data available.")


# Tab 4: Malware URLs
with tab4:
    st.header("Malware Distribution URLs")
    
    df_urls = query_malware_urls()
    
    if not df_urls.empty:
        col1, col2 = st.columns(2)
        
        with col1:
            statuses = ['All'] + sorted(df_urls['Status'].unique().tolist())
            selected_status = st.selectbox("Filter by Status", statuses)
        
        with col2:
            search_query = st.text_input("Search URLs", "")
        
        # Apply filters
        filtered_df = df_urls.copy()
        if selected_status != 'All':
            filtered_df = filtered_df[filtered_df['Status'] == selected_status]
        if search_query:
            filtered_df = filtered_df[
                filtered_df['URL'].str.contains(search_query, case=False, na=False)
            ]
        
        st.subheader(f"Found {len(filtered_df)} Malware URLs")
        st.dataframe(
            filtered_df[['URL', 'Host', 'Status', 'Malware', 'First Seen']],
            use_container_width=True
        )
        
        # Charts
        col1, col2 = st.columns(2)
        with col1:
            status_counts = df_urls.groupby('Status').size().reset_index(name='Count')
            fig = px.pie(status_counts, names='Status', values='Count', title='URL Status Distribution')
            st.plotly_chart(style_fig(fig), use_container_width=True, key="urls_status")

        with col2:
            malware_counts = df_urls['Malware'].value_counts().head(10).reset_index()
            malware_counts.columns = ['Malware', 'Count']
            fig = px.bar(malware_counts, x='Malware', y='Count', title='Top 10 Malware Families')
            st.plotly_chart(style_fig(fig), use_container_width=True, key="urls_malware")
    else:
        st.info("No malware URL data available.")


# Tab 5: Domain Intelligence
with tab5:
    st.header("Domain Intelligence")

    db = get_db()
    try:
        domains = db.query(DomainIntelligence).filter_by(
            is_malicious=True
        ).order_by(DomainIntelligence.last_updated.desc()).limit(500).all()
    except (SQLAlchemyError, Exception):
        domains = []
    finally:
        db.close()

    if domains:
        df_domains = pd.DataFrame([
            {
                'Domain': d.domain,
                'Confidence': d.confidence_score,
                'Registrar': d.registrar or 'Unknown',
                'Sources': ', '.join(d.sources or []),
                'Last Updated': d.last_updated,
            }
            for d in domains
        ])
        st.dataframe(df_domains, use_container_width=True)
    else:
        st.info(
            "No malicious domains yet. Domain IOCs from ThreatFox appear here after "
            "C2 sync or ThreatFox re-ingestion."
        )


# Tab 6: Feed Management
with tab6:
    st.header("Feed Management")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("Manual Feed Ingestion")
        
        if st.button("🔄 Ingest All Feeds", use_container_width=True):
            st.info("Triggering feed ingestion...")
            try:
                response = requests.post(
                    f"http://localhost:{settings.api_port}/api/v1/feeds/ingest/all"
                )
                if response.status_code == 200:
                    data = response.json()
                    st.success("✓ Ingestion completed!")
                    st.json(data)
                else:
                    st.error(f"Ingestion failed: {response.text}")
            except Exception as e:
                st.error(f"Error: {str(e)}")
        
        feeds = ['threatfox', 'urlhaus']
        selected_feed = st.selectbox("Select Feed", feeds)
        
        if st.button(f"📥 Ingest {selected_feed}", use_container_width=True):
            st.info(f"Ingesting {selected_feed}...")
            try:
                response = requests.post(
                    f"http://localhost:{settings.api_port}/api/v1/feeds/ingest/{selected_feed}"
                )
                if response.status_code == 200:
                    data = response.json()
                    st.success("✓ Ingestion completed!")
                    st.json(data)
                else:
                    st.error(f"Ingestion failed: {response.text}")
            except Exception as e:
                st.error(f"Error: {str(e)}")
    
    with col2:
        st.subheader("Available Feeds")
        try:
            response = requests.get(
                f"http://localhost:{settings.api_port}/api/v1/feeds/available"
            )
            if response.status_code == 200:
                feeds_data = response.json()
                for feed in feeds_data.get('feeds', []):
                    with st.expander(f"📊 {feed['name'].upper()}"):
                        st.write(f"**Description:** {feed['description']}")
                        st.write(f"**Type:** {feed['type']}")
                        st.write(f"**Frequency:** {feed['frequency']}")
        except Exception as e:
            st.error(f"Could not load feeds: {str(e)}")

st.divider()
st.markdown(
    f'<p class="tit-footer">Last updated {datetime.now().strftime("%Y-%m-%d %H:%M:%S")} UTC</p>',
    unsafe_allow_html=True,
)
