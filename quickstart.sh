#!/bin/bash
# Quick start script for Threat Intelligence Tracker

set -e

echo "🛡️  Threat Intelligence Tracker - Quick Start"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Check Python version
python_version=$(python3 --version 2>&1)
echo "✓ Python found: $python_version"

# Prefer python3.12 if available (avoids Python 3.13 incompatibilities)
if command -v python3.12 >/dev/null 2>&1; then
    PYTHON_CMD=python3.12
else
    PYTHON_CMD=python3
fi

# Create virtual environment if not exists
# Create virtual environment with chosen interpreter
if [ ! -d "venv" ]; then
    echo "📦 Creating virtual environment..."
    $PYTHON_CMD -m venv venv
fi

# Activate virtual environment
echo "✓ Activating virtual environment..."
source venv/bin/activate

# Install/upgrade dependencies
echo "📥 Installing dependencies..."
pip install -q --upgrade pip
pip install -q -r requirements.txt

# Create .env if not exists
if [ ! -f ".env" ]; then
    echo "⚙️  Creating .env file..."
    cp .env.example .env
    echo "   ⚠️  Please edit .env with your API keys"
fi

# Initialize database (use virtualenv Python).
# Load .env if present so users can set `DATABASE_URL` to their Postgres DSN.
if [ -f ".env" ]; then
    set -a
    . .env
    set +a
fi
DB_URL="${DATABASE_URL:-postgresql://threat_intel_user:threat_intel_password@localhost:5432/threat_intel_db}"

if [ "$DB_URL" = "postgresql://user:password@localhost:5432/threat_intel_db" ]; then
    echo "❌ DATABASE_URL is still using the placeholder PostgreSQL credentials."
    echo "   Update .env with a real Postgres DSN, or use the bundled local database:"
    echo "   docker compose up -d postgres"
    echo "   DATABASE_URL=postgresql://threat_intel_user:threat_intel_password@localhost:5432/threat_intel_db"
    exit 1
fi

echo "🗄️  Initializing database using $DB_URL"
if ! DATABASE_URL="$DB_URL" python - <<'PY'
import sys
from sqlalchemy.exc import OperationalError

try:
    from src.database.db import db_manager

    db_manager.init_db()
except OperationalError as exc:
    detail = str(exc.orig).strip() or "server is not reachable or refused the connection"
    print(f"   PostgreSQL connection failed: {detail}")
    sys.exit(1)

print("   ✓ Database initialized")
PY
then
    echo ""
    echo "❌ Could not initialize PostgreSQL."
    echo "   Check that Postgres is running and that DATABASE_URL credentials match."
    echo "   For the bundled local database, run:"
    echo "   docker compose up -d postgres"
    exit 1
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "✓ Setup complete!"
echo ""
echo "Next steps:"
echo "  1. Edit .env with your API keys (optional)"
echo "  2. Start API server: python main.py api"
echo "  3. Start dashboard: python main.py dashboard"
echo "  4. Run CLI: python main.py cli --help"
echo ""
echo "Documentation:"
echo "  - README.md: Overview and features"
echo "  - SETUP.md: Detailed setup instructions"
echo "  - API_DOCUMENTATION.md: API endpoints"
echo "  - USAGE_EXAMPLES.md: Code examples"
echo "  - ARCHITECTURE.md: Technical design"
echo ""
