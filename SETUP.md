# Setup Guide

## 🔧 Installation Steps

### 1. Prerequisites

- Python 3.9 or higher
- PostgreSQL 12+
- pip package manager
- Virtual environment support

### 2. Clone Repository

```bash
git clone <repository-url>
cd threat-intel-tracker
```

### 3. Create Virtual Environment

```bash
# Linux/Mac
python3 -m venv venv
source venv/bin/activate

# Windows
python -m venv venv
venv\Scripts\activate
```

### 4. Install Dependencies

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

### 5. Configure Environment

```bash
# Copy example configuration
cp .env.example .env

# Edit .env file with your settings
nano .env
```

### 6. Database Setup

#### Option A: Bundled PostgreSQL via Docker Compose

```bash
# Start the project database
docker compose up -d postgres

# Use the default local DSN from .env.example
DATABASE_URL=postgresql://threat_intel_user:threat_intel_password@localhost:5432/threat_intel_db
```

#### Option B: Existing PostgreSQL Instance

```bash
# Create database
createdb threat_intel_db

# Create user
createuser threat_intel_user

# Set password (connect to psql and run):
ALTER USER threat_intel_user WITH PASSWORD 'your_secure_password';

# Grant privileges:
GRANT ALL PRIVILEGES ON DATABASE threat_intel_db TO threat_intel_user;

# Update .env
DATABASE_URL=postgresql://threat_intel_user:your_secure_password@localhost:5432/threat_intel_db
```

#### Option C: SQLite (Temporary Local Experiments Only)

```bash
# This is useful for isolated experiments, but Postgres is the supported setup
# for schema alignment, ingestion behavior, and downstream store integration.
DATABASE_URL=sqlite:///./threat_intel.db
```

### 7. Initialize Database

```bash
python -c "
from src.database.db import db_manager
db_manager.init_db()
print('✓ Database initialized successfully')
"
```

### 8. Get API Keys (Optional)

Register and get API keys from:

- **Shodan**: https://account.shodan.io/
- **Censys**: https://censys.io/register
- **Binary Edge**: https://www.binaryedge.io/
- **Zoomeye**: https://www.zoomeye.org/

Update `.env` with your keys:

```env
SHODAN_API_KEY=your_shodan_key
CENSYS_PAT=your_censys_personal_access_token_here
BINARY_EDGE_API_KEY=your_key
ZOOMEYE_API_KEY=your_key
```

## 🚀 Running the Application

### Start API Server

```bash
python main.py api
```

The API will be available at:
- **Swagger UI**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc
- **API Base**: http://localhost:8000/api/v1

### Start Dashboard

In a new terminal:

```bash
python main.py dashboard
```

Dashboard will be at: http://localhost:8501

### Start CLI

```bash
python main.py cli --help
```

## 🔄 Initial Data Ingestion

Ingest data from open-source feeds:

```bash
# Via CLI
python main.py cli feeds ingest-all

# Via API
curl -X POST http://localhost:8000/api/v1/feeds/ingest/all

# Via Python
from src.database.db import db_manager
from src.feeds.orchestrator import FeedOrchestrator

db = db_manager.get_session()
orchestrator = FeedOrchestrator(db)
result = orchestrator.ingest_all()
print(result)
```

## 📋 Verification

### Check API Health

```bash
curl http://localhost:8000/api/v1/health
```

### Check Database Connection

```bash
python -c "
from src.database.db import db_manager
db = db_manager.get_session()
print(f'✓ Database connected successfully')
db.close()
"
```

### Test CLI

```bash
python main.py cli c2 list
python main.py cli stats overview
```

## ⚙️ Configuration Options

### Logging

```env
LOG_LEVEL=DEBUG|INFO|WARNING|ERROR|CRITICAL
```

### Real-time Processing

```env
ENABLE_REALTIME=true|false
UPDATE_INTERVAL_MINUTES=60
```

### API Settings

```env
API_HOST=0.0.0.0
API_PORT=8000
DASHBOARD_PORT=8501
```

## 🐛 Troubleshooting

### Database Connection Error

```bash
# Check PostgreSQL is running
sudo systemctl status postgresql

# Test connection
psql -U threat_intel_user -d threat_intel_db -h localhost
```

### Module Not Found Errors

```bash
# Ensure virtual environment is activated
source venv/bin/activate

# Reinstall dependencies
pip install -r requirements.txt --force-reinstall
```

### API Port Already in Use

```bash
# Change port in .env
API_PORT=8001

# Or kill process using port 8000
lsof -ti:8000 | xargs kill -9
```

### Feed Ingestion Fails

```bash
# Check internet connection
ping api.abuse.ch

# Enable debug logging
LOG_LEVEL=DEBUG python main.py api
```

## 🔒 Security Setup

### For Production

1. **Use strong database passwords**

```bash
# Generate secure password
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

2. **Enable HTTPS**

```bash
# Generate SSL certificates
openssl req -x509 -newkey rsa:4096 -nodes -out cert.pem -keyout key.pem -days 365
```

3. **Set environment-specific configs**

```bash
# Create .env.production
cp .env .env.production
# Edit with production values
```

4. **Run with gunicorn for production**

```bash
gunicorn -w 4 -b 0.0.0.0:8000 src.api.main:app
```

## 📦 Docker Setup (Optional)

```dockerfile
FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .

ENV DATABASE_URL=postgresql://user:pass@db:5432/threat_intel
ENV LOG_LEVEL=INFO

EXPOSE 8000

CMD ["python", "main.py", "api"]
```

Build and run:

```bash
docker build -t threat-intel-tracker .
docker run -p 8000:8000 --env-file .env threat-intel-tracker
```

## ✅ Testing Installation

Run complete verification:

```bash
#!/bin/bash

echo "Testing Threat Intelligence Tracker Installation..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Test Python version
python --version

# Test virtual environment
which python

# Test imports
python -c "from src.database.db import db_manager; print('✓ Database module OK')"
python -c "from src.api.main import app; print('✓ API module OK')"
python -c "from src.cli.cli import cli; print('✓ CLI module OK')"

# Test database connection
python -c "from src.database.db import db_manager; db = db_manager.get_session(); print('✓ Database connection OK'); db.close()"

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "✓ All checks passed! Installation ready."
```

## 📚 Next Steps

1. **Read the README.md** for feature overview
2. **Check API_DOCUMENTATION.md** for endpoint details
3. **See USAGE_EXAMPLES.md** for practical examples
4. **Review ARCHITECTURE.md** for technical details

## 🆘 Support

- Check logs: `tail -f logs/threat_intel.log`
- Review documentation in `/docs` directory
- Check GitHub issues for known problems
