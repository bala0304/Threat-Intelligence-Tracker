"""Main entry point for the application."""
import sys
import uvicorn
from src.config import get_settings


def run_api():
    """Run the REST API server."""
    settings = get_settings()
    uvicorn.run(
        "src.api.main:app",
        host=settings.api_host,
        port=settings.api_port,
        reload=True
    )


def run_dashboard():
    """Run the Streamlit dashboard."""
    import subprocess
    import os
    from src.config import get_settings
    
    settings = get_settings()
    dashboard_path = os.path.join(os.path.dirname(__file__), 'dashboard', 'app.py')
    
    subprocess.run([
        'streamlit', 'run',
        dashboard_path,
        '--server.port', str(settings.dashboard_port),
        '--server.address', '0.0.0.0'
    ])


if __name__ == '__main__':
    if len(sys.argv) > 1:
        if sys.argv[1] == 'api':
            run_api()
        elif sys.argv[1] == 'dashboard':
            run_dashboard()
        elif sys.argv[1] == 'cli':
            from src.cli.cli import cli
            cli(args=sys.argv[2:])
        else:
            print("Usage: python main.py [api|dashboard|cli]")
    else:
        print("Threat Intelligence Tracker")
        print("Usage: python main.py [api|dashboard|cli]")
        print("  api       - Run REST API server")
        print("  dashboard - Run Streamlit dashboard")
        print("  cli       - Run CLI tool")
