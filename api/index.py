import sys
from pathlib import Path

# Add the scanner-engine directory to the Python path so imports inside app.py resolve correctly
sys.path.insert(0, str((Path(__file__).parent.parent / "scanner-engine").resolve()))

# Import the FastAPI application instance
from app import app
