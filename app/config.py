import os
import sys
from pathlib import Path
from dotenv import load_dotenv

# Attempt to find and load the .env file from multiple locations
print("Current working directory:", os.getcwd())
env_paths = [
    '.env',                             # Current directory
    '../.env',                          # Parent directory
    Path(__file__).parent.parent / '.env',  # Project root
]

env_loaded = False
for env_path in env_paths:
    print(f"Trying to load .env from: {env_path}")
    if os.path.exists(env_path):
        print(f"Found .env at {env_path}, loading...")
        load_dotenv(env_path)
        env_loaded = True
        break

if not env_loaded:
    print("WARNING: No .env file found. Will try to use environment variables or defaults.")
    # Try to load from environment without .env file
    load_dotenv()

# API Keys and Configuration
GOOGLE_NEWS_API_KEY = os.getenv("GOOGLE_NEWS_API_KEY")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")  # Optional VirusTotal integration
ALIENVAULT_API_KEY = os.getenv("ALIENVAULT_API_KEY", "")  # Optional AlienVault integration
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./cyberthreat.db")

# Debug print to verify values (hide sensitive parts of API keys)
def mask_api_key(key):
    if not key:
        return "NOT SET"
    if len(key) <= 8:
        return "****" 
    return key[:4] + "****" + key[-4:]

print(f"GOOGLE_NEWS_API_KEY: {mask_api_key(GOOGLE_NEWS_API_KEY)}")
print(f"OPENAI_API_KEY: {mask_api_key(OPENAI_API_KEY)}")
print(f"DATABASE_URL: {DATABASE_URL}")

# Check if required keys are missing and provide helpful error message
missing_keys = []
if not GOOGLE_NEWS_API_KEY:
    missing_keys.append("GOOGLE_NEWS_API_KEY")
if not OPENAI_API_KEY:
    missing_keys.append("OPENAI_API_KEY")

if missing_keys:
    print(f"ERROR: The following required environment variables are missing: {', '.join(missing_keys)}")
    print("Please make sure to create a .env file with these variables or set them in your environment.")
    print("Example .env file content:")
    print("GOOGLE_NEWS_API_KEY=your_google_news_api_key")
    print("OPENAI_API_KEY=your_openai_api_key")
    print("DATABASE_URL=sqlite:///./cyberthreat.db")
    
    # Uncomment to stop execution if keys are missing
    # sys.exit(1)

# MITRE ATT&CK Framework - Simplified mapping for categorization
MITRE_TACTICS = {
    "TA0001": "Initial Access",
    "TA0002": "Execution",
    "TA0003": "Persistence",
    "TA0004": "Privilege Escalation",
    "TA0005": "Defense Evasion",
    "TA0006": "Credential Access",
    "TA0007": "Discovery",
    "TA0008": "Lateral Movement",
    "TA0009": "Collection",
    "TA0010": "Exfiltration",
    "TA0011": "Command and Control",
    "TA0040": "Impact"
}

# Constants used by the application
DEFAULT_PAGE_SIZE = 20
MAX_PAGE_SIZE = 100
DEFAULT_FETCH_LIMIT = 10
MAX_FETCH_LIMIT = 50