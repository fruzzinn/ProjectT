import re
import requests

def extract_iocs(text):
    """Extract Indicators of Compromise from text"""
    iocs = {
        "ip_addresses": [],
        "domains": [],
        "urls": [],
        "hashes": [],
        "emails": []
    }
    
    # IP address regex (basic IPv4)
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    
    # Domain regex
    domain_pattern = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
    
    # URL regex
    url_pattern = r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+'
    
    # Hash patterns
    md5_pattern = r'\b[a-fA-F0-9]{32}\b'
    sha1_pattern = r'\b[a-fA-F0-9]{40}\b'
    sha256_pattern = r'\b[a-fA-F0-9]{64}\b'
    
    # Email regex
    email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    
    # Extract matches
    iocs["ip_addresses"] = list(set(re.findall(ip_pattern, text)))
    iocs["domains"] = list(set(re.findall(domain_pattern, text)))
    iocs["urls"] = list(set(re.findall(url_pattern, text)))
    iocs["hashes"] = list(set(
        re.findall(md5_pattern, text) + 
        re.findall(sha1_pattern, text) + 
        re.findall(sha256_pattern, text)
    ))
    iocs["emails"] = list(set(re.findall(email_pattern, text)))
    
    return iocs

def get_cvss_from_cve(cve_id):
    """Fetch CVSS score for a CVE ID from NVD"""
    if not cve_id or not cve_id.startswith("CVE-"):
        return None
    
    try:
        # NVD API endpoint
        url = f"https://services.nvd.nist.gov/rest/json/cve/1.0/{cve_id}"
        response = requests.get(url, timeout=5)
        
        if response.status_code == 200:
            data = response.json()
            impact = data.get("result", {}).get("CVE_Items", [{}])[0].get("impact", {})
            
            # Get CVSS V3 score if available, otherwise V2
            if "baseMetricV3" in impact:
                return impact["baseMetricV3"]["cvssV3"]["baseScore"]
            elif "baseMetricV2" in impact:
                return impact["baseMetricV2"]["cvssV2"]["baseScore"]
        
        return None
    except Exception as e:
        print(f"Error fetching CVSS for {cve_id}: {e}")
        return None

async def fetch_article_content(url):
    """Fetch the full content of an article from its URL"""
    try:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36"
        }
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            # Simple extraction of text - in a production system, 
            # use a more sophisticated scraper like newspaper3k
            return response.text
        return ""
    except Exception as e:
        print(f"Error fetching article content: {e}")
        return ""