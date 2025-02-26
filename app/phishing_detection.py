import os
import re
import json
import time
import uuid
import hashlib
import requests
import asyncio
import numpy as np
from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta
from fastapi import APIRouter, Depends, HTTPException, Query, BackgroundTasks, File, UploadFile, Form
from fastapi.responses import JSONResponse
from sqlalchemy import Column, Integer, String, DateTime, Float, JSON, ForeignKey, Boolean, Text, func
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session, relationship
from pydantic import BaseModel, validator
from urllib.parse import urlparse
import cv2
import tensorflow as tf
from bs4 import BeautifulSoup
import whois
import socket
import tldextract
import cssutils
import logging
import imagehash
from PIL import Image
from io import BytesIO
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager
from urllib3.exceptions import InsecureRequestWarning
import difflib
import concurrent.futures

# Suppress insecure request warnings for potentially malicious sites
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# This assumes you've already defined Base and get_db() in your main app.py
# We'll use the same database connection
from app import Base, get_db

# Initialize router
phishing_router = APIRouter(prefix="/api/phishing", tags=["phishing"])

# ===============================
# Database Models
# ===============================

class PhishingSite(Base):
    __tablename__ = "phishing_sites"
    
    id = Column(String, primary_key=True, index=True)
    url = Column(String, unique=True, index=True)
    domain = Column(String, index=True)
    target_site = Column(String, default="tamm.abudhabi", index=True)
    target_page = Column(String, index=True)
    status = Column(String, index=True)  # active, monitoring, taken-down
    first_detected = Column(DateTime, default=datetime.utcnow)
    last_checked = Column(DateTime, default=datetime.utcnow)
    
    # Technical information
    ip_address = Column(String, nullable=True)
    country_code = Column(String, nullable=True)
    hosting_provider = Column(String, nullable=True)
    registrar = Column(String, nullable=True)
    registration_date = Column(DateTime, nullable=True)
    ssl_info = Column(JSON, nullable=True)
    
    # Analysis metrics
    similarity_score = Column(Float)  # Overall similarity score
    visual_similarity = Column(Float)
    content_similarity = Column(Float)
    url_similarity = Column(Float)
    ml_confidence = Column(Float)
    
    # Features detected
    features_detected = Column(JSON)  # List of detected phishing features
    
    # Content information
    html_content = Column(Text, nullable=True)
    screenshot_path = Column(String, nullable=True)
    has_login_form = Column(Boolean, default=False)
    has_tamm_logo = Column(Boolean, default=False)
    form_targets = Column(JSON, nullable=True)  # Where forms submit data to
    
    # Actions and mitigations
    is_reported = Column(Boolean, default=False)
    report_details = Column(JSON, nullable=True)
    blocked = Column(Boolean, default=False)
    takedown_requested = Column(DateTime, nullable=True)
    taken_down_date = Column(DateTime, nullable=True)
    notes = Column(Text, nullable=True)

# ===============================
# Pydantic Models for API
# ===============================

class PhishingSiteBase(BaseModel):
    url: str
    target_page: Optional[str] = "main"
    
    @validator('url')
    def validate_url(cls, v):
        if not v.startswith(('http://', 'https://')):
            raise ValueError('URL must start with http:// or https://')
        return v

class PhishingSiteCreate(PhishingSiteBase):
    pass

class PhishingSiteUpdate(BaseModel):
    status: Optional[str] = None
    is_reported: Optional[bool] = None
    blocked: Optional[bool] = None
    notes: Optional[str] = None

class PhishingSiteResponse(PhishingSiteBase):
    id: str
    domain: str
    status: str
    first_detected: datetime
    last_checked: datetime
    similarity_score: float
    visual_similarity: Optional[float] = None
    content_similarity: Optional[float] = None
    url_similarity: Optional[float] = None
    ml_confidence: Optional[float] = None
    features_detected: list
    ip_address: Optional[str] = None
    country_code: Optional[str] = None
    hosting_provider: Optional[str] = None
    registration_date: Optional[datetime] = None
    has_login_form: bool
    has_tamm_logo: bool
    screenshot_path: Optional[str] = None
    
    class Config:
        from_attributes = True

class PhishingScanRequest(BaseModel):
    urls: Optional[List[str]] = None
    scan_related_domains: Optional[bool] = True
    check_typosquatting: Optional[bool] = True
    depth: Optional[int] = 1

class ScanProgressResponse(BaseModel):
    scan_id: str
    status: str
    progress: float
    sites_found: int
    started_at: datetime
    estimated_completion: Optional[datetime] = None

class PhishingFilterParams(BaseModel):
    status: Optional[str] = None
    target_page: Optional[str] = None
    min_similarity: Optional[float] = None
    days: Optional[int] = None
    search: Optional[str] = None
    sort_by: Optional[str] = "first_detected"
    sort_order: Optional[str] = "desc"
    page: int = 1
    page_size: int = 20

class PhishingStatsResponse(BaseModel):
    total_sites: int
    active_sites: int
    taken_down_sites: int
    average_similarity: float
    by_target_page: dict
    by_country: dict
    by_status: dict
    detection_trend: dict  # Date to count mapping
    
# ===============================
# ML Models and Detection Logic
# ===============================

# Configuration for target site (Tamm Abu Dhabi)
TARGET_SITE_CONFIG = {
    "domain": "www.tamm.abudhabi",
    "url": "https://www.tamm.abudhabi/",
    "pages": {
        "main": "https://www.tamm.abudhabi/",
        "login": "https://www.tamm.abudhabi/en/login",
        "business-services": "https://www.tamm.abudhabi/en/business-services",
        "payments": "https://www.tamm.abudhabi/en/payments"
    },
    "screenshots": {
        "main": "./screenshots/tamm_main.png",
        "login": "./screenshots/tamm_login.png",
        "business-services": "./screenshots/tamm_business.png",
        "payments": "./screenshots/tamm_payments.png"
    },
    "logo_hashes": [
        "a1b2c3d4e5f6",  # Hash of the main logo
        "f6e5d4c3b2a1"   # Hash of the alternate logo
    ],
    "text_fingerprints": [
        "Abu Dhabi Government Services",
        "Tamm",
        "Smart Abu Dhabi",
        "Digital Government"
    ]
}

# Typosquatting variations to check
def generate_typosquatting_domains(domain):
    """Generate potential typosquatting variations of a domain"""
    domain_parts = tldextract.extract(domain)
    base_name = domain_parts.domain
    suffix = f".{domain_parts.suffix}"
    
    variations = []
    
    # Character replacements
    for i in range(len(base_name)):
        # Character substitution (common typos)
        for c in "abcdefghijklmnopqrstuvwxyz0123456789-":
            if c != base_name[i]:
                variations.append(f"{base_name[:i]}{c}{base_name[i+1:]}{suffix}")
        
        # Character insertion
        for c in "abcdefghijklmnopqrstuvwxyz0123456789-":
            variations.append(f"{base_name[:i]}{c}{base_name[i:]}{suffix}")
    
    # Character deletion
    for i in range(len(base_name)):
        variations.append(f"{base_name[:i]}{base_name[i+1:]}{suffix}")
    
    # Character transposition
    for i in range(len(base_name)-1):
        variations.append(f"{base_name[:i]}{base_name[i+1]}{base_name[i]}{base_name[i+2:]}{suffix}")
    
    # Common TLD variations
    tlds = [".com", ".org", ".net", ".co", ".info", ".site", ".xyz"]
    for tld in tlds:
        if tld != suffix:
            variations.append(f"{base_name}{tld}")
    
    # Homograph attacks (visually similar characters)
    homographs = {
        'a': ['à', 'á', 'â', 'ã', 'ä', 'å', 'а'],
        'b': ['b', 'ḅ', 'ḇ', 'б'],
        'c': ['ç', 'ć', 'ĉ', 'с'],
        'd': ['d', 'ď', 'đ', 'ɗ', 'ḍ', 'ḏ'],
        'e': ['è', 'é', 'ê', 'ë', 'ē', 'е', 'ё'],
        'i': ['í', 'ì', 'ï', 'î', 'ι'],
        'o': ['ó', 'ò', 'ô', 'õ', 'ö', 'ø', 'о'],
        'm': ['м'],
        'n': ['ń', 'ñ', 'ň', 'ṇ', 'ṅ'],
        'p': ['р'],
        's': ['ś', 'š', 'ṣ'],
        't': ['ť', 'ṭ', 'ţ', 'т'],
        'u': ['ú', 'ù', 'û', 'ü', 'ū'],
        'w': ['ѡ', 'ԝ'],
        'y': ['ý', 'ÿ', 'у']
    }
    
    for i, char in enumerate(base_name):
        if char in homographs:
            for h_char in homographs[char]:
                variations.append(f"{base_name[:i]}{h_char}{base_name[i+1:]}{suffix}")
    
    # Add "secure", "login", "portal", etc.
    prefixes = ["secure", "login", "portal", "my", "account", "signin", "service"]
    for prefix in prefixes:
        variations.append(f"{prefix}-{base_name}{suffix}")
        variations.append(f"{prefix}{base_name}{suffix}")
    
    # Return unique variations
    return list(set(variations))

class PhishingDetector:
    """Class to handle phishing detection logic"""
    
    def __init__(self):
        self.chrome_options = Options()
        self.chrome_options.add_argument("--headless")
        self.chrome_options.add_argument("--no-sandbox")
        self.chrome_options.add_argument("--disable-dev-shm-usage")
        self.chrome_options.add_argument("--disable-gpu")
        self.chrome_options.add_argument("--window-size=1920,1080")
        
        # Create screenshots directory if it doesn't exist
        os.makedirs("./screenshots", exist_ok=True)
        
        # Initialize the target site screenshots if they don't exist
        self._init_target_screenshots()
        
        # Load ML model (placeholder - in a real implementation, load actual model)
        # self.model = tf.keras.models.load_model("./models/phishing_detector.h5")
        logging.info("PhishingDetector initialized")
    
    def _init_target_screenshots(self):
        """Initialize screenshots of the target website if they don't exist"""
        for page_name, screenshot_path in TARGET_SITE_CONFIG["screenshots"].items():
            if not os.path.exists(screenshot_path):
                logging.info(f"Taking screenshot of {page_name} page")
                try:
                    url = TARGET_SITE_CONFIG["pages"][page_name]
                    self._take_screenshot(url, screenshot_path)
                except Exception as e:
                    logging.error(f"Failed to take screenshot of {page_name} page: {e}")
    
    def _take_screenshot(self, url, output_path):
        """Take a screenshot of a URL"""
        try:
            driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=self.chrome_options)
            driver.get(url)
            # Wait for page to load
            time.sleep(5)
            driver.save_screenshot(output_path)
            driver.quit()
            return True
        except Exception as e:
            logging.error(f"Error taking screenshot of {url}: {e}")
            return False
    
    def get_domain_info(self, url):
        """Get information about a domain"""
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        
        try:
            # Get IP address
            ip_address = socket.gethostbyname(domain)
            
            # Get WHOIS information
            w = whois.whois(domain)
            
            # Get country information using IP
            country_response = requests.get(f"https://ipinfo.io/{ip_address}/json", timeout=5)
            country_data = country_response.json()
            
            # Extract useful information
            result = {
                "domain": domain,
                "ip_address": ip_address,
                "country_code": country_data.get("country", "Unknown"),
                "hosting_provider": country_data.get("org", "Unknown"),
                "registrar": w.registrar,
                "creation_date": w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date,
                "expiration_date": w.expiration_date[0] if isinstance(w.expiration_date, list) else w.expiration_date,
            }
            
            return result
        except Exception as e:
            logging.error(f"Error getting domain info for {url}: {e}")
            return {
                "domain": domain,
                "ip_address": None,
                "country_code": None,
                "hosting_provider": None,
                "registrar": None,
                "creation_date": None,
                "expiration_date": None,
            }
    
    def calculate_url_similarity(self, url, target_domain="www.tamm.abudhabi"):
        """Calculate similarity between a URL and the target domain"""
        # Extract domain from URL
        parsed_url = urlparse(url)
        domain = parsed_url.netloc.lower()
        
        # Calculate Levenshtein distance
        distance = self._levenshtein_distance(domain, target_domain)
        max_len = max(len(domain), len(target_domain))
        
        # Convert to similarity score (0-100)
        if max_len == 0:
            return 0
        
        similarity = (1 - (distance / max_len)) * 100
        return similarity
    
    def _levenshtein_distance(self, s1, s2):
        """Calculate the Levenshtein distance between two strings"""
        if len(s1) < len(s2):
            return self._levenshtein_distance(s2, s1)
        
        if len(s2) == 0:
            return len(s1)
        
        previous_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row
        
        return previous_row[-1]
    
    def calculate_visual_similarity(self, screenshot_path, target_page="main"):
        """Calculate visual similarity between a screenshot and the target page"""
        target_screenshot = TARGET_SITE_CONFIG["screenshots"][target_page]
        
        if not os.path.exists(target_screenshot) or not os.path.exists(screenshot_path):
            logging.error(f"Screenshot files not found: {target_screenshot} or {screenshot_path}")
            return 0
        
        try:
            # Calculate perceptual hash similarity
            img1 = Image.open(screenshot_path)
            img2 = Image.open(target_screenshot)
            
            # Calculate average hash
            hash1 = imagehash.average_hash(img1)
            hash2 = imagehash.average_hash(img2)
            
            # Calculate similarity (0-100)
            hash_similarity = 100 - (hash1 - hash2) * 100 / 64  # 64 is max hash difference
            
            # Calculate color histogram similarity
            img1_cv = cv2.imread(screenshot_path)
            img2_cv = cv2.imread(target_screenshot)
            
            if img1_cv is None or img2_cv is None:
                logging.error("Failed to load images for CV processing")
                return max(0, hash_similarity)
            
            # Resize images to same dimensions
            img1_cv = cv2.resize(img1_cv, (500, 500))
            img2_cv = cv2.resize(img2_cv, (500, 500))
            
            # Calculate histograms
            hist1 = cv2.calcHist([img1_cv], [0, 1, 2], None, [8, 8, 8], [0, 256, 0, 256, 0, 256])
            hist2 = cv2.calcHist([img2_cv], [0, 1, 2], None, [8, 8, 8], [0, 256, 0, 256, 0, 256])
            
            # Normalize histograms
            cv2.normalize(hist1, hist1)
            cv2.normalize(hist2, hist2)
            
            # Calculate correlation
            hist_similarity = cv2.compareHist(hist1, hist2, cv2.HISTCMP_CORREL) * 100
            
            # Average the two similarity measures
            similarity = (hash_similarity + hist_similarity) / 2
            return max(0, min(100, similarity))
        
        except Exception as e:
            logging.error(f"Error calculating visual similarity: {e}")
            return 0
    
    def calculate_content_similarity(self, html_content, target_page="main"):
        """Calculate content similarity between HTML and target page"""
        # Fetch target page HTML
        target_url = TARGET_SITE_CONFIG["pages"][target_page]
        
        try:
            response = requests.get(target_url, timeout=10, verify=False)
            target_html = response.text
            
            # Parse both HTML contents
            soup1 = BeautifulSoup(html_content, 'html.parser')
            soup2 = BeautifulSoup(target_html, 'html.parser')
            
            # Extract text
            text1 = soup1.get_text().lower()
            text2 = soup2.get_text().lower()
            
            # Calculate sequence matcher similarity
            sm = difflib.SequenceMatcher(None, text1, text2)
            text_similarity = sm.ratio() * 100
            
            # Check for logo
            has_logo = self._check_for_logo(soup1)
            
            # Check for common elements and structure
            tags_similarity = self._compare_element_structure(soup1, soup2)
            
            # Check for specific Tamm Abu Dhabi text fingerprints
            fingerprint_score = self._check_text_fingerprints(text1)
            
            # Calculate weighted similarity
            similarity = (text_similarity * 0.4 + tags_similarity * 0.3 + fingerprint_score * 0.3)
            
            # Detect specific features
            features = self._detect_phishing_features(soup1, html_content)
            
            return {
                "similarity": max(0, min(100, similarity)),
                "has_logo": has_logo,
                "features": features,
                "has_login_form": "fake-login" in features,
                "form_targets": self._extract_form_targets(soup1)
            }
        
        except Exception as e:
            logging.error(f"Error calculating content similarity: {e}")
            return {
                "similarity": 0,
                "has_logo": False,
                "features": [],
                "has_login_form": False,
                "form_targets": []
            }
    
    def _check_for_logo(self, soup):
        """Check if the page contains the Tamm Abu Dhabi logo"""
        # This would be more sophisticated in production with actual logo detection
        # For this example, we'll just check for "tamm" in image URLs or alt text
        images = soup.find_all('img')
        
        for img in images:
            img_src = img.get('src', '').lower()
            img_alt = img.get('alt', '').lower()
            
            if 'tamm' in img_src or 'tamm' in img_alt or 'abu dhabi' in img_alt:
                return True
            
            # Also check for parent links with Tamm
            parent = img.parent
            if parent and parent.name == 'a':
                href = parent.get('href', '').lower()
                if 'tamm' in href or 'abudhabi' in href:
                    return True
        
        # Also check for specific logo classes or IDs
        logo_elements = soup.select('.logo, #logo, .brand-logo, .site-logo')
        for element in logo_elements:
            text = element.get_text().lower()
            if 'tamm' in text or 'abu dhabi' in text:
                return True
        
        return False
    
    def _compare_element_structure(self, soup1, soup2):
        """Compare the structure of two HTML documents"""
        # Count tags by type
        tags1 = {}
        tags2 = {}
        
        for tag in soup1.find_all(True):
            tag_name = tag.name
            tags1[tag_name] = tags1.get(tag_name, 0) + 1
        
        for tag in soup2.find_all(True):
            tag_name = tag.name
            tags2[tag_name] = tags2.get(tag_name, 0) + 1
        
        # Calculate similarity between tag distributions
        all_tags = set(list(tags1.keys()) + list(tags2.keys()))
        similarity_sum = 0
        
        for tag in all_tags:
            count1 = tags1.get(tag, 0)
            count2 = tags2.get(tag, 0)
            
            # Avoid division by zero
            max_count = max(count1, count2)
            if max_count > 0:
                similarity_sum += 1 - (abs(count1 - count2) / max_count)
        
        if len(all_tags) == 0:
            return 0
        
        return (similarity_sum / len(all_tags)) * 100
    
    def _check_text_fingerprints(self, text):
        """Check for specific text fingerprints from Tamm Abu Dhabi"""
        score = 0
        for fingerprint in TARGET_SITE_CONFIG["text_fingerprints"]:
            if fingerprint.lower() in text:
                score += 25  # Each fingerprint adds 25% similarity
        
        return min(100, score)
    
    def _detect_phishing_features(self, soup, html_content):
        """Detect phishing features in the HTML content"""
        features = []
        
        # Check for login forms
        forms = soup.find_all('form')
        for form in forms:
            # Look for password fields
            password_fields = form.find_all('input', {'type': 'password'})
            if password_fields:
                features.append('fake-login')
                break
        
        # Check for logo cloning
        if self._check_for_logo(soup):
            features.append('logo-clone')
        
        # Check for SSL information in text
        if 'secure' in html_content.lower() or 'ssl' in html_content.lower():
            features.append('ssl-emphasis')
        
        # Check for similar layout
        if 'tamm' in html_content.lower() or 'abu dhabi' in html_content.lower():
            features.append('similar-layout')
        
        # Check for data harvesting
        if 'email' in html_content.lower() and ('password' in html_content.lower() or 'login' in html_content.lower()):
            features.append('data-harvesting')
        
        # Check for payment forms
        payment_terms = ['payment', 'credit card', 'debit card', 'card number', 'expiry', 'cvv']
        if any(term in html_content.lower() for term in payment_terms):
            features.append('payment-form')
        
        # Check for document upload forms
        if 'upload' in html_content.lower() or 'file' in html_content.lower() or 'document' in html_content.lower():
            features.append('document-upload')
        
        # Check for SSL
        if 'https://' in html_content:
            features.append('ssl-valid')
        else:
            features.append('ssl-missing')
        
        return features
    
    def _extract_form_targets(self, soup):
        """Extract form submission targets"""
        targets = []
        forms = soup.find_all('form')
        
        for form in forms:
            action = form.get('action', '')
            method = form.get('method', 'get').upper()
            
            if action:
                targets.append({
                    'action': action,
                    'method': method
                })
            else:
                # Forms without action attribute submit to the current page
                targets.append({
                    'action': 'self',
                    'method': method
                })
        
        return targets
    
    def check_site(self, url, target_page="main"):
        """Perform a comprehensive check on a potentially phishing site"""
        # Generate unique ID for the site
        site_id = f"ps-{uuid.uuid4().hex[:8]}"
        
        # Create screenshot directory if it doesn't exist
        os.makedirs("./screenshots", exist_ok=True)
        
        # Generate screenshot filename
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        screenshot_filename = f"./screenshots/{domain.replace('.', '_')}_{int(time.time())}.png"
        
        # Take screenshot
        screenshot_success = self._take_screenshot(url, screenshot_filename)
        
        # Get domain information
        domain_info = self.get_domain_info(url)
        
        # Calculate URL similarity
        url_similarity = self.calculate_url_similarity(url)
        
        # Get HTML content
        try:
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36"
            }
            response = requests.get(url, headers=headers, timeout=10, verify=False)
            html_content = response.text
        except Exception as e:
            logging.error(f"Error fetching HTML from {url}: {e}")
            html_content = ""
        
        # Calculate content similarity
        content_analysis = self.calculate_content_similarity(html_content, target_page)
        content_similarity = content_analysis["similarity"]
        
        # Calculate visual similarity if screenshot was successful
        visual_similarity = 0
        if screenshot_success:
            visual_similarity = self.calculate_visual_similarity(screenshot_filename, target_page)
        
        # Calculate overall similarity score (weighted average)
        similarity_score = (
            url_similarity * 0.3 +
            content_similarity * 0.4 +
            visual_similarity * 0.3
        )
        
        # Calculate ML confidence (in a real implementation, use actual ML model prediction)
        # Here we'll simulate it based on the similarity score
        ml_confidence = min(1.0, max(0.0, similarity_score / 100 * 1.2))  # Adjust the scale slightly
        
        # Prepare result
        result = {
            "id": site_id,
            "url": url,
            "domain": domain,
            "target_page": target_page,
            "status": "active" if similarity_score > 65 else "monitoring",
            "similarity_score": similarity_score,
            "visual_similarity": visual_similarity,
            "content_similarity": content_similarity,
            "url_similarity": url_similarity,
            "ml_confidence": ml_confidence,
            "features_detected": content_analysis["features"],
            "has_login_form": content_analysis["has_login_form"],
            "has_tamm_logo": content_analysis["has_logo"],
            "form_targets": content_analysis["form_targets"],
            "screenshot_path": screenshot_filename if screenshot_success else None,
            "html_content": html_content,
            "ip_address": domain_info["ip_address"],
            "country_code": domain_info["country_code"],
            "hosting_provider": domain_info["hosting_provider"],
            "registration_date": domain_info["creation_date"]
        }
        
        return result

# Initialize phishing detector
phishing_detector = PhishingDetector()

# Track active scans
active_scans = {}

# ===============================
# API Endpoints
# ===============================

@phishing_router.get("/sites", response_model=List[PhishingSiteResponse])
async def get_phishing_sites(
    status: Optional[str] = None,
    target_page: Optional[str] = None,
    min_similarity: Optional[float] = None,
    days: Optional[int] = None,
    search: Optional[str] = None,
    sort_by: str = "first_detected",
    sort_order: str = "desc",
    page: int = 1,
    page_size: int = 20,
    db: Session = Depends(get_db)
):
    """Get phishing sites with filtering"""
    query = db.query(PhishingSite)
    
    # Apply filters
    if status:
        query = query.filter(PhishingSite.status == status)
    
    if target_page:
        query = query.filter(PhishingSite.target_page == target_page)
    
    if min_similarity is not None:
        query = query.filter(PhishingSite.similarity_score >= min_similarity)
    
    if days:
        cutoff_date = datetime.utcnow() - timedelta(days=days)
        query = query.filter(PhishingSite.first_detected >= cutoff_date)
    
    if search:
        query = query.filter(
            (PhishingSite.url.contains(search)) | 
            (PhishingSite.domain.contains(search))
        )
    
    # Apply sorting
    if sort_order.lower() == "asc":
        query = query.order_by(getattr(PhishingSite, sort_by).asc())
    else:
        query = query.order_by(getattr(PhishingSite, sort_by).desc())
    
    # Get total count
    total = query.count()
    
    # Apply pagination
    sites = query.offset((page - 1) * page_size).limit(page_size).all()
    
    return sites

@phishing_router.get("/sites/{site_id}", response_model=PhishingSiteResponse)
async def get_phishing_site(site_id: str, db: Session = Depends(get_db)):
    """Get a single phishing site by ID"""
    site = db.query(PhishingSite).filter(PhishingSite.id == site_id).first()
    if not site:
        raise HTTPException(status_code=404, detail="Phishing site not found")
    return site

@phishing_router.post("/sites/{site_id}", response_model=PhishingSiteResponse)
async def update_phishing_site(
    site_id: str,
    site_update: PhishingSiteUpdate,
    db: Session = Depends(get_db)
):
    """Update a phishing site"""
    site = db.query(PhishingSite).filter(PhishingSite.id == site_id).first()
    if not site:
        raise HTTPException(status_code=404, detail="Phishing site not found")
    
    # Update fields if provided
    if site_update.status is not None:
        site.status = site_update.status
        # If status changed to taken-down, set the taken-down date
        if site_update.status == "taken-down":
            site.taken_down_date = datetime.utcnow()
    
    if site_update.is_reported is not None:
        site.is_reported = site_update.is_reported
    
    if site_update.blocked is not None:
        site.blocked = site_update.blocked
    
    if site_update.notes is not None:
        site.notes = site_update.notes
    
    # Update last checked timestamp
    site.last_checked = datetime.utcnow()
    
    db.commit()
    db.refresh(site)
    
    return site

@phishing_router.post("/report/{site_id}")
async def report_phishing_site(
    site_id: str,
    contact_info: Optional[str] = None,
    report_details: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """Report a phishing site to authorities/hosting providers"""
    site = db.query(PhishingSite).filter(PhishingSite.id == site_id).first()
    if not site:
        raise HTTPException(status_code=404, detail="Phishing site not found")
    
    # In a real implementation, this would send reports to appropriate authorities
    # For this example, we'll just update the database
    
    site.is_reported = True
    site.report_details = {
        "reported_at": datetime.utcnow().isoformat(),
        "contact_info": contact_info,
        "details": report_details
    }
    
    db.commit()
    
    return {"message": f"Phishing site {site.url} reported successfully"}

@phishing_router.post("/scan", response_model=ScanProgressResponse)
async def start_phishing_scan(
    scan_request: PhishingScanRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
):
    """Start a scan for phishing sites"""
    scan_id = f"scan-{uuid.uuid4().hex[:8]}"
    
    # Initialize scan tracking
    active_scans[scan_id] = {
        "status": "starting",
        "progress": 0.0,
        "sites_found": 0,
        "started_at": datetime.utcnow(),
        "urls_to_check": [],
        "estimated_completion": None
    }
    
    # Add URLs to check
    urls_to_check = []
    
    # Add explicitly provided URLs
    if scan_request.urls:
        urls_to_check.extend(scan_request.urls)
    
    # Add typosquatting variations
    if scan_request.check_typosquatting:
        typo_variations = generate_typosquatting_domains("www.tamm.abudhabi")
        # Add http/https prefixes
        for variation in typo_variations:
            urls_to_check.append(f"http://{variation}")
            urls_to_check.append(f"https://{variation}")
    
    # Start background scan
    active_scans[scan_id]["urls_to_check"] = urls_to_check
    active_scans[scan_id]["estimated_completion"] = datetime.utcnow() + timedelta(minutes=len(urls_to_check) // 10 + 1)
    
    background_tasks.add_task(run_phishing_scan, scan_id, urls_to_check, scan_request.depth, db)
    
    return {
        "scan_id": scan_id,
        "status": "starting",
        "progress": 0.0,
        "sites_found": 0,
        "started_at": active_scans[scan_id]["started_at"],
        "estimated_completion": active_scans[scan_id]["estimated_completion"]
    }

@phishing_router.get("/scan/{scan_id}", response_model=ScanProgressResponse)
async def get_scan_status(scan_id: str):
    """Get the status of a running scan"""
    if scan_id not in active_scans:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    scan_info = active_scans[scan_id]
    
    return {
        "scan_id": scan_id,
        "status": scan_info["status"],
        "progress": scan_info["progress"],
        "sites_found": scan_info["sites_found"],
        "started_at": scan_info["started_at"],
        "estimated_completion": scan_info["estimated_completion"]
    }

@phishing_router.post("/check")
async def check_single_url(url: str = Form(...), target_page: str = Form("main")):
    """Check a single URL for phishing indicators"""
    try:
        result = phishing_detector.check_site(url, target_page)
        return result
    except Exception as e:
        logging.error(f"Error checking URL {url}: {e}")
        raise HTTPException(status_code=500, detail=f"Error checking URL: {str(e)}")

@phishing_router.get("/stats", response_model=PhishingStatsResponse)
async def get_phishing_stats(db: Session = Depends(get_db)):
    """Get phishing detection statistics"""
    # Get total sites
    total_sites = db.query(func.count(PhishingSite.id)).scalar()
    
    # Get active sites
    active_sites = db.query(func.count(PhishingSite.id)).filter(
        PhishingSite.status == "active"
    ).scalar()
    
    # Get taken down sites
    taken_down_sites = db.query(func.count(PhishingSite.id)).filter(
        PhishingSite.status == "taken-down"
    ).scalar()
    
    # Get average similarity
    avg_similarity = db.query(func.avg(PhishingSite.similarity_score)).scalar() or 0
    
    # Get sites by target page
    target_page_counts = db.query(
        PhishingSite.target_page,
        func.count(PhishingSite.id).label("count")
    ).group_by(PhishingSite.target_page).all()
    
    # Get sites by country
    country_counts = db.query(
        PhishingSite.country_code,
        func.count(PhishingSite.id).label("count")
    ).group_by(PhishingSite.country_code).all()
    
    # Get sites by status
    status_counts = db.query(
        PhishingSite.status,
        func.count(PhishingSite.id).label("count")
    ).group_by(PhishingSite.status).all()
    
    # Get detection trend (last 30 days)
    thirty_days_ago = datetime.utcnow() - timedelta(days=30)
    date_counts = db.query(
        func.date(PhishingSite.first_detected).label("date"),
        func.count(PhishingSite.id).label("count")
    ).filter(PhishingSite.first_detected >= thirty_days_ago).group_by(
        func.date(PhishingSite.first_detected)
    ).all()
    
    return {
        "total_sites": total_sites,
        "active_sites": active_sites,
        "taken_down_sites": taken_down_sites,
        "average_similarity": avg_similarity,
        "by_target_page": {tp[0]: tp[1] for tp in target_page_counts},
        "by_country": {cc[0] if cc[0] else "Unknown": cc[1] for cc in country_counts},
        "by_status": {s[0]: s[1] for s in status_counts},
        "detection_trend": {str(d[0]): d[1] for d in date_counts}
    }

# ===============================
# Background Tasks
# ===============================

async def run_phishing_scan(scan_id: str, urls: List[str], depth: int, db: Session):
    """Run phishing scan in the background"""
    active_scans[scan_id]["status"] = "running"
    sites_found = 0
    
    try:
        total_urls = len(urls)
        for i, url in enumerate(urls):
            # Update progress
            active_scans[scan_id]["progress"] = (i / total_urls) * 100
            
            try:
                # Check if URL is already in database
                existing = db.query(PhishingSite).filter(PhishingSite.url == url).first()
                if existing:
                    # URL already checked, just update last_checked
                    existing.last_checked = datetime.utcnow()
                    db.commit()
                    continue
                
                # Determine most likely target page
                target_page = "main"  # Default to main page
                if "login" in url.lower():
                    target_page = "login"
                elif "business" in url.lower():
                    target_page = "business-services"
                elif "payment" in url.lower():
                    target_page = "payments"
                
                # Check the site
                result = phishing_detector.check_site(url, target_page)
                
                # If similarity is high enough, add to database
                if result["similarity_score"] > 50:  # Configurable threshold
                    phishing_site = PhishingSite(
                        id=result["id"],
                        url=result["url"],
                        domain=result["domain"],
                        target_page=result["target_page"],
                        status=result["status"],
                        similarity_score=result["similarity_score"],
                        visual_similarity=result["visual_similarity"],
                        content_similarity=result["content_similarity"],
                        url_similarity=result["url_similarity"],
                        ml_confidence=result["ml_confidence"],
                        features_detected=result["features_detected"],
                        has_login_form=result["has_login_form"],
                        has_tamm_logo=result["has_tamm_logo"],
                        form_targets=result["form_targets"],
                        screenshot_path=result["screenshot_path"],
                        html_content=result["html_content"],
                        ip_address=result["ip_address"],
                        country_code=result["country_code"],
                        hosting_provider=result["hosting_provider"],
                        registration_date=result["registration_date"]
                    )
                    
                    db.add(phishing_site)
                    db.commit()
                    sites_found += 1
                    active_scans[scan_id]["sites_found"] = sites_found
            
            except Exception as e:
                logging.error(f"Error checking URL {url}: {e}")
                continue  # Continue with next URL
            
            # Add a delay to avoid rate limiting
            await asyncio.sleep(1)
        
        # Scan completed
        active_scans[scan_id]["status"] = "completed"
        active_scans[scan_id]["progress"] = 100.0
        
        # Keep scan info for 30 minutes then remove it
        await asyncio.sleep(1800)
        if scan_id in active_scans:
            del active_scans[scan_id]
    
    except Exception as e:
        logging.error(f"Error in phishing scan {scan_id}: {e}")
        active_scans[scan_id]["status"] = "error"
        active_scans[scan_id]["error"] = str(e)

# Function to integrate with the main app
def setup_phishing_routes(app):
    """Add phishing routes to the main FastAPI app"""
    app.include_router(phishing_router)
    
    # Create tables if they don't exist
    from app import engine
    Base.metadata.create_all(bind=engine)
    
    return app