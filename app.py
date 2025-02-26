import os
import re
import json
import time
import hashlib
import requests
import asyncio
import tiktoken  # For token counting
from fastapi import FastAPI, Depends, HTTPException, Query, BackgroundTasks, Request
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Float, JSON, ForeignKey, Table, Text, func
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session, relationship
from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta
from dotenv import load_dotenv
import openai
from pydantic import BaseModel

# Load environment variables
load_dotenv()

# API Keys and Configuration
GOOGLE_NEWS_API_KEY = os.getenv("GOOGLE_NEWS_API_KEY")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")  # Optional VirusTotal integration
ALIENVAULT_API_KEY = os.getenv("ALIENVAULT_API_KEY", "")  # Optional AlienVault integration
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./cyberthreat.db")

# Initialize OpenAI
openai.api_key = OPENAI_API_KEY
client = openai.OpenAI(api_key=OPENAI_API_KEY)

# FastAPI app setup
app = FastAPI(
    title="Cybersecurity Threat Intelligence API",
    description="A sophisticated API for gathering, analyzing, and delivering cybersecurity threat intelligence",
    version="2.0.0"
)

# CORS Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Update for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Database setup
Base = declarative_base()
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Association tables for many-to-many relationships
threat_actor_association = Table(
    'threat_actor_association',
    Base.metadata,
    Column('article_id', Integer, ForeignKey('news_articles.id')),
    Column('actor_id', Integer, ForeignKey('threat_actors.id'))
)

ioc_association = Table(
    'ioc_association',
    Base.metadata,
    Column('article_id', Integer, ForeignKey('news_articles.id')),
    Column('ioc_id', Integer, ForeignKey('indicators.id'))
)

# Define database models
class ThreatActor(Base):
    __tablename__ = "threat_actors"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True)
    description = Column(Text)
    aliases = Column(Text)  # Changed from JSON to Text
    motivation = Column(String)
    sophistication = Column(String)
    first_seen = Column(DateTime)
    last_seen = Column(DateTime)
    ttps = Column(Text)  # Changed from JSON to Text
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    @property
    def aliases_list(self):
        """Convert stored JSON string to Python list"""
        if not self.aliases:
            return []
        try:
            return json.loads(self.aliases)
        except:
            return []
    
    @property
    def ttps_list(self):
        """Convert stored JSON string to Python list"""
        if not self.ttps:
            return []
        try:
            return json.loads(self.ttps)
        except:
            return []

class Indicator(Base):
    __tablename__ = "indicators"
    id = Column(Integer, primary_key=True, index=True)
    type = Column(String, index=True)  # IP, URL, domain, hash, etc.
    value = Column(String, unique=True, index=True)
    confidence = Column(Float)
    context = Column(Text)
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)
    created_at = Column(DateTime, default=datetime.utcnow)

class NewsArticle(Base):
    __tablename__ = "news_articles"
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, index=True)
    summary = Column(Text)
    content = Column(Text)
    url = Column(String, unique=True)
    source = Column(String, index=True)
    
    # Enhanced categorization
    category = Column(String, index=True)
    severity = Column(String, index=True)
    severity_score = Column(Float)  # Numerical severity (0-10)
    confidence = Column(Float)  # Confidence in the analysis (0-1)
    
    # MITRE ATT&CK classification - stored as Text (JSON strings) in SQLite
    mitre_tactics = Column(Text)  # JSON string of MITRE ATT&CK tactics
    mitre_techniques = Column(Text)  # JSON string of MITRE ATT&CK techniques
    
    # CVE and vulnerability tracking
    cve = Column(String, index=True, nullable=True)  # Store as string
    cvss_score = Column(Float, nullable=True)  # Common Vulnerability Scoring System
    affected_systems = Column(Text, nullable=True)  # JSON string of affected systems
    
    # Additional threat data
    threat_actors = relationship("ThreatActor", secondary=threat_actor_association)
    indicators = relationship("Indicator", secondary=ioc_association)
    
    # Temporal data
    published_date = Column(DateTime, index=True)
    discovered_date = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    @property
    def mitre_tactics_list(self):
        """Convert stored JSON string to Python list"""
        if not self.mitre_tactics:
            return []
        try:
            return json.loads(self.mitre_tactics)
        except:
            return []
            
    @property
    def mitre_techniques_list(self):
        """Convert stored JSON string to Python list"""
        if not self.mitre_techniques:
            return []
        try:
            return json.loads(self.mitre_techniques)
        except:
            return []
            
    @property
    def affected_systems_list(self):
        """Convert stored JSON string to Python list"""
        if not self.affected_systems:
            return []
        try:
            return json.loads(self.affected_systems)
        except:
            return []

# Create database tables
Base.metadata.create_all(bind=engine)

# Dependencies
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Pydantic models for API
class ArticleBase(BaseModel):
    title: str
    summary: str
    url: str
    source: str
    category: str
    severity: str
    severity_score: float
    published_date: datetime
    cve: Optional[str] = None
    cvss_score: Optional[float] = None
    mitre_tactics: Optional[List[str]] = None
    mitre_techniques: Optional[List[str]] = None
    
    class Config:
        from_attributes = True  # Updated for Pydantic v2 compatibility

class ThreatResponse(BaseModel):
    total: int
    page: int
    page_size: int
    results: List[ArticleBase]

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

# Token management utilities
def num_tokens_from_string(string: str, model: str = "gpt-3.5-turbo") -> int:
    """Returns the number of tokens in a text string."""
    try:
        encoding = tiktoken.encoding_for_model(model)
        return len(encoding.encode(string))
    except Exception:
        # Fallback: rough approximation (4 chars ~= 1 token)
        return len(string) // 4

def truncate_to_token_limit(text: str, max_tokens: int = 4000, model: str = "gpt-3.5-turbo") -> str:
    """Truncate text to fit within token limit."""
    if not text:
        return ""
        
    # Calculate current tokens
    current_tokens = num_tokens_from_string(text, model)
    
    # If already under limit, return as is
    if current_tokens <= max_tokens:
        return text
    
    # Otherwise, truncate - we'll use a simple ratio approach
    ratio = max_tokens / current_tokens
    new_length = int(len(text) * ratio * 0.9)  # 10% safety margin
    return text[:new_length] + "... [truncated]"

# Rate limit handling
async def retry_with_exponential_backoff(
    func,
    max_retries: int = 5,
    initial_delay: float = 1,
    exponential_base: float = 2,
    max_delay: float = 60,
    jitter: bool = True,
    *args,
    **kwargs
):
    """Retry a function with exponential backoff."""
    delay = initial_delay
    
    for retry in range(max_retries):
        try:
            return await func(*args, **kwargs)
        except openai.RateLimitError as e:
            if retry == max_retries - 1:
                raise e  # Re-raise the last exception if we've exhausted retries
                
            if jitter:
                delay *= (0.5 + exponential_base - 0.5 * exponential_base)
                
            delay = min(delay, max_delay)
            print(f"Rate limit hit, retrying in {delay:.2f} seconds...")
            await asyncio.sleep(delay)
            delay *= exponential_base
        except Exception as e:
            # Don't retry on other exceptions
            print(f"Non-rate-limit error occurred: {e}")
            raise e

# Helper functions for threat intelligence
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

async def analyze_with_ai(title, description, content=""):
    """Enhanced AI analysis for cybersecurity articles with rate limit handling"""
    # Prepare the input text
    full_text = f"Title: {title}\nDescription: {description}\n"
    
    # Truncate content to avoid rate limits
    if content:
        # We'll need around 1000 tokens for the model response
        content = truncate_to_token_limit(content, max_tokens=4000)
        full_text += f"Content: {content}"
    
    # Check total tokens and truncate if necessary
    full_text = truncate_to_token_limit(full_text, max_tokens=6000)
    
    prompt = f"""
    You are a cybersecurity expert tasked with analyzing threat intelligence data.
    
    Analyze the following cybersecurity article and provide structured intelligence:
    
    {full_text}
    
    Provide a structured JSON response with the following fields:
    1. "category": The most specific category from ["Ransomware", "Phishing", "Malware", "Zero-Day Exploit", "Vulnerability", "Supply Chain Attack", "Advanced Persistent Threat", "Data Breach", "DDoS", "Insider Threat", "Nation-State Attack", "Cryptojacking", "Social Engineering", "IoT Attack", "Other"]
    2. "severity": ["Critical", "High", "Medium", "Low"]
    3. "severity_score": A numerical score from 0-10 indicating the severity
    4. "confidence": A value from 0-1 indicating confidence in your analysis
    5. "cve": Any CVE identifiers mentioned (format: CVE-YYYY-NNNNN)
    6. "affected_systems": List of affected systems, software, hardware
    7. "mitre_tactics": List of MITRE ATT&CK tactics that apply
    8. "mitre_techniques": List of MITRE ATT&CK techniques that apply
    9. "threat_actors": List of threat actors/groups mentioned or likely responsible
    10. "iocs": Any indicators of compromise mentioned
    11. "summary": A concise technical summary of the threat (max 150 words)
    12. "mitigation": Brief mitigation recommendations
    
    Return ONLY the JSON with no additional text.
    """
    
    # Use retry logic with the analysis request
    try:
        async def make_request():
            response = client.chat.completions.create(
                model="gpt-3.5-turbo",  # Use 3.5 instead of 4o for lower rate limits
                messages=[
                    {"role": "system", "content": "You are a cybersecurity threat intelligence expert."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.1
            )
            return response
            
        response = await retry_with_exponential_backoff(make_request)
        
        result_text = response.choices[0].message.content.strip()
        
        try:
            # Strip any markdown formatting if present
            if result_text.startswith("```json"):
                result_text = result_text.replace("```json", "", 1)
            if result_text.endswith("```"):
                result_text = result_text.rsplit("```", 1)[0]
                
            return json.loads(result_text.strip())
        except json.JSONDecodeError:
            print(f"JSON parsing error, raw response: {result_text}")
            return {
                "category": "Other",
                "severity": "Medium",
                "severity_score": 5.0,
                "confidence": 0.5,
                "summary": "Failed to process AI response."
            }
    
    except Exception as e:
        print(f"AI analysis error: {e}")
        return {
            "category": "Other",
            "severity": "Unknown",
            "severity_score": 5.0,
            "confidence": 0.3,
            "summary": "Failed to process with AI analysis."
        }

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
    except Exception:
        return ""

# Background task functions
async def process_article(article_data, db):
    """Process a single article with enhanced analysis"""
    try:
        # Check if article already exists
        existing = db.query(NewsArticle).filter(NewsArticle.url == article_data["url"]).first()
        if existing:
            return None
        
        # Fetch full article content when available
        content = await fetch_article_content(article_data["url"])
        
        # Enhanced AI analysis
        analysis = await analyze_with_ai(
            article_data["title"], 
            article_data.get("description", ""),
            content
        )
        
        # Handle list to string conversions for database compatibility
        cve_value = None
        if analysis.get("cve"):
            # If cve is a list, convert to string or take first item
            if isinstance(analysis["cve"], list):
                if analysis["cve"]:  # If list is not empty
                    cve_value = analysis["cve"][0]  # Take first CVE
                else:
                    cve_value = None
            else:
                cve_value = analysis["cve"]  # Already a string or None
        
        # Convert other list fields to JSON strings
        mitre_tactics = analysis.get("mitre_tactics", [])
        mitre_techniques = analysis.get("mitre_techniques", [])
        affected_systems = analysis.get("affected_systems", [])
        
        # Ensure proper JSON serialization for SQLite Text columns
        mitre_tactics_json = json.dumps(mitre_tactics) if mitre_tactics else None
        mitre_techniques_json = json.dumps(mitre_techniques) if mitre_techniques else None
        affected_systems_json = json.dumps(affected_systems) if affected_systems else None
        
        # Extract CVSS score for CVE if available
        cvss_score = None
        if cve_value:
            cvss_score = get_cvss_from_cve(cve_value)
        
        # Extract IOCs from content
        iocs = extract_iocs(content)
        
        # Create the article record
        article = NewsArticle(
            title=article_data["title"],
            summary=analysis.get("summary", "No summary available"),
            content=content[:10000],  # Limit content size
            url=article_data["url"],
            source=article_data.get("source", {}).get("name", "Unknown"),
            category=analysis.get("category", "Other"),
            severity=analysis.get("severity", "Medium"),
            severity_score=analysis.get("severity_score", 5.0),
            confidence=analysis.get("confidence", 0.5),
            mitre_tactics=mitre_tactics_json,
            mitre_techniques=mitre_techniques_json,
            cve=cve_value,
            cvss_score=cvss_score,
            affected_systems=affected_systems_json,
            published_date=datetime.fromisoformat(article_data["publishedAt"].replace("Z", "+00:00"))
            if article_data.get("publishedAt") else datetime.utcnow()
        )
        
        # Add to database
        db.add(article)
        db.commit()
        db.refresh(article)
        
        # Process and store threat actors
        if analysis.get("threat_actors"):
            threat_actors = analysis["threat_actors"]
            # Handle if threat_actors is a string instead of list
            if isinstance(threat_actors, str):
                threat_actors = [threat_actors]
                
            for actor_name in threat_actors:
                actor = db.query(ThreatActor).filter(ThreatActor.name == actor_name).first()
                if not actor:
                    # Create with proper JSON serialization for Text columns
                    actor = ThreatActor(
                        name=actor_name,
                        description=f"Threat actor mentioned in relation to {article.title}",
                        aliases=json.dumps([]),  # Empty array as JSON string
                        motivation="Unknown",
                        sophistication="Unknown",
                        first_seen=article.published_date,
                        last_seen=article.published_date,
                        ttps=json.dumps([])  # Empty array as JSON string
                    )
                    db.add(actor)
                    db.commit()
                    db.refresh(actor)
                
                # Associate actor with article
                article.threat_actors.append(actor)
        
        # Process IOCs
        for ioc_type, values in iocs.items():
            # Normalize IOC type
            normalized_type = ioc_type.rstrip('s')  # Convert 'ip_addresses' to 'ip_address'
            if normalized_type == 'ip_addres':  # Fix special case
                normalized_type = 'ip'
                
            for value in values:
                # Check if IOC already exists
                ioc = db.query(Indicator).filter(Indicator.value == value).first()
                if not ioc:
                    ioc = Indicator(
                        type=normalized_type,
                        value=value,
                        confidence=0.7,  # Default confidence
                        context=f"Extracted from article: {article.title}",
                        first_seen=article.published_date,
                        last_seen=article.published_date
                    )
                    db.add(ioc)
                    db.commit()
                    db.refresh(ioc)
                
                # Associate IOC with article
                article.indicators.append(ioc)
        
        db.commit()
        return article
    except Exception as e:
        db.rollback()
        print(f"Error processing article: {e}")
        return None

async def fetch_and_process_news(background_tasks):
    """Fetch cybersecurity news from multiple sources with rate limit awareness"""
    # Use a unique session for this background task
    db = SessionLocal()
    
    try:
        # Process fewer articles per batch to avoid rate limits
        search_queries = [
            "cybersecurity OR data breach OR ransomware",
            "vulnerability OR exploit OR zero-day OR CVE",
        ]
        
        all_articles = []
        
        for query in search_queries:
            url = f"https://newsapi.org/v2/everything?q={query}&language=en&pageSize=10&apiKey={GOOGLE_NEWS_API_KEY}"
            
            try:
                response = requests.get(url, timeout=10)
                articles = response.json().get("articles", [])
                all_articles.extend(articles)
                # Avoid rate limits
                await asyncio.sleep(1)
            except Exception as e:
                print(f"Error fetching news for query '{query}': {e}")
        
        # De-duplicate articles by URL
        seen_urls = set()
        unique_articles = []
        
        for article in all_articles:
            if article["url"] not in seen_urls and article.get("title") and article.get("description"):
                seen_urls.add(article["url"])
                unique_articles.append(article)
        
        # Limit to 5 articles per batch to avoid rate limits
        unique_articles = unique_articles[:5]
        
        # Process each article with delay between to avoid rate limits
        for article in unique_articles:
            await process_article(article, db)
            # More substantial delay to avoid API rate limits
            await asyncio.sleep(2)
        
        print(f"✅ Processed {len(unique_articles)} articles.")
    except Exception as e:
        print(f"Error in fetch_and_process_news: {e}")
    finally:
        db.close()

# API Endpoints
@app.get("/")
def root():
    return {
        "message": "Cybersecurity Threat Intelligence API",
        "version": "2.0",
        "endpoints": [
            "/api/threats",
            "/api/threats/recent",
            "/api/threats/severe",
            "/api/threats/cve/{cve_id}",
            "/api/actors",
            "/api/indicators",
            "/api/fetch" 
        ]
    }

@app.get("/api/threats", response_model=ThreatResponse)
def get_threats(
    db: Session = Depends(get_db),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    category: Optional[str] = None,
    severity: Optional[str] = None,
    min_severity_score: Optional[float] = None,
    days: Optional[int] = None,
    cve: Optional[str] = None,
    threat_actor: Optional[str] = None,
    search: Optional[str] = None
):
    """
    Get threat intelligence with advanced filtering options
    """
    query = db.query(NewsArticle)
    
    # Apply filters
    if category:
        query = query.filter(NewsArticle.category == category)
    
    if severity:
        query = query.filter(NewsArticle.severity == severity)
    
    if min_severity_score is not None:
        query = query.filter(NewsArticle.severity_score >= min_severity_score)
    
    if days:
        cutoff_date = datetime.utcnow() - timedelta(days=days)
        query = query.filter(NewsArticle.published_date >= cutoff_date)
    
    if cve:
        query = query.filter(NewsArticle.cve == cve)
    
    if threat_actor:
        query = query.join(NewsArticle.threat_actors).filter(ThreatActor.name.contains(threat_actor))
    
    if search:
        query = query.filter(
            (NewsArticle.title.contains(search)) | 
            (NewsArticle.summary.contains(search)) |
            (NewsArticle.content.contains(search))
        )
    
    # Get total count for pagination
    total = query.count()
    
    # Apply pagination
    query = query.order_by(NewsArticle.published_date.desc())
    query = query.offset((page - 1) * page_size).limit(page_size)
    
    # Execute query
    articles = query.all()
    
    # Convert JSON strings to lists for the response
    results = []
    for article in articles:
        article_dict = {
            "title": article.title,
            "summary": article.summary,
            "url": article.url,
            "source": article.source,
            "category": article.category,
            "severity": article.severity,
            "severity_score": article.severity_score,
            "confidence": article.confidence,
            "published_date": article.published_date,
            "cve": article.cve,
            "cvss_score": article.cvss_score,
            "mitre_tactics": article.mitre_tactics_list,
            "mitre_techniques": article.mitre_techniques_list
        }
        results.append(article_dict)
    
    return {
        "total": total,
        "page": page,
        "page_size": page_size,
        "results": results
    }

@app.get("/api/threats/recent")
def get_recent_threats(db: Session = Depends(get_db), limit: int = Query(10, ge=1, le=50)):
    """Get the most recent threats"""
    articles = db.query(NewsArticle).order_by(NewsArticle.published_date.desc()).limit(limit).all()
    
    return [
        {
            "title": article.title,
            "summary": article.summary,
            "url": article.url,
            "source": article.source,
            "category": article.category,
            "severity": article.severity,
            "severity_score": article.severity_score,
            "cve": article.cve,
            "mitre_tactics": article.mitre_tactics_list,
            "published_date": article.published_date.isoformat() + "Z"
        }
        for article in articles
    ]

@app.get("/api/threats/severe")
def get_severe_threats(db: Session = Depends(get_db), limit: int = Query(10, ge=1, le=50)):
    """Get the most severe threats"""
    threats = db.query(NewsArticle).filter(
        NewsArticle.severity.in_(["Critical", "High"])
    ).order_by(NewsArticle.severity_score.desc(), NewsArticle.published_date.desc()).limit(limit).all()
    
    return [
        {
            "title": article.title,
            "summary": article.summary,
            "url": article.url,
            "source": article.source,
            "category": article.category,
            "severity": article.severity,
            "cve": article.cve,
            "published_date": article.published_date.isoformat() + "Z"
        }
        for article in articles
    ]

# Startup tasks
@app.on_event("startup")
async def startup_event():
    # Ensure database is initialized
    Base.metadata.create_all(bind=engine)
    
    # Schedule the initial data fetch 
    # (in a production app, use a separate scheduler like Celery)
    background_tasks = BackgroundTasks()
    background_tasks.add_task(fetch_and_process_news, background_tasks)

# To run the app: 
# uvicorn app:app --reload