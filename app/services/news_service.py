import json
import asyncio
import requests
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from typing import List, Dict, Any, Optional

from app.models.news import NewsArticle
from app.models.actors import ThreatActor
from app.models.indicators import Indicator
from app.utils.ai_utils import analyze_with_ai
from app.utils.ioc_utils import extract_iocs, get_cvss_from_cve, fetch_article_content
from app.config import GOOGLE_NEWS_API_KEY

async def process_article(article_data: Dict[str, Any], db: Session) -> Optional[NewsArticle]:
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

async def fetch_and_process_news(db: Session):
    """Fetch cybersecurity news from multiple sources with rate limit awareness"""
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
        processed = []
        for article in unique_articles:
            result = await process_article(article, db)
            if result:
                processed.append(result)
            # More substantial delay to avoid API rate limits
            await asyncio.sleep(2)
        
        print(f"✅ Processed {len(processed)} articles.")
        return processed
    except Exception as e:
        print(f"Error in fetch_and_process_news: {e}")
        return []

def get_recent_threats(db: Session, limit: int = 10):
    """Get the most recent threats"""
    return db.query(NewsArticle).order_by(
        NewsArticle.published_date.desc()
    ).limit(limit).all()

def get_severe_threats(db: Session, limit: int = 10):
    """Get the most severe threats"""
    return db.query(NewsArticle).filter(
        NewsArticle.severity.in_(["Critical", "High"])
    ).order_by(
        NewsArticle.severity_score.desc(), 
        NewsArticle.published_date.desc()
    ).limit(limit).all()

def get_threats_by_cve(db: Session, cve_id: str):
    """Get threats related to a specific CVE"""
    return db.query(NewsArticle).filter(
        NewsArticle.cve == cve_id
    ).all()

def get_filtered_threats(
    db: Session,
    page: int = 1,
    page_size: int = 20,
    category: Optional[str] = None,
    severity: Optional[str] = None,
    min_severity_score: Optional[float] = None,
    days: Optional[int] = None,
    cve: Optional[str] = None,
    threat_actor: Optional[str] = None,
    search: Optional[str] = None
):
    """Get threat intelligence with advanced filtering options"""
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
        query = query.join(NewsArticle.threat_actors).filter(
            ThreatActor.name.contains(threat_actor)
        )
    
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
    results = query.all()
    
    return total, results