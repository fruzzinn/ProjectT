from fastapi import APIRouter, Depends, Query, BackgroundTasks
from sqlalchemy.orm import Session
from typing import List, Optional

from app.database import get_db
from app.schemas.schemas import ArticleBase, ThreatResponse
from app.services import news_service, get_filtered_threats
from app.config import DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE, DEFAULT_FETCH_LIMIT, MAX_FETCH_LIMIT

router = APIRouter(prefix="/api/threats", tags=["threats"])

@router.get("", response_model=ThreatResponse)
def get_threats(
    db: Session = Depends(get_db),
    page: int = Query(1, ge=1),
    page_size: int = Query(DEFAULT_PAGE_SIZE, ge=1, le=MAX_PAGE_SIZE),
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
    total, results = news_service.get_filtered_threats(
        db, page, page_size, category, severity, 
        min_severity_score, days, cve, threat_actor, search
    )
    
    # Convert JSON strings to lists for the response
    articles = []
    for article in results:
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
        articles.append(article_dict)
    
    return {
        "total": total,
        "page": page,
        "page_size": page_size,
        "results": articles
    }

@router.get("/recent")
def get_recent_threats(
    db: Session = Depends(get_db), 
    limit: int = Query(DEFAULT_FETCH_LIMIT, ge=1, le=MAX_FETCH_LIMIT)
):
    """Get the most recent threats"""
    articles = news_service.get_recent_threats(db, limit)
    
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

@router.get("/severe")
def get_severe_threats(
    db: Session = Depends(get_db), 
    limit: int = Query(DEFAULT_FETCH_LIMIT, ge=1, le=MAX_FETCH_LIMIT)
):
    """Get the most severe threats"""
    articles = news_service.get_severe_threats(db, limit)
    
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
            "mitre_techniques": article.mitre_techniques_list,
            "published_date": article.published_date.isoformat() + "Z"
        }
        for article in articles
    ]

@router.get("/cve/{cve_id}")
def get_threats_by_cve(cve_id: str, db: Session = Depends(get_db)):
    """Get threats related to a specific CVE"""
    articles = news_service.get_threats_by_cve(db, cve_id)
    
    return [
        {
            "title": article.title,
            "summary": article.summary,
            "url": article.url,
            "source": article.source,
            "category": article.category,
            "severity": article.severity,
            "severity_score": article.severity_score,
            "mitre_tactics": article.mitre_tactics_list,
            "mitre_techniques": article.mitre_techniques_list,
            "published_date": article.published_date.isoformat() + "Z"
        }
        for article in articles
    ]

@router.post("/fetch")
@router.get("/fetch")
async def fetch_threats(background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    """Trigger a background fetch of new threat intelligence"""
    background_tasks.add_task(news_service.fetch_and_process_news, db)
    return {"message": "Threat intelligence fetch started. Check back later for results."}