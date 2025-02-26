from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.api import news, actors, indicators, stats
from app.database import get_db
from app.models.news import NewsArticle

# Main API router that includes all the route modules
api_router = APIRouter()

# Include all the routers from different modules
api_router.include_router(news.router)
api_router.include_router(actors.router)
api_router.include_router(indicators.router)
api_router.include_router(stats.router)

# Legacy endpoint for frontend compatibility
legacy_router = APIRouter()

@legacy_router.get("/news")
async def get_news(db = Depends(get_db)):
    """Legacy endpoint for frontend compatibility"""
    articles = db.query(NewsArticle).order_by(NewsArticle.published_date.desc()).all()
    
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

# Include the legacy router
api_router.include_router(legacy_router)