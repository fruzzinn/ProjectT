from sqlalchemy import func
from sqlalchemy.orm import Session
from datetime import datetime, timedelta

from app.models.news import NewsArticle
from app.models.actors import ThreatActor
from app.models.indicators import Indicator

def get_system_statistics(db: Session):
    """Get various system statistics"""
    
    # Total articles
    total_articles = db.query(NewsArticle).count()
    
    # Articles by severity
    severity_counts = db.query(
        NewsArticle.severity, 
        func.count(NewsArticle.id).label("count")
    ).group_by(NewsArticle.severity).all()
    
    # Articles by category
    category_counts = db.query(
        NewsArticle.category, 
        func.count(NewsArticle.id).label("count")
    ).group_by(NewsArticle.category).all()
    
    # Recent trend (last 30 days)
    thirty_days_ago = datetime.utcnow() - timedelta(days=30)
    daily_counts = db.query(
        func.date(NewsArticle.published_date).label("date"),
        func.count(NewsArticle.id).label("count")
    ).filter(NewsArticle.published_date >= thirty_days_ago).group_by(
        func.date(NewsArticle.published_date)
    ).all()
    
    # Additional stats
    total_actors = db.query(ThreatActor).count()
    total_indicators = db.query(Indicator).count()
    
    # Aggregate stats
    critical_threats = next((s[1] for s in severity_counts if s[0] == "Critical"), 0)
    high_threats = next((s[1] for s in severity_counts if s[0] == "High"), 0)
    
    # Format the results
    stats = {
        "total_articles": total_articles,
        "severity_distribution": {s[0]: s[1] for s in severity_counts},
        "category_distribution": {c[0]: c[1] for c in category_counts},
        "daily_trend": {str(d[0]): d[1] for d in daily_counts},
        "total_actors": total_actors,
        "total_indicators": total_indicators,
        "critical_threats": critical_threats,
        "high_threats": high_threats
    }
    
    return stats