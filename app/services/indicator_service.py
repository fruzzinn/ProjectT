from sqlalchemy.orm import Session
from typing import List, Optional
from datetime import datetime, timedelta

from app.models.indicators import Indicator

def get_indicators(
    db: Session,
    type_filter: Optional[str] = None,
    days: int = 30
):
    """Get indicators of compromise (IOCs) with filters"""
    query = db.query(Indicator)
    
    if type_filter:
        query = query.filter(Indicator.type == type_filter)
    
    # Filter by recency
    cutoff_date = datetime.utcnow() - timedelta(days=days)
    query = query.filter(Indicator.last_seen >= cutoff_date)
    
    return query.all()

def get_indicator_by_value(db: Session, value: str):
    """Get an indicator by its value"""
    return db.query(Indicator).filter(Indicator.value == value).first()

def get_indicators_by_type(db: Session, ioc_type: str):
    """Get indicators filtered by type"""
    return db.query(Indicator).filter(Indicator.type == ioc_type).all()

def get_high_confidence_indicators(db: Session, confidence_threshold: float = 0.7):
    """Get indicators with high confidence scores"""
    return db.query(Indicator).filter(
        Indicator.confidence >= confidence_threshold
    ).all()