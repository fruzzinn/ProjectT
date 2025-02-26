from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from typing import List, Optional

from app.database import get_db
from app.services import indicator_service

router = APIRouter(prefix="/api/indicators", tags=["indicators"])

@router.get("")
def get_indicators(
    db: Session = Depends(get_db),
    type: Optional[str] = None,
    days: int = Query(30, ge=1)
):
    """Get indicators of compromise (IOCs)"""
    indicators = indicator_service.get_indicators(db, type, days)
    
    return [
        {
            "type": ioc.type,
            "value": ioc.value,
            "confidence": ioc.confidence,
            "context": ioc.context,
            "first_seen": ioc.first_seen.isoformat() + "Z",
            "last_seen": ioc.last_seen.isoformat() + "Z"
        }
        for ioc in indicators
    ]

@router.get("/high-confidence")
def get_high_confidence_indicators(
    db: Session = Depends(get_db),
    confidence: float = Query(0.7, ge=0.0, le=1.0)
):
    """Get high confidence indicators"""
    indicators = indicator_service.get_high_confidence_indicators(db, confidence)
    
    return [
        {
            "type": ioc.type,
            "value": ioc.value,
            "confidence": ioc.confidence,
            "context": ioc.context,
            "first_seen": ioc.first_seen.isoformat() + "Z",
            "last_seen": ioc.last_seen.isoformat() + "Z"
        }
        for ioc in indicators
    ]

@router.get("/type/{ioc_type}")
def get_indicators_by_type(
    ioc_type: str,
    db: Session = Depends(get_db)
):
    """Get indicators by type"""
    indicators = indicator_service.get_indicators_by_type(db, ioc_type)
    
    return [
        {
            "type": ioc.type,
            "value": ioc.value,
            "confidence": ioc.confidence,
            "context": ioc.context,
            "first_seen": ioc.first_seen.isoformat() + "Z",
            "last_seen": ioc.last_seen.isoformat() + "Z"
        }
        for ioc in indicators
    ]