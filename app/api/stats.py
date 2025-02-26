from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.database import get_db
from app.services import stats_service

router = APIRouter(prefix="/api/stats", tags=["statistics"])

@router.get("")
def get_statistics(db: Session = Depends(get_db)):
    """Get threat intelligence statistics"""
    return stats_service.get_system_statistics(db)