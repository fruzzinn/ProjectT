from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime

# Pydantic models for API request/response validation

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

class ActorBase(BaseModel):
    name: str
    description: str
    aliases: List[str]
    motivation: str
    sophistication: str
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None

    class Config:
        from_attributes = True

class IndicatorBase(BaseModel):
    type: str
    value: str
    confidence: float
    context: str
    first_seen: datetime
    last_seen: datetime
    
    class Config:
        from_attributes = True