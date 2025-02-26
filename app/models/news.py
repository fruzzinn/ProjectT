import json
from sqlalchemy import Column, Integer, String, Float, Text, DateTime
from sqlalchemy.orm import relationship
from datetime import datetime

from app.database import Base
from app.models.base import threat_actor_association, ioc_association

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