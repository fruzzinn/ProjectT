import json
from sqlalchemy import Column, Integer, String, DateTime, Text
from datetime import datetime

from app.database import Base

class ThreatActor(Base):
    __tablename__ = "threat_actors"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True)
    description = Column(Text)
    aliases = Column(Text)  # Stored as JSON string
    motivation = Column(String)
    sophistication = Column(String)
    first_seen = Column(DateTime)
    last_seen = Column(DateTime)
    ttps = Column(Text)  # Tactics, Techniques, and Procedures (MITRE ATT&CK) - stored as JSON string
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