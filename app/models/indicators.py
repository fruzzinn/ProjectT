from sqlalchemy import Column, Integer, String, Float, Text, DateTime
from datetime import datetime

from app.database import Base

class Indicator(Base):
    __tablename__ = "indicators"
    id = Column(Integer, primary_key=True, index=True)
    type = Column(String, index=True)  # IP, URL, domain, hash, etc.
    value = Column(String, unique=True, index=True)
    confidence = Column(Float)
    context = Column(Text)
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)
    created_at = Column(DateTime, default=datetime.utcnow)