from sqlalchemy.orm import Session
from typing import List

from app.models.actors import ThreatActor

def get_all_threat_actors(db: Session):
    """Get all threat actors from the database"""
    return db.query(ThreatActor).all()

def get_threat_actor_by_name(db: Session, name: str):
    """Get a threat actor by name"""
    return db.query(ThreatActor).filter(ThreatActor.name == name).first()

def get_threat_actors_by_sophistication(db: Session, sophistication: str):
    """Get threat actors filtered by sophistication level"""
    return db.query(ThreatActor).filter(
        ThreatActor.sophistication == sophistication
    ).all()

def get_recent_threat_actors(db: Session, limit: int = 10):
    """Get the most recently observed threat actors"""
    return db.query(ThreatActor).order_by(
        ThreatActor.last_seen.desc()
    ).limit(limit).all()