from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from typing import List

from app.database import get_db
from app.services import actor_service

router = APIRouter(prefix="/api/actors", tags=["actors"])

@router.get("")
def get_threat_actors(db: Session = Depends(get_db)):
    """Get threat actor information"""
    actors = actor_service.get_all_threat_actors(db)
    
    return [
        {
            "name": actor.name,
            "description": actor.description,
            "aliases": actor.aliases_list,  # Use the property that handles JSON parsing
            "motivation": actor.motivation,
            "sophistication": actor.sophistication,
            "first_seen": actor.first_seen.isoformat() + "Z" if actor.first_seen else None,
            "last_seen": actor.last_seen.isoformat() + "Z" if actor.last_seen else None
        }
        for actor in actors
    ]

@router.get("/recent")
def get_recent_actors(db: Session = Depends(get_db), limit: int = Query(10, ge=1, le=50)):
    """Get most recently observed threat actors"""
    actors = actor_service.get_recent_threat_actors(db, limit)
    
    return [
        {
            "name": actor.name,
            "description": actor.description,
            "aliases": actor.aliases_list,
            "motivation": actor.motivation,
            "sophistication": actor.sophistication,
            "first_seen": actor.first_seen.isoformat() + "Z" if actor.first_seen else None,
            "last_seen": actor.last_seen.isoformat() + "Z" if actor.last_seen else None
        }
        for actor in actors
    ]

@router.get("/{name}")
def get_actor_by_name(name: str, db: Session = Depends(get_db)):
    """Get a specific threat actor by name"""
    actor = actor_service.get_threat_actor_by_name(db, name)
    
    if not actor:
        return {"message": "Actor not found"}
    
    return {
        "name": actor.name,
        "description": actor.description,
        "aliases": actor.aliases_list,
        "motivation": actor.motivation,
        "sophistication": actor.sophistication,
        "first_seen": actor.first_seen.isoformat() + "Z" if actor.first_seen else None,
        "last_seen": actor.last_seen.isoformat() + "Z" if actor.last_seen else None
    }