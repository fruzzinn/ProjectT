import asyncio
from fastapi import FastAPI, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes import api_router
from app.database import init_db, SessionLocal
from app.services import fetch_and_process_news

# Create FastAPI application
app = FastAPI(
    title="Cybersecurity Threat Intelligence API",
    description="A sophisticated API for gathering, analyzing, and delivering cybersecurity threat intelligence",
    version="2.0.0"
)

# CORS Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Update for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include all routes
app.include_router(api_router)

# Root endpoint
@app.get("/")
def root():
    return {
        "message": "Cybersecurity Threat Intelligence API",
        "version": "2.0",
        "endpoints": [
            "/api/threats",
            "/api/threats/recent",
            "/api/threats/severe",
            "/api/threats/cve/{cve_id}",
            "/api/actors",
            "/api/indicators",
            "/api/stats",
            "/api/fetch" 
        ]
    }

# Startup event
@app.on_event("startup")
async def startup_event():
    # Initialize database
    init_db()
    
    # Start initial data fetch
    # In a production app, use a separate scheduler like Celery
    background_tasks = BackgroundTasks()
    db = SessionLocal()
    try:
        await fetch_and_process_news(db)
    except Exception as e:
        print(f"Error in startup fetch: {e}")
    finally:
        db.close()

# To run the app: 
# uvicorn app.main:app --reload

from phishing_detection import setup_phishing_routes

# Initialize the app with phishing routes
app = setup_phishing_routes(app)

# Add phishing stats to the main dashboard endpoint
@app.get("/api/dashboard")
def get_dashboard_stats(db: Session = Depends(get_db)):
    """Get combined dashboard statistics including phishing data"""
    # Get existing threat stats
    threat_stats = get_statistics(db)
    
    # Get phishing stats
    phishing_stats = None
    try:
        from phishing_detection import PhishingSite
        
        # Total phishing sites
        total_phishing = db.query(func.count(PhishingSite.id)).scalar() or 0
        
        # Active phishing sites
        active_phishing = db.query(func.count(PhishingSite.id)).filter(
            PhishingSite.status == "active"
        ).scalar() or 0
        
        # Sites taken down
        taken_down = db.query(func.count(PhishingSite.id)).filter(
            PhishingSite.status == "taken-down"
        ).scalar() or 0
        
        # Recent detections
        recent_phishing = db.query(PhishingSite).order_by(
            PhishingSite.first_detected.desc()
        ).limit(5).all()
        
        phishing_stats = {
            "total_sites": total_phishing,
            "active_sites": active_phishing,
            "taken_down_sites": taken_down,
            "recent_detections": [
                {
                    "url": site.url,
                    "similarity_score": site.similarity_score,
                    "detected_date": site.first_detected.isoformat() + "Z",
                    "status": site.status
                }
                for site in recent_phishing
            ]
        }
    except Exception as e:
        print(f"Error getting phishing stats: {e}")
        phishing_stats = {
            "total_sites": 0,
            "active_sites": 0,
            "taken_down_sites": 0,
            "recent_detections": []
        }
    
    # Combine stats
    combined_stats = {
        "threats": threat_stats,
        "phishing": phishing_stats
    }
    
    return combined_stats