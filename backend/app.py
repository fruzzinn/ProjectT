import os
from fastapi import FastAPI
import requests
import openai
from sqlalchemy import create_engine, Column, Integer, String, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime
from dotenv import load_dotenv
from datetime import datetime

# Load environment variables
load_dotenv()

# FastAPI app setup
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()

# CORS Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Change this to your frontend URL (e.g., "http://localhost:3000")
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Load API keys from .env
GOOGLE_NEWS_API_KEY = os.getenv("GOOGLE_NEWS_API_KEY")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
DATABASE_URL = "sqlite:///./news.db"

# Set OpenAI API key
openai.api_key = OPENAI_API_KEY

# Database setup
Base = declarative_base()
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Define database model
class NewsArticle(Base):
    __tablename__ = "news"
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, index=True)
    summary = Column(String)
    url = Column(String)
    source = Column(String)
    category = Column(String)
    severity = Column(String)
    cve = Column(String, nullable=True)
    published_date = Column(DateTime)

Base.metadata.create_all(bind=engine)

# Fetch Cybersecurity News
def fetch_news():
    query = "cybersecurity OR data breach OR ransomware OR cyber attack OR vulnerability exploit"
    url = f"https://newsapi.org/v2/everything?q={query}&language=en&apiKey={GOOGLE_NEWS_API_KEY}"
    response = requests.get(url)
    articles = response.json()

    print("DEBUG: Raw API Response ->", articles)  # ✅ Debugging Step

    return articles.get("articles", [])

# Categorization & CVE Identification
import re
import json

def categorize_and_summarize_article(title, description):
    try:
        client = openai.OpenAI(api_key=OPENAI_API_KEY)
        prompt = f"""
        Analyze the following cybersecurity article and categorize it.
        - Assign a category from: ["Ransomware", "Phishing", "Malware", "Zero-Day Exploit", "Vulnerability Exploit", "Nation-State Attack", "Other"]
        - Determine severity: ["Critical", "High", "Medium", "Low"]
        - Identify any CVE references (if available).
        - Summarize the threat in a **brief, intelligence-oriented manner**.

        Title: {title}
        Description: {description}
        """

        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "system", "content": prompt}]
        )

        output_text = response.choices[0].message.content.strip()

        # ✅ Ensure AI Output is Valid JSON
        try:
            parsed_output = json.loads(output_text)
            category = parsed_output.get("category", "Other")
            severity = parsed_output.get("severity", "Unknown")
            cve = parsed_output.get("cve", "None")
            summary = parsed_output.get("summary", "No summary provided.")

            return category, severity, summary, cve

        except json.JSONDecodeError:
            print(f"🚨 AI Response Failed JSON Parsing: {output_text}")
            return "Other", "Unknown", "Failed to process AI response.", "None"

    except Exception as e:
        print(f"🚨 AI Request Failed: {e}")
        return "Other", "Unknown", "Failed to process AI response.", "None"


@app.get("/")
def root():
    return {"message": "FastAPI is running!"}

# Fetch & Process News
@app.get("/fetch_news")
def fetch_and_store_news():
    db = SessionLocal()
    articles = fetch_news()
    processed_articles = []

    for article in articles:
        title = article.get("title", "").strip()
        description = article.get("description", "")

        if not title or not isinstance(description, str) or not description.strip():
            print(f"SKIPPED: Article missing title/description -> {article}")  # ✅ Debugging Step
            continue  # Skip invalid articles

        category, severity, summary, cve = categorize_and_summarize_article(title, description.strip())

        published_date_str = article.get("publishedAt", None)
        published_date = datetime.strptime(published_date_str, "%Y-%m-%dT%H:%M:%SZ") if published_date_str else datetime.utcnow()

        data = NewsArticle(
            title=title,
            summary=summary,
            url=article.get("url", "#"),
            source=article.get("source", {}).get("name", "Unknown"),
            category=category,
            severity=severity,
            cve=cve,
            published_date=published_date
        )

        # Avoid duplicates
        existing_article = db.query(NewsArticle).filter(NewsArticle.title == data.title).first()
        if not existing_article:
            db.add(data)
            db.commit()
            db.refresh(data)
            processed_articles.append(data)

    db.close()
    print(f"✅ Processed {len(processed_articles)} articles.")
    return {"message": "News fetched and processed!", "data": processed_articles}

# Retrieve News
@app.get("/news")
def get_news():
    db = SessionLocal()
    news = db.query(NewsArticle).all()
    db.close()

    return [
        {
            "title": article.title,
            "summary": article.summary,
            "url": article.url,
            "source": article.source,
            "category": article.category,
            "severity": article.severity,
            "cve": article.cve,
            "published_date": datetime.utcnow().isoformat() + "Z"
        }
        for article in news
    ]
