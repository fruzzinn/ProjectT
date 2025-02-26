from sqlalchemy import Table, Column, Integer, ForeignKey, DateTime
from app.database import Base

# Association tables for many-to-many relationships
threat_actor_association = Table(
    'threat_actor_association',
    Base.metadata,
    Column('article_id', Integer, ForeignKey('news_articles.id')),
    Column('actor_id', Integer, ForeignKey('threat_actors.id'))
)

ioc_association = Table(
    'ioc_association',
    Base.metadata,
    Column('article_id', Integer, ForeignKey('news_articles.id')),
    Column('ioc_id', Integer, ForeignKey('indicators.id'))
)