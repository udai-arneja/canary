from sqlalchemy import Column, Integer, String, Boolean, DateTime, Text
from sqlalchemy.sql import func
from app.database import Base

class Attack(Base):
    __tablename__ = "attacks"
    
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=func.now(), index=True)
    website_url = Column(String, index=True)
    vulnerability_type = Column(String, index=True)
    attack_vector = Column(String)
    success = Column(Boolean, default=False, index=True)
    payload = Column(Text, nullable=True)
    source_ip = Column(String, nullable=True)
    user_agent = Column(String, nullable=True)
    response_code = Column(Integer, nullable=True)

class Vulnerability(Base):
    __tablename__ = "vulnerabilities"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True)
    description = Column(Text)
    severity = Column(String)  # low, medium, high, critical
    website_url = Column(String, index=True)

class Website(Base):
    __tablename__ = "websites"
    
    id = Column(Integer, primary_key=True, index=True)
    url = Column(String, unique=True, index=True)
    status = Column(String)  # active, inactive, compromised
    last_checked = Column(DateTime, nullable=True)

