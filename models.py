from sqlalchemy import Column, Integer, String, DateTime, Text
from datetime import datetime
from database import Base


class LogEvent(Base):
    __tablename__ = "log_events"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    source_ip = Column(String)
    destination_ip = Column(String)
    event_type = Column(String)
    user = Column(String)
    status = Column(String)
    raw_log = Column(Text)


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    source_ip = Column(String)
    alert_type = Column(String)
    severity = Column(String)
    risk_score = Column(Integer)
    status = Column(String, default="Open")
    created_at = Column(DateTime, default=datetime.utcnow)