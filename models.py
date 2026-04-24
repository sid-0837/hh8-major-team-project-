from sqlalchemy import Column, Integer, String, DateTime
from database import Base
from datetime import datetime

class LogEvent(Base):
    __tablename__ = "logs"

    id = Column(Integer, primary_key=True, index=True)
    source_ip = Column(String)
    user = Column(String)
    status = Column(String)
    raw_log = Column(String)
    timestamp = Column(DateTime, default=datetime.utcnow)


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    source_ip = Column(String)
    alert_type = Column(String)
    severity = Column(String)
    risk_score = Column(Integer)
    timestamp = Column(DateTime, default=datetime.utcnow)
