from fastapi import FastAPI, Depends
from sqlalchemy.orm import Session
from database import engine, SessionLocal
import models
from pydantic import BaseModel
import re
from risk_engine import calculate_risk
from ml_detector import detect_anomaly
from datetime import datetime, timedelta
from fastapi.middleware.cors import CORSMiddleware

# Create tables
models.Base.metadata.create_all(bind=engine)

# Initialize FastAPI
app = FastAPI()

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -------------------------
# Database Dependency
# -------------------------
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# -------------------------
# Request Schema
# -------------------------
class LogInput(BaseModel):
    raw_log: str

# -------------------------
# Root Endpoint
# -------------------------
@app.get("/")
def read_root():
    return {"message": "AI-SIEM backend is running"}

# -------------------------
# Log Ingestion Endpoint
# -------------------------
@app.post("/ingest-log")
def ingest_log(log: LogInput, db: Session = Depends(get_db)):

    source_ip = None
    user = None
    status = None

    # Extract IP
    ip_match = re.search(r"\d+\.\d+\.\d+\.\d+", log.raw_log)
    if ip_match:
        source_ip = ip_match.group()

    # Determine login status
    if "Failed" in log.raw_log:
        status = "Failed"
    elif "Success" in log.raw_log:
        status = "Success"

    # Extract username
    if "user=" in log.raw_log:
        user = log.raw_log.split("user=")[-1]

    # Store log in database
    new_log = models.LogEvent(
        source_ip=source_ip,
        user=user,
        status=status,
        raw_log=log.raw_log
    )

    db.add(new_log)
    db.commit()
    db.refresh(new_log)

    # -------------------------
    # Correlation Logic
    # -------------------------
    if status == "Failed" and source_ip:

        two_minutes_ago = datetime.utcnow() - timedelta(minutes=2)

        # Count failed attempts within 2 minutes
        recent_failures = db.query(models.LogEvent).filter(
            models.LogEvent.source_ip == source_ip,
            models.LogEvent.status == "Failed",
            models.LogEvent.timestamp >= two_minutes_ago
        ).count()

        # AI anomaly detection
        anomaly = detect_anomaly(recent_failures)

        # Risk score calculation
        risk_score = calculate_risk(status, recent_failures, anomaly)

        print("Failure count:", recent_failures)

        # Check if alert already exists for this IP
        existing_alert = db.query(models.Alert).filter(
            models.Alert.source_ip == source_ip
        ).first()

        # Trigger alert if threshold reached
        if recent_failures >= 5 and not existing_alert:

            new_alert = models.Alert(
                source_ip=source_ip,
                alert_type="Brute Force Attack",
                severity="High",
                risk_score=risk_score
            )

            db.add(new_alert)
            db.commit()

    return {"message": "Log stored successfully"}

# -------------------------
# Stats Endpoint
# -------------------------
@app.get("/stats")
def get_stats(db: Session = Depends(get_db)):

    total_logs = db.query(models.LogEvent).count()
    total_alerts = db.query(models.Alert).count()

    return {
        "total_logs": total_logs,
        "total_alerts": total_alerts
    }

# -------------------------
# Get Alerts Endpoint
# -------------------------
@app.get("/alerts")
def get_alerts(db: Session = Depends(get_db)):

    alerts = db.query(models.Alert).all()
    return alerts
@app.get("/logs")
def get_logs(db: Session = Depends(get_db)):

    logs = db.query(models.LogEvent).order_by(
        models.LogEvent.timestamp.desc()
    ).limit(20).all()

    return logs