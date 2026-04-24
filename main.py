from fastapi import FastAPI, Depends
from sqlalchemy.orm import Session
from database import engine, SessionLocal
import models
from pydantic import BaseModel
import re
from datetime import datetime, timedelta
from fastapi.middleware.cors import CORSMiddleware

from risk_engine import calculate_risk
from ml_detector import detect_anomaly

models.Base.metadata.create_all(bind=engine)

app = FastAPI()

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# DB dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Input model
class LogInput(BaseModel):
    raw_log: str

@app.get("/")
def home():
    return {"message": "SIEM Running"}

# -------------------------
# INGEST LOG
# -------------------------
@app.post("/ingest-log")
def ingest_log(log: LogInput, db: Session = Depends(get_db)):

    source_ip = None
    user = None
    status = None

    ip_match = re.search(r"\d+\.\d+\.\d+\.\d+", log.raw_log)
    if ip_match:
        source_ip = ip_match.group()

    if "failed" in log.raw_log.lower():
        status = "Failed"
    elif "success" in log.raw_log.lower():
        status = "Success"

    if "user=" in log.raw_log:
        user = log.raw_log.split("user=")[-1]

    new_log = models.LogEvent(
        source_ip=source_ip,
        user=user,
        status=status,
        raw_log=log.raw_log
    )

    db.add(new_log)
    db.commit()

    # -------------------------
    # DETECTION
    # -------------------------
    alert_type = None
    severity = "Low"
    anomaly = False
    recent_failures = 0

    # Brute Force
    if status == "Failed" and source_ip:
        time_limit = datetime.utcnow() - timedelta(minutes=2)

        recent_failures = db.query(models.LogEvent).filter(
            models.LogEvent.source_ip == source_ip,
            models.LogEvent.status == "Failed",
            models.LogEvent.timestamp >= time_limit
        ).count()

        anomaly = detect_anomaly(recent_failures)

        if recent_failures >= 3:
            alert_type = "Brute Force Attack"
            severity = "High"

    # SQL Injection
    sql_patterns = ["' OR '1'='1", "UNION SELECT", "--", "DROP TABLE"]

    if any(p.lower() in log.raw_log.lower() for p in sql_patterns):
        alert_type = "SQL Injection Attempt"
        severity = "Critical"
        anomaly = True

    # Unauthorized Access
    if "unauthorized" in log.raw_log.lower():
        alert_type = "Unauthorized Access"
        severity = "High"

    risk_score = calculate_risk(status, recent_failures, anomaly)

    if alert_type:
        alert = models.Alert(
            source_ip=source_ip,
            alert_type=alert_type,
            severity=severity,
            risk_score=risk_score
        )
        db.add(alert)
        db.commit()

    return {"message": "Processed"}

# -------------------------
# ALERTS API
# -------------------------
@app.get("/alerts")
def get_alerts(db: Session = Depends(get_db)):
    alerts = db.query(models.Alert).order_by(
        models.Alert.timestamp.desc()
    ).all()

    return [
        {
            "source_ip": a.source_ip,
            "alert_type": a.alert_type,
            "severity": a.severity,
            "risk_score": a.risk_score,
            "timestamp": str(a.timestamp)
        }
        for a in alerts
    ]

# -------------------------
# RISK TREND
# -------------------------
@app.get("/risk-trend")
def risk_trend(db: Session = Depends(get_db)):

    alerts = db.query(models.Alert).order_by(
        models.Alert.timestamp.desc()
    ).limit(10).all()

    alerts.reverse()

    return [
        {"time": str(a.timestamp)[11:19], "risk": a.risk_score}
        for a in alerts
    ]
