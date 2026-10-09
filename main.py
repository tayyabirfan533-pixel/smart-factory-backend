from datetime import datetime, timedelta
from typing import Optional
import os, json, asyncio, hashlib, secrets, statistics

from fastapi import FastAPI, Depends, HTTPException, WebSocket, WebSocketDisconnect, Query
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import jwt, JWTError
from pydantic import BaseModel, Field
from sqlalchemy import create_engine, Column, Integer, String, Float, Boolean, DateTime, ForeignKey, Text
from sqlalchemy.orm import declarative_base, sessionmaker, Session
from dotenv import load_dotenv

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./factory.db")
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

engine_args = {"connect_args": {"check_same_thread": False}} if DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(DATABASE_URL, **engine_args)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()

SECRET_KEY = os.getenv("SECRET_KEY", "change-this-secret-before-deployment")
ALGORITHM = "HS256"
TOKEN_MINUTES = 1440
security = HTTPBearer(auto_error=False)

app = FastAPI(title="Smart Factory Monitoring API", version="1.0.0")
clients = set()
recent_readings = {}

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), nullable=False)
    email = Column(String(255), unique=True, index=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    role = Column(String(30), default="operator")
    created_at = Column(DateTime, default=datetime.utcnow)

class Machine(Base):
    __tablename__ = "machines"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(120), nullable=False)
    location = Column(String(200), default="")
    description = Column(Text, default="")
    status = Column(String(30), default="online")
    temp_warning = Column(Float, default=80)
    temp_critical = Column(Float, default=100)
    pressure_warning = Column(Float, default=100)
    pressure_critical = Column(Float, default=130)
    vibration_warning = Column(Float, default=8)
    vibration_critical = Column(Float, default=12)
    power_warning = Column(Float, default=90)
    power_critical = Column(Float, default=100)
    last_seen = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

class Reading(Base):
    __tablename__ = "readings"
    id = Column(Integer, primary_key=True, index=True)
    machine_id = Column(Integer, ForeignKey("machines.id"), index=True)
    temperature = Column(Float, nullable=False)
    pressure = Column(Float, nullable=False)
    vibration = Column(Float, nullable=False)
    power_consumption = Column(Float, nullable=False)
    machine_status = Column(String(30), default="running")
    anomaly = Column(Boolean, default=False)
    recorded_at = Column(DateTime, default=datetime.utcnow, index=True)

class Alert(Base):
    __tablename__ = "alerts"
    id = Column(Integer, primary_key=True, index=True)
    machine_id = Column(Integer, ForeignKey("machines.id"), index=True)
    severity = Column(String(20), nullable=False)
    message = Column(String(500), nullable=False)
    status = Column(String(20), default="open", index=True)
    acknowledged_by = Column(String(255), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    acknowledged_at = Column(DateTime, nullable=True)
    resolved_at = Column(DateTime, nullable=True)

class Maintenance(Base):
    __tablename__ = "maintenance"
    id = Column(Integer, primary_key=True, index=True)
    machine_id = Column(Integer, ForeignKey("machines.id"), index=True)
    title = Column(String(200), nullable=False)
    details = Column(Text, default="")
    performed_by = Column(String(255), default="")
    maintenance_date = Column(DateTime, default=datetime.utcnow)
    next_due = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def hash_password(password):
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 200000).hex()
    return f"{salt}${digest}"

def verify_password(password, stored):
    try:
        salt, digest = stored.split("$", 1)
        candidate = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 200000).hex()
        return secrets.compare_digest(candidate, digest)
    except Exception:
        return False

def create_token(user):
    payload = {
        "sub": str(user.id),
        "email": user.email,
        "role": user.role,
        "exp": datetime.utcnow() + timedelta(minutes=TOKEN_MINUTES)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

def current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
    db: Session = Depends(get_db)
):
    if not credentials:
        raise HTTPException(status_code=401, detail="Bearer token required")
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = int(payload["sub"])
    except (JWTError, ValueError, KeyError):
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user

def admin_only(user=Depends(current_user)):
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin role required")
    return user

def machine_or_404(db, machine_id):
    machine = db.query(Machine).filter(Machine.id == machine_id).first()
    if not machine:
        raise HTTPException(status_code=404, detail="Machine not found")
    return machine

def machine_dict(m):
    return {
        "id": m.id, "name": m.name, "location": m.location,
        "description": m.description, "status": m.status,
        "last_seen": m.last_seen, "created_at": m.created_at,
        "thresholds": {
            "temperature": {"warning": m.temp_warning, "critical": m.temp_critical},
            "pressure": {"warning": m.pressure_warning, "critical": m.pressure_critical},
            "vibration": {"warning": m.vibration_warning, "critical": m.vibration_critical},
            "power_consumption": {"warning": m.power_warning, "critical": m.power_critical}
        }
    }

def reading_dict(r):
    return {
        "id": r.id, "machine_id": r.machine_id,
        "temperature": r.temperature, "pressure": r.pressure,
        "vibration": r.vibration, "power_consumption": r.power_consumption,
        "machine_status": r.machine_status, "anomaly": r.anomaly,
        "recorded_at": r.recorded_at
    }

def alert_dict(a):
    return {
        "id": a.id, "machine_id": a.machine_id, "severity": a.severity,
        "message": a.message, "status": a.status,
        "acknowledged_by": a.acknowledged_by, "created_at": a.created_at,
        "acknowledged_at": a.acknowledged_at, "resolved_at": a.resolved_at
    }

async def broadcast(event):
    dead = set()
    message = json.dumps(event, default=str)
    for ws in list(clients):
        try:
            await ws.send_text(message)
        except Exception:
            dead.add(ws)
    clients.difference_update(dead)

class RegisterIn(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    email: str
    password: str = Field(min_length=8, max_length=128)

class LoginIn(BaseModel):
    email: str
    password: str

class MachineIn(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    location: str = ""
    description: str = ""

class ThresholdIn(BaseModel):
    temp_warning: float = 80
    temp_critical: float = 100
    pressure_warning: float = 100
    pressure_critical: float = 130
    vibration_warning: float = 8
    vibration_critical: float = 12
    power_warning: float = 90
    power_critical: float = 100

class ReadingIn(BaseModel):
    temperature: float = Field(ge=0)
    pressure: float = Field(ge=0)
    vibration: float = Field(ge=0)
    power_consumption: float = Field(ge=0)
    machine_status: str = "running"

class MaintenanceIn(BaseModel):
    title: str = Field(min_length=1, max_length=200)
    details: str = ""
    performed_by: str = ""
    maintenance_date: Optional[datetime] = None
    next_due: Optional[datetime] = None

@app.get("/")
def root():
    return {"message": "Smart Factory Monitoring API", "docs": "/docs", "health": "/health"}

@app.get("/health")
def health():
    return {"status": "ok", "service": "smart-factory-backend"}

@app.post("/api/auth/register")
def register(data: RegisterIn, db: Session = Depends(get_db)):
    email = data.email.strip().lower()
    if db.query(User).filter(User.email == email).first():
        raise HTTPException(status_code=409, detail="Email already registered")
    admin_email = os.getenv("ADMIN_EMAIL", "").strip().lower()
    role = "admin" if admin_email and email == admin_email else "operator"
    user = User(name=data.name.strip(), email=email, password_hash=hash_password(data.password), role=role)
    db.add(user)
    db.commit()
    db.refresh(user)
    return {"message": "Registered successfully", "user": {"id": user.id, "name": user.name, "email": user.email, "role": user.role}, "access_token": create_token(user), "token_type": "bearer"}

@app.post("/api/auth/login")
def login(data: LoginIn, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == data.email.strip().lower()).first()
    if not user or not verify_password(data.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    return {"access_token": create_token(user), "token_type": "bearer", "user": {"id": user.id, "name": user.name, "email": user.email, "role": user.role}}

@app.get("/api/me")
def me(user=Depends(current_user)):
    return {"id": user.id, "name": user.name, "email": user.email, "role": user.role}

@app.post("/api/machines")
async def create_machine(data: MachineIn, db: Session = Depends(get_db), user=Depends(current_user)):
    machine = Machine(name=data.name, location=data.location, description=data.description)
    db.add(machine)
    db.commit()
    db.refresh(machine)
    result = machine_dict(machine)
    await broadcast({"type": "machine_created", "machine": result})
    return result

@app.get("/api/machines")
def list_machines(
    search: Optional[str] = None,
    status: Optional[str] = None,
    page: int = Query(1, ge=1),
    limit: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db), user=Depends(current_user)
):
    q = db.query(Machine)
    if search:
        q = q.filter((Machine.name.ilike(f"%{search}%")) | (Machine.location.ilike(f"%{search}%")))
    if status:
        q = q.filter(Machine.status == status)
    total = q.count()
    items = q.order_by(Machine.id.desc()).offset((page - 1) * limit).limit(limit).all()
    return {"items": [machine_dict(m) for m in items], "total": total, "page": page, "limit": limit}

@app.get("/api/machines/{machine_id}")
def get_machine(machine_id: int, db: Session = Depends(get_db), user=Depends(current_user)):
    m = machine_or_404(db, machine_id)
    latest = db.query(Reading).filter(Reading.machine_id == machine_id).order_by(Reading.id.desc()).first()
    return {**machine_dict(m), "latest_reading": reading_dict(latest) if latest else None}

@app.patch("/api/machines/{machine_id}/thresholds")
def set_thresholds(machine_id: int, data: ThresholdIn, db: Session = Depends(get_db), user=Depends(admin_only)):
    m = machine_or_404(db, machine_id)
    if data.temp_warning >= data.temp_critical or data.pressure_warning >= data.pressure_critical or data.vibration_warning >= data.vibration_critical or data.power_warning >= data.power_critical:
        raise HTTPException(status_code=400, detail="Each warning threshold must be lower than its critical threshold")
    for key, value in data.model_dump().items():
        setattr(m, key, value)
    db.commit()
    db.refresh(m)
    return machine_dict(m)

def detect_anomaly(machine_id, values, db):
    history = recent_readings.get(machine_id, [])
    if len(history) < 5:
        rows = db.query(Reading).filter(Reading.machine_id == machine_id).order_by(Reading.id.desc()).limit(10).all()
        history = [{k: getattr(r, k) for k in values} for r in reversed(rows)]
    anomalous = False
    for key, value in values.items():
        series = [float(x[key]) for x in history if key in x]
        if len(series) >= 5:
            mean = statistics.mean(series)
            sd = statistics.pstdev(series)
            if sd > 0 and abs(value - mean) > 3 * sd:
                anomalous = True
    recent_readings.setdefault(machine_id, []).append(values)
    recent_readings[machine_id] = recent_readings[machine_id][-20:]
    return anomalous

@app.post("/api/machines/{machine_id}/readings")
async def ingest_reading(machine_id: int, data: ReadingIn, db: Session = Depends(get_db), user=Depends(current_user)):
    machine = machine_or_404(db, machine_id)
    values = {
        "temperature": data.temperature, "pressure": data.pressure,
        "vibration": data.vibration, "power_consumption": data.power_consumption
    }
    anomaly = detect_anomaly(machine_id, values, db)
    reading = Reading(machine_id=machine_id, **values, machine_status=data.machine_status, anomaly=anomaly)
    machine.last_seen = datetime.utcnow()
    machine.status = "online"
    db.add(reading)
    db.flush()

    limits = {
        "temperature": (machine.temp_warning, machine.temp_critical),
        "pressure": (machine.pressure_warning, machine.pressure_critical),
        "vibration": (machine.vibration_warning, machine.vibration_critical),
        "power_consumption": (machine.power_warning, machine.power_critical)
    }
    generated = []
    for key, value in values.items():
        warning, critical = limits[key]
        severity = "critical" if value >= critical else "warning" if value >= warning else None
        if severity:
            message = f"{key.replace('_', ' ').title()} is {value}; {severity} threshold is {critical if severity == 'critical' else warning}"
            alert = Alert(machine_id=machine_id, severity=severity, message=message)
            db.add(alert)
            db.flush()
            generated.append(alert_dict(alert))

    if anomaly:
        alert = Alert(machine_id=machine_id, severity="warning", message="Possible sensor anomaly detected from recent readings")
        db.add(alert)
        db.flush()
        generated.append(alert_dict(alert))

    db.commit()
    db.refresh(reading)
    result = reading_dict(reading)
    await broadcast({"type": "sensor_update", "machine_id": machine_id, "reading": result})
    for alert in generated:
        await broadcast({"type": "alert", "alert": alert})
    await broadcast({"type": "machine_status", "machine_id": machine_id, "status": machine.status})
    return {"reading": result, "alerts_generated": generated}

@app.get("/api/machines/{machine_id}/readings")
def get_readings(
    machine_id: int, page: int = Query(1, ge=1), limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db), user=Depends(current_user)
):
    machine_or_404(db, machine_id)
    q = db.query(Reading).filter(Reading.machine_id == machine_id)
    total = q.count()
    rows = q.order_by(Reading.id.desc()).offset((page - 1) * limit).limit(limit).all()
    return {"items": [reading_dict(r) for r in rows], "total": total, "page": page, "limit": limit}

@app.get("/api/alerts")
def list_alerts(
    status: Optional[str] = None, severity: Optional[str] = None,
    machine_id: Optional[int] = None, page: int = Query(1, ge=1),
    limit: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db), user=Depends(current_user)
):
    q = db.query(Alert)
    if status:
        q = q.filter(Alert.status == status)
    if severity:
        q = q.filter(Alert.severity == severity)
    if machine_id:
        q = q.filter(Alert.machine_id == machine_id)
    total = q.count()
    rows = q.order_by(Alert.id.desc()).offset((page - 1) * limit).limit(limit).all()
    return {"items": [alert_dict(a) for a in rows], "total": total, "page": page, "limit": limit}

@app.post("/api/alerts/{alert_id}/acknowledge")
async def acknowledge_alert(alert_id: int, db: Session = Depends(get_db), user=Depends(current_user)):
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    if alert.status == "resolved":
        raise HTTPException(status_code=400, detail="Resolved alert cannot be acknowledged")
    alert.status = "acknowledged"
    alert.acknowledged_by = user.email
    alert.acknowledged_at = datetime.utcnow()
    db.commit()
    db.refresh(alert)
    result = alert_dict(alert)
    await broadcast({"type": "alert_updated", "alert": result})
    return result

@app.post("/api/alerts/{alert_id}/resolve")
async def resolve_alert(alert_id: int, db: Session = Depends(get_db), user=Depends(current_user)):
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    alert.status = "resolved"
    alert.resolved_at = datetime.utcnow()
    db.commit()
    db.refresh(alert)
    result = alert_dict(alert)
    await broadcast({"type": "alert_updated", "alert": result})
    return result

@app.post("/api/machines/{machine_id}/maintenance")
def add_maintenance(machine_id: int, data: MaintenanceIn, db: Session = Depends(get_db), user=Depends(current_user)):
    machine_or_404(db, machine_id)
    record = Maintenance(
        machine_id=machine_id, title=data.title, details=data.details,
        performed_by=data.performed_by or user.email,
        maintenance_date=data.maintenance_date or datetime.utcnow(), next_due=data.next_due
    )
    db.add(record)
    db.commit()
    db.refresh(record)
    return {"id": record.id, "machine_id": record.machine_id, "title": record.title, "details": record.details, "performed_by": record.performed_by, "maintenance_date": record.maintenance_date, "next_due": record.next_due}

@app.get("/api/machines/{machine_id}/maintenance")
def get_maintenance(machine_id: int, page: int = Query(1, ge=1), limit: int = Query(20, ge=1, le=100), db: Session = Depends(get_db), user=Depends(current_user)):
    machine_or_404(db, machine_id)
    q = db.query(Maintenance).filter(Maintenance.machine_id == machine_id)
    total = q.count()
    rows = q.order_by(Maintenance.id.desc()).offset((page - 1) * limit).limit(limit).all()
    return {"items": [{"id": r.id, "machine_id": r.machine_id, "title": r.title, "details": r.details, "performed_by": r.performed_by, "maintenance_date": r.maintenance_date, "next_due": r.next_due} for r in rows], "total": total, "page": page, "limit": limit}

@app.get("/api/analytics")
def analytics(db: Session = Depends(get_db), user=Depends(current_user)):
    readings = db.query(Reading).all()
    machines = db.query(Machine).all()
    alerts = db.query(Alert).all()
    keys = ["temperature", "pressure", "vibration", "power_consumption"]
    averages = {k: round(statistics.mean([getattr(r, k) for r in readings]), 2) if readings else 0 for k in keys}
    total_alerts = len(alerts)
    uptime = round(100 * sum(1 for m in machines if m.status == "online") / len(machines), 2) if machines else 0
    return {
        "machine_count": len(machines),
        "online_machines": sum(1 for m in machines if m.status == "online"),
        "offline_machines": sum(1 for m in machines if m.status == "offline"),
        "average_sensor_readings": averages,
        "uptime_percent": uptime,
        "alert_frequency": {"total": total_alerts, "warning": sum(1 for a in alerts if a.severity == "warning"), "critical": sum(1 for a in alerts if a.severity == "critical"), "open": sum(1 for a in alerts if a.status == "open"), "acknowledged": sum(1 for a in alerts if a.status == "acknowledged"), "resolved": sum(1 for a in alerts if a.status == "resolved")},
        "anomaly_count": sum(1 for r in readings if r.anomaly),
        "machine_health": [{"machine_id": m.id, "name": m.name, "status": m.status, "health_score": max(0, 100 - 15 * db.query(Alert).filter(Alert.machine_id == m.id, Alert.status == "open", Alert.severity == "critical").count() - 5 * db.query(Alert).filter(Alert.machine_id == m.id, Alert.status == "open", Alert.severity == "warning").count())} for m in machines]
    }

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    clients.add(websocket)
    try:
        await websocket.send_json({"type": "connected", "message": "Live factory updates connected"})
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        clients.discard(websocket)
    except Exception:
        clients.discard(websocket)

async def offline_monitor():
    while True:
        try:
            db = SessionLocal()
            cutoff = datetime.utcnow() - timedelta(seconds=120)
            machines = db.query(Machine).filter(Machine.status == "online", Machine.last_seen != None, Machine.last_seen < cutoff).all()
            changed = []
            for machine in machines:
                machine.status = "offline"
                changed.append(machine.id)
            if changed:
                db.commit()
                for machine_id in changed:
                    await broadcast({"type": "machine_status", "machine_id": machine_id, "status": "offline"})
            db.close()
        except Exception:
            pass
        await asyncio.sleep(30)

@app.on_event("startup")
async def startup_event():
    asyncio.create_task(offline_monitor())

