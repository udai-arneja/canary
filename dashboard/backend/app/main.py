from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from contextlib import asynccontextmanager
import uvicorn
from typing import List, Dict, Any
import json
from datetime import datetime, timedelta

from app.database import init_db, get_db
from app.models import Attack, Vulnerability, Website
from app.schemas import AttackCreate, AttackResponse, StatsResponse, RiskForecast
from app.forecasting import RiskForecaster
from app.agent_detection import AgentDetector

# Global connections manager for WebSockets
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except:
                pass

manager = ConnectionManager()
forecaster = RiskForecaster()
agent_detector = AgentDetector()

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    init_db()
    yield
    # Shutdown
    pass

app = FastAPI(
    title="AI Cyber Attack Monitoring Dashboard",
    description="Real-time monitoring and risk forecasting for AI cyber attacks",
    version="1.0.0",
    lifespan=lifespan
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
async def root():
    return {"message": "AI Cyber Attack Monitoring API"}

@app.post("/api/attacks", response_model=AttackResponse)
async def create_attack(attack: AttackCreate):
    """Receive attack data from honeypots via REST API or webhook"""
    db = next(get_db())
    
    try:
        # Create attack record
        db_attack = Attack(
            timestamp=attack.timestamp or datetime.utcnow(),
            website_url=attack.website_url,
            vulnerability_type=attack.vulnerability_type,
            attack_vector=attack.attack_vector,
            success=attack.success,
            payload=attack.payload,
            source_ip=attack.source_ip,
            user_agent=attack.user_agent,
            response_code=attack.response_code
        )
        
        db.add(db_attack)
        db.commit()
        db.refresh(db_attack)
        
        # Analyze for autonomous agent indicators
        agent_indicators = agent_detector.analyze_attack(db_attack)
        
        # Broadcast to WebSocket clients
        attack_data = {
            "id": db_attack.id,
            "timestamp": db_attack.timestamp.isoformat(),
            "website_url": db_attack.website_url,
            "vulnerability_type": db_attack.vulnerability_type,
            "attack_vector": db_attack.attack_vector,
            "success": db_attack.success,
            "source_ip": db_attack.source_ip,
            "agent_indicators": agent_indicators.dict()
        }
        await manager.broadcast({"type": "new_attack", "data": attack_data})
        
        return AttackResponse(
            id=db_attack.id,
            timestamp=db_attack.timestamp,
            website_url=db_attack.website_url,
            vulnerability_type=db_attack.vulnerability_type,
            attack_vector=db_attack.attack_vector,
            success=db_attack.success,
            payload=db_attack.payload,
            source_ip=db_attack.source_ip,
            user_agent=db_attack.user_agent,
            response_code=db_attack.response_code,
            agent_indicators=agent_indicators
        )
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        db.close()

@app.get("/api/attacks", response_model=List[AttackResponse])
async def get_attacks(limit: int = 100, offset: int = 0):
    """Get recent attacks"""
    db = next(get_db())
    try:
        attacks = db.query(Attack).order_by(Attack.timestamp.desc()).offset(offset).limit(limit).all()
        result = []
        for attack in attacks:
            agent_indicators = agent_detector.analyze_attack(attack)
            result.append(AttackResponse(
                id=attack.id,
                timestamp=attack.timestamp,
                website_url=attack.website_url,
                vulnerability_type=attack.vulnerability_type,
                attack_vector=attack.attack_vector,
                success=attack.success,
                payload=attack.payload,
                source_ip=attack.source_ip,
                user_agent=attack.user_agent,
                response_code=attack.response_code,
                agent_indicators=agent_indicators
            ))
        return result
    finally:
        db.close()

@app.get("/api/stats", response_model=StatsResponse)
async def get_stats():
    """Get comprehensive statistics"""
    db = next(get_db())
    
    try:
        # Total attacks
        total_attacks = db.query(Attack).count()
        
        # Attacks in different time windows
        now = datetime.utcnow()
        attacks_24h = db.query(Attack).filter(Attack.timestamp >= now - timedelta(hours=24)).count()
        attacks_7d = db.query(Attack).filter(Attack.timestamp >= now - timedelta(days=7)).count()
        attacks_30d = db.query(Attack).filter(Attack.timestamp >= now - timedelta(days=30)).count()
        
        # Successful vs failed attacks
        successful_attacks = db.query(Attack).filter(Attack.success == True).count()
        failed_attacks = total_attacks - successful_attacks
        
        # Websites attacked
        websites_attacked = db.query(Attack.website_url).distinct().count()
        
        # Vulnerabilities successfully attacked
        successful_vulns = db.query(Attack.vulnerability_type).filter(
            Attack.success == True
        ).distinct().all()
        successful_vulns = [v[0] for v in successful_vulns]
        
        # Vulnerabilities attacked but failed
        failed_vulns = db.query(Attack.vulnerability_type).filter(
            Attack.success == False
        ).distinct().all()
        failed_vulns = [v[0] for v in failed_vulns]
        
        # Attack vectors
        from sqlalchemy import func
        attack_vectors = db.query(Attack.attack_vector, func.count(Attack.id)).group_by(
            Attack.attack_vector
        ).all()
        
        # Attacks per website
        website_stats = db.query(
            Attack.website_url,
            func.count(Attack.id).label('count'),
            func.sum(func.cast(Attack.success, func.Integer)).label('successful')
        ).group_by(Attack.website_url).all()
        
        # Vulnerability success rates
        vuln_stats = db.query(
            Attack.vulnerability_type,
            func.count(Attack.id).label('total'),
            func.sum(func.cast(Attack.success, func.Integer)).label('successful')
        ).group_by(Attack.vulnerability_type).all()
        
        # Time series data (last 24 hours, hourly buckets)
        time_series = []
        for i in range(24):
            hour_start = now - timedelta(hours=i+1)
            hour_end = now - timedelta(hours=i)
            count = db.query(Attack).filter(
                Attack.timestamp >= hour_start,
                Attack.timestamp < hour_end
            ).count()
            time_series.append({
                "timestamp": hour_start.isoformat(),
                "count": count
            })
        time_series.reverse()
        
        return StatsResponse(
            total_attacks=total_attacks,
            attacks_24h=attacks_24h,
            attacks_7d=attacks_7d,
            attacks_30d=attacks_30d,
            successful_attacks=successful_attacks,
            failed_attacks=failed_attacks,
            websites_attacked=websites_attacked,
            successful_vulnerabilities=successful_vulns,
            failed_vulnerabilities=failed_vulns,
            attack_vectors=[{"vector": v[0], "count": v[1]} for v in attack_vectors],
            website_stats=[{"url": w[0], "total": w[1], "successful": w[2] or 0} for w in website_stats],
            vulnerability_stats=[{"type": v[0], "total": v[1], "successful": v[2] or 0} for v in vuln_stats],
            time_series=time_series
        )
    finally:
        db.close()

@app.get("/api/risk-forecast", response_model=RiskForecast)
async def get_risk_forecast():
    """Get risk trajectory and forecasting"""
    db = next(get_db())
    try:
        attacks = db.query(Attack).order_by(Attack.timestamp.asc()).all()
        forecast = forecaster.generate_forecast(attacks)
        return forecast
    finally:
        db.close()

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            # Keep connection alive and handle any client messages
            data = await websocket.receive_text()
            # Echo back or handle commands
            await websocket.send_json({"type": "pong", "data": json.loads(data) if data else {}})
    except WebSocketDisconnect:
        manager.disconnect(websocket)

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)

