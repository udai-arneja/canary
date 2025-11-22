from app.models import Attack
from app.schemas import AgentIndicators
from sqlalchemy.orm import Session
from app.database import SessionLocal
from datetime import datetime, timedelta
from typing import List
import statistics

class AgentDetector:
    """Detect autonomous AI agent indicators in attacks"""
    
    def analyze_attack(self, attack: Attack) -> AgentIndicators:
        """Analyze a single attack for autonomous agent indicators"""
        db = SessionLocal()
        indicators = []
        
        try:
            # Get recent attacks from same source
            recent_window = attack.timestamp - timedelta(minutes=5)
            recent_attacks = db.query(Attack).filter(
                Attack.source_ip == attack.source_ip,
                Attack.timestamp >= recent_window,
                Attack.timestamp <= attack.timestamp
            ).order_by(Attack.timestamp.asc()).all()
            
            # Speed analysis: rapid successive attacks
            speed_score = 0.0
            if len(recent_attacks) > 1:
                time_diffs = []
                for i in range(1, len(recent_attacks)):
                    diff = (recent_attacks[i].timestamp - recent_attacks[i-1].timestamp).total_seconds()
                    time_diffs.append(diff)
                
                if time_diffs:
                    avg_time = statistics.mean(time_diffs)
                    # Very fast attacks (< 1 second) suggest automation
                    if avg_time < 1.0:
                        speed_score = 1.0
                        indicators.append("Extremely rapid attack sequence")
                    elif avg_time < 5.0:
                        speed_score = 0.7
                        indicators.append("Rapid attack sequence")
                    elif avg_time < 30.0:
                        speed_score = 0.4
                        indicators.append("Fast attack sequence")
            
            # Pattern analysis: systematic exploration
            pattern_score = 0.0
            if len(recent_attacks) > 2:
                # Check for systematic vulnerability testing
                vuln_types = [a.vulnerability_type for a in recent_attacks]
                unique_vulns = len(set(vuln_types))
                total_attacks = len(vuln_types)
                
                # High diversity in short time suggests systematic scanning
                if unique_vulns / total_attacks > 0.7 and total_attacks > 3:
                    pattern_score = 0.8
                    indicators.append("Systematic vulnerability exploration")
                
                # Check for methodical website targeting
                websites = [a.website_url for a in recent_attacks]
                if len(set(websites)) > 1:
                    pattern_score = max(pattern_score, 0.6)
                    indicators.append("Multi-target systematic approach")
            
            # Coordination analysis: multiple IPs, similar patterns
            coordination_score = 0.0
            # Check for similar attack patterns from different IPs in short time
            similar_attacks = db.query(Attack).filter(
                Attack.vulnerability_type == attack.vulnerability_type,
                Attack.attack_vector == attack.attack_vector,
                Attack.timestamp >= recent_window,
                Attack.timestamp <= attack.timestamp
            ).all()
            
            unique_ips = len(set([a.source_ip for a in similar_attacks if a.source_ip]))
            if unique_ips > 3:
                coordination_score = 0.7
                indicators.append("Coordinated multi-source attack pattern")
            elif unique_ips > 1:
                coordination_score = 0.4
                indicators.append("Multiple sources with similar patterns")
            
            # User agent analysis
            if attack.user_agent:
                ua_lower = attack.user_agent.lower()
                if any(bot in ua_lower for bot in ['bot', 'crawler', 'spider', 'scraper']):
                    indicators.append("Bot-like user agent")
                    pattern_score = max(pattern_score, 0.5)
            
            # Payload analysis: sophisticated or generic
            if attack.payload:
                # Check for generic/common attack patterns
                generic_patterns = ['union select', 'script>', 'eval(', 'base64']
                if any(pattern in attack.payload.lower() for pattern in generic_patterns):
                    pattern_score = max(pattern_score, 0.3)
                    indicators.append("Generic attack payload pattern")
            
            # Overall probability (weighted combination)
            overall = (speed_score * 0.3 + pattern_score * 0.4 + coordination_score * 0.3)
            
            if overall > 0.7:
                indicators.append("High probability of autonomous agent")
            elif overall > 0.4:
                indicators.append("Moderate probability of autonomous agent")
            
            return AgentIndicators(
                speed_score=speed_score,
                pattern_score=pattern_score,
                coordination_score=coordination_score,
                overall_agent_probability=overall,
                indicators=indicators if indicators else ["No strong agent indicators"]
            )
            
        finally:
            db.close()

