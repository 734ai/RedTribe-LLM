"""
Real-time WebSocket integration for live threat monitoring
"""

from fastapi import WebSocket, WebSocketDisconnect
import asyncio
import json
from datetime import datetime
from typing import Dict, List
import random
import logging

class ConnectionManager:
    """Manage WebSocket connections for real-time updates"""
    
    def __init__(self):
        self.active_connections: List[WebSocket] = []
        self.logger = logging.getLogger(__name__)
    
    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        self.logger.info(f"New WebSocket connection: {len(self.active_connections)} total")
    
    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
        self.logger.info(f"WebSocket disconnected: {len(self.active_connections)} remaining")
    
    async def send_personal_message(self, message: str, websocket: WebSocket):
        try:
            await websocket.send_text(message)
        except Exception as e:
            self.logger.error(f"Failed to send personal message: {e}")
            self.disconnect(websocket)
    
    async def broadcast(self, message: str):
        """Broadcast message to all connected clients"""
        disconnected = []
        for connection in self.active_connections:
            try:
                await connection.send_text(message)
            except Exception as e:
                self.logger.error(f"Failed to broadcast to connection: {e}")
                disconnected.append(connection)
        
        # Clean up disconnected clients
        for connection in disconnected:
            self.disconnect(connection)

# Global connection manager
manager = ConnectionManager()

class ThreatFeedSimulator:
    """Simulate real-time threat intelligence feeds"""
    
    def __init__(self):
        self.threat_types = [
            "malware_detection",
            "network_intrusion", 
            "data_exfiltration",
            "brute_force_attack",
            "ddos_attempt",
            "suspicious_login",
            "privilege_escalation",
            "lateral_movement"
        ]
        
        self.threat_sources = [
            "firewall_logs",
            "ids_sensor",
            "endpoint_detection",
            "network_monitor", 
            "email_security",
            "web_filter",
            "dns_monitor",
            "user_behavior"
        ]
        
        self.severity_levels = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
        
    def generate_threat_event(self) -> Dict:
        """Generate a simulated threat event"""
        
        return {
            "event_id": f"evt_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{random.randint(1000, 9999)}",
            "timestamp": datetime.now().isoformat(),
            "threat_type": random.choice(self.threat_types),
            "source": random.choice(self.threat_sources),
            "severity": random.choice(self.severity_levels),
            "confidence": round(random.uniform(0.3, 0.95), 2),
            "source_ip": f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}",
            "target_ip": f"192.168.1.{random.randint(1, 254)}",
            "details": self._generate_threat_details(),
            "status": "active"
        }
    
    def _generate_threat_details(self) -> Dict:
        """Generate detailed threat information"""
        
        return {
            "attack_vector": random.choice([
                "network_based",
                "email_based", 
                "web_based",
                "endpoint_based",
                "social_engineering"
            ]),
            "mitre_technique": f"T{random.randint(1001, 1609)}",
            "indicators": [
                f"suspicious_process_{random.randint(1, 100)}.exe",
                f"malicious_domain_{random.randint(1, 50)}.com",
                f"unusual_network_traffic_port_{random.randint(1024, 65535)}"
            ],
            "recommendation": "Investigate immediately and implement containment measures"
        }

# Global threat feed simulator
threat_simulator = ThreatFeedSimulator()

async def threat_feed_worker():
    """Background worker that generates and broadcasts threat events"""
    
    while True:
        if manager.active_connections:
            # Generate threat event
            threat_event = threat_simulator.generate_threat_event()
            
            # Broadcast to all connected clients
            await manager.broadcast(json.dumps({
                "type": "threat_event",
                "data": threat_event
            }))
            
            # Log the event
            logging.getLogger(__name__).info(f"Broadcast threat event: {threat_event['event_id']}")
        
        # Wait before next event (simulate real-time frequency)
        await asyncio.sleep(random.uniform(2, 8))  # 2-8 seconds between events

class ThreatMonitor:
    """Advanced threat monitoring with analytics"""
    
    def __init__(self):
        self.active_threats: List[Dict] = []
        self.threat_history: List[Dict] = []
        self.alert_thresholds = {
            "CRITICAL": 1,  # Alert immediately
            "HIGH": 3,      # Alert after 3 events
            "MEDIUM": 10,   # Alert after 10 events  
            "LOW": 50       # Alert after 50 events
        }
        
    def process_threat_event(self, event: Dict) -> Dict:
        """Process and analyze threat event"""
        
        # Add to active threats
        self.active_threats.append(event)
        self.threat_history.append(event)
        
        # Analyze trends
        analysis = self._analyze_threat_trends()
        
        # Generate alerts if needed
        alerts = self._check_alert_conditions(event)
        
        return {
            "event": event,
            "analysis": analysis,
            "alerts": alerts,
            "statistics": self._generate_statistics()
        }
    
    def _analyze_threat_trends(self) -> Dict:
        """Analyze current threat trends"""
        
        if len(self.threat_history) < 2:
            return {"trend": "insufficient_data"}
        
        recent_events = self.threat_history[-10:]  # Last 10 events
        
        # Count by severity
        severity_counts = {}
        for event in recent_events:
            severity = event["severity"]
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        # Calculate trend
        critical_high_ratio = (severity_counts.get("CRITICAL", 0) + severity_counts.get("HIGH", 0)) / len(recent_events)
        
        if critical_high_ratio > 0.5:
            trend = "escalating"
        elif critical_high_ratio > 0.2:
            trend = "elevated" 
        else:
            trend = "normal"
        
        return {
            "trend": trend,
            "critical_high_ratio": round(critical_high_ratio, 2),
            "severity_distribution": severity_counts,
            "total_recent_events": len(recent_events)
        }
    
    def _check_alert_conditions(self, event: Dict) -> List[Dict]:
        """Check if alerts should be triggered"""
        
        alerts = []
        severity = event["severity"]
        
        # Count recent events of same severity
        recent_same_severity = [
            e for e in self.threat_history[-100:]  # Last 100 events
            if e["severity"] == severity
        ]
        
        threshold = self.alert_thresholds.get(severity, 10)
        
        if len(recent_same_severity) >= threshold:
            alerts.append({
                "type": f"{severity.lower()}_threshold_alert",
                "message": f"Threshold exceeded: {len(recent_same_severity)} {severity} events detected",
                "severity": severity,
                "recommended_action": self._get_recommended_action(severity)
            })
        
        return alerts
    
    def _get_recommended_action(self, severity: str) -> str:
        """Get recommended action based on severity"""
        
        actions = {
            "CRITICAL": "Initiate emergency response procedures immediately",
            "HIGH": "Escalate to security team and begin investigation",
            "MEDIUM": "Increase monitoring and prepare for potential escalation",
            "LOW": "Document and continue routine monitoring"
        }
        
        return actions.get(severity, "Review and assess threat significance")
    
    def _generate_statistics(self) -> Dict:
        """Generate current threat statistics"""
        
        total_active = len(self.active_threats)
        total_history = len(self.threat_history)
        
        if total_history == 0:
            return {"total_events": 0}
        
        # Calculate statistics
        severity_stats = {}
        for event in self.threat_history:
            severity = event["severity"]
            severity_stats[severity] = severity_stats.get(severity, 0) + 1
        
        return {
            "total_events": total_history,
            "active_threats": total_active,
            "severity_distribution": severity_stats,
            "average_confidence": round(
                sum(e["confidence"] for e in self.threat_history) / total_history, 2
            )
        }

# Global threat monitor
threat_monitor = ThreatMonitor()
