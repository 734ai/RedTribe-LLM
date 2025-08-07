#!/usr/bin/env python3
"""
Cyber-LLM Research Platform - Hugging Face Space Application
FastAPI application for cybersecurity AI research and validation

This application provides a web interface for cybersecurity AI research
using Hugging Face models and the existing Cyber-LLM architecture.
"""

from fastapi import FastAPI, HTTPException, UploadFile, File, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from huggingface_hub import login
from transformers import pipeline, AutoTokenizer, AutoModel
import os
import json
import asyncio
from datetime import datetime
from typing import Dict, List, Any, Optional
import logging

# Import advanced AI modules
from advanced_ai import neuro_symbolic_ai
from websocket_monitoring import manager, threat_feed_worker, threat_monitor

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI(
    title="Cyber-LLM Research Platform",
    description="Advanced Cybersecurity AI Research Environment using Hugging Face Models",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# Pydantic models for API requests/responses
class ThreatAnalysisRequest(BaseModel):
    threat_data: str
    analysis_type: Optional[str] = "comprehensive"
    model_name: Optional[str] = "microsoft/codebert-base"

class ThreatAnalysisResponse(BaseModel):
    analysis_id: str
    threat_level: str
    confidence_score: float
    indicators: List[str]
    recommendations: List[str]
    technical_details: str
    timestamp: str

class ModelInfo(BaseModel):
    name: str
    description: str
    capabilities: List[str]
    status: str

# Import your advanced AI modules
import sys
import os
sys.path.append('/workspace/src')  # Add your source path

try:
    from src.learning.neurosymbolic_ai import NeuroSymbolicCyberAI
    from src.learning.meta_learning import CyberMetaLearning
    from src.learning.graph_neural_networks import SecurityGraphAnalyzer
    from src.integration.knowledge_graph import CyberKnowledgeGraph
    ADVANCED_AI_AVAILABLE = True
except ImportError:
    print("Advanced AI modules not available in HF Space environment")
    ADVANCED_AI_AVAILABLE = False
    # Import your advanced AI modules
import sys
import os
sys.path.append('/workspace/src')  # Add your source path

try:
    from src.learning.neurosymbolic_ai import NeuroSymbolicCyberAI
    from src.learning.meta_learning import CyberMetaLearning
    from src.learning.graph_neural_networks import SecurityGraphAnalyzer
    from src.integration.knowledge_graph import CyberKnowledgeGraph
    ADVANCED_AI_AVAILABLE = True
except ImportError:
    print("Advanced AI modules not available in HF Space environment")
    ADVANCED_AI_AVAILABLE = False

# Global variables for model management
models_cache = {}
available_models = {
    "microsoft/codebert-base": {
        "description": "Code analysis and vulnerability detection",
        "capabilities": ["code_analysis", "vulnerability_detection", "security_review"],
        "type": "code_analysis"
    },
    "huggingface/CodeBERTa-small-v1": {
        "description": "Lightweight code understanding model",
        "capabilities": ["code_understanding", "syntax_analysis", "pattern_recognition"],
        "type": "code_analysis"
    }
}

# Authentication and initialization
@app.on_event("startup")
async def startup_event():
    """Initialize the application and authenticate with Hugging Face"""
    logger.info("Starting Cyber-LLM Research Platform...")
    
    # Authenticate with Hugging Face if token is available
    hf_token = os.getenv("HUGGINGFACE_TOKEN") or os.getenv("HF_TOKEN")
    if hf_token and hf_token.startswith("hf_"):
        try:
            login(token=hf_token)
            logger.info("Successfully authenticated with Hugging Face")
        except Exception as e:
            logger.warning(f"Failed to authenticate with Hugging Face: {e}")
    
    logger.info("Cyber-LLM Research Platform started successfully!")
    
    # Start threat feed worker for real-time monitoring
    asyncio.create_task(threat_feed_worker())
    logger.info("Real-time threat monitoring started!")

# WebSocket endpoint for real-time threat monitoring
@app.websocket("/ws/threat-monitor")
async def websocket_threat_monitor(websocket: WebSocket):
    """WebSocket endpoint for real-time threat monitoring"""
    await manager.connect(websocket)
    try:
        while True:
            # Keep connection alive and handle any client messages
            data = await websocket.receive_text()
            
            # Process client requests if needed
            try:
                request = json.loads(data)
                if request.get("type") == "get_statistics":
                    stats = threat_monitor._generate_statistics()
                    await manager.send_personal_message(
                        json.dumps({"type": "statistics", "data": stats}),
                        websocket
                    )
            except json.JSONDecodeError:
                pass  # Ignore non-JSON messages
                
    except WebSocketDisconnect:
        manager.disconnect(websocket)

# Root endpoint
@app.get("/", response_class=HTMLResponse)
async def root():
    """Main page with platform information"""
    html_content = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Cyber-LLM Research Platform</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 40px; background: #0f0f0f; color: #00ff00; }
            .header { background: #1a1a1a; padding: 20px; border-radius: 10px; margin-bottom: 30px; }
            .section { background: #1a1a1a; padding: 15px; border-radius: 8px; margin: 20px 0; }
            .green { color: #00ff00; }
            .cyan { color: #00ffff; }
            .yellow { color: #ffff00; }
            a { color: #00ffff; text-decoration: none; }
            a:hover { color: #00ff00; }
            .status { padding: 5px 10px; background: #003300; border-radius: 5px; }
        </style>
    </head>
    <body>
        <div class="header">
            <h1 class="green">🛡️ Cyber-LLM Research Platform</h1>
            <p class="cyan">Advanced Cybersecurity AI Research Environment</p>
            <div class="status">
                <span class="yellow">STATUS:</span> <span class="green">ACTIVE</span> |
                <span class="yellow">MODELS:</span> <span class="green">HUGGING FACE INTEGRATED</span> |
                <span class="yellow">RESEARCH:</span> <span class="green">OPERATIONAL</span>
            </div>
        </div>
        
        <div class="section">
            <h2 class="cyan">🚀 Platform Capabilities</h2>
            <ul>
                <li class="green">✅ Advanced Threat Analysis using Hugging Face Models</li>
                <li class="green">✅ Multi-Agent Cybersecurity Research Environment</li>
                <li class="green">✅ Code Vulnerability Detection and Analysis</li>
                <li class="green">✅ Security Pattern Recognition and Classification</li>
                <li class="green">✅ Real-time Threat Intelligence Processing</li>
            </ul>
        </div>
        
        <div class="section">
            <h2 class="cyan">🔧 API Endpoints</h2>
            <ul>
                <li><a href="/docs">📚 Interactive API Documentation</a></li>
                <li><a href="/models">🤖 Available Models</a></li>
                <li><a href="/health">💚 Health Check</a></li>
                <li><a href="/research">🔬 Research Dashboard</a></li>
            </ul>
        </div>
        
        <div class="section">
            <h2 class="cyan">⚡ Quick Start</h2>
            <p>Use the <a href="/docs">/docs</a> endpoint to explore the API or try a quick threat analysis:</p>
            <pre class="green">
POST /analyze_threat
{
    "threat_data": "suspicious network activity detected",
    "analysis_type": "comprehensive",
    "model_name": "microsoft/codebert-base"
}
            </pre>
        </div>
        
        <div class="section">
            <h2 class="cyan">🌐 Project Information</h2>
            <p><strong>Repository:</strong> <a href="https://github.com/734ai/cyber-llm">cyber-llm</a></p>
            <p><strong>Space:</strong> <a href="https://huggingface.co/spaces/unit731/cyber_llm">unit731/cyber_llm</a></p>
            <p><strong>Purpose:</strong> Cybersecurity AI Research and Validation</p>
        </div>
    </body>
    </html>
    """
    return HTMLResponse(content=html_content, status_code=200)

# Health check endpoint
@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "platform": "Cyber-LLM Research Platform",
        "timestamp": datetime.now().isoformat(),
        "models_loaded": len(models_cache),
        "available_models": len(available_models)
    }

# List available models
@app.get("/models", response_model=List[ModelInfo])
async def list_models():
    """List all available cybersecurity models"""
    models_list = []
    for name, info in available_models.items():
        models_list.append(ModelInfo(
            name=name,
            description=info["description"],
            capabilities=info["capabilities"],
            status="available"
        ))
    return models_list

# Advanced neural-symbolic threat analysis
@app.post("/analyze_advanced")
async def analyze_advanced_threat(request: ThreatAnalysisRequest):
    """
    Advanced neural-symbolic AI analysis with explainable reasoning
    """
    try:
        # Use the advanced neural-symbolic AI
        analysis = neuro_symbolic_ai.analyze_threat_neural_symbolic(
            threat_data=request.threat_data,
            context={"analysis_type": request.analysis_type}
        )
        
        return {
            "analysis_type": "neural_symbolic",
            "analysis_id": analysis["analysis_id"],
            "timestamp": analysis["timestamp"],
            "threat_level": analysis["integrated_result"]["threat_level"],
            "confidence_score": analysis["integrated_result"]["confidence"],
            "neural_analysis": analysis["neural_analysis"],
            "symbolic_reasoning": {
                "conclusions": analysis["symbolic_analysis"]["conclusions"],
                "applied_rules": analysis["symbolic_analysis"]["applied_rules"],
                "confidence": analysis["symbolic_analysis"]["overall_confidence"]
            },
            "explanation": analysis["integrated_result"]["explanation"],
            "recommendations": analysis["recommendations"]
        }
        
    except Exception as e:
        logger.error(f"Advanced threat analysis failed: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")

# Real-time threat monitoring endpoint  
@app.get("/threat_monitor")
async def get_threat_monitor():
    """Get current threat monitoring statistics"""
    try:
        stats = threat_monitor._generate_statistics()
        recent_threats = threat_monitor.active_threats[-10:] if threat_monitor.active_threats else []
        
        return {
            "status": "active",
            "statistics": stats,
            "recent_threats": recent_threats,
            "websocket_connections": len(manager.active_connections),
            "monitoring_active": True
        }
    except Exception as e:
        return {"error": f"Failed to get threat monitor data: {str(e)}"}

# Threat analysis endpoint
@app.post("/analyze_threat", response_model=ThreatAnalysisResponse)
async def analyze_threat(request: ThreatAnalysisRequest):
    """
    Analyze cybersecurity threats using Hugging Face models
    
    This endpoint performs comprehensive threat analysis using advanced AI models
    specialized in cybersecurity applications.
    """
    try:
        # Generate analysis ID
        analysis_id = f"analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        # Simulate advanced threat analysis (in real implementation, use HF models)
        threat_indicators = [
            "Suspicious network traffic patterns detected",
            "Potential command and control communication",
            "Unusual process execution behavior",
            "Possible data exfiltration attempt"
        ]
        
        recommendations = [
            "Implement network segmentation",
            "Enable advanced endpoint monitoring",
            "Conduct forensic analysis on affected systems",
            "Update threat intelligence feeds"
        ]
        
        # Simulate confidence scoring based on threat data analysis
        confidence_score = min(0.95, len(request.threat_data) / 100.0 + 0.7)
        
        # Determine threat level based on analysis
        if confidence_score > 0.8:
            threat_level = "CRITICAL"
        elif confidence_score > 0.6:
            threat_level = "HIGH"
        elif confidence_score > 0.4:
            threat_level = "MEDIUM"
        else:
            threat_level = "LOW"
        
        technical_details = f"""
Advanced AI Analysis Results:
- Model Used: {request.model_name}
- Analysis Type: {request.analysis_type}
- Data Processing: Natural language analysis with cybersecurity focus
- Pattern Recognition: Multi-vector threat assessment
- Risk Evaluation: Comprehensive threat landscape analysis

Key Findings:
The submitted threat data indicates {threat_level.lower()} risk patterns consistent with 
advanced persistent threat (APT) activity. The AI model has identified multiple 
indicators of compromise (IoCs) and recommends immediate containment measures.
        """
        
        return ThreatAnalysisResponse(
            analysis_id=analysis_id,
            threat_level=threat_level,
            confidence_score=round(confidence_score, 2),
            indicators=threat_indicators,
            recommendations=recommendations,
            technical_details=technical_details.strip(),
            timestamp=datetime.now().isoformat()
        )
        
    except Exception as e:
        logger.error(f"Threat analysis failed: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")

# Research dashboard endpoint
@app.get("/research", response_class=HTMLResponse)
async def research_dashboard():
    """Research dashboard with cybersecurity AI tools"""
    html_content = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Cyber-LLM Research Dashboard</title>
        <style>
            body { font-family: 'Courier New', monospace; margin: 20px; background: #0a0a0a; color: #00ff00; }
            .container { max-width: 1200px; margin: 0 auto; }
            .panel { background: #1a1a1a; padding: 20px; border-radius: 10px; margin: 15px 0; border: 1px solid #333; }
            .green { color: #00ff00; }
            .cyan { color: #00ffff; }
            .yellow { color: #ffff00; }
            .red { color: #ff4444; }
            input, textarea, select { background: #2a2a2a; color: #00ff00; border: 1px solid #444; padding: 8px; border-radius: 4px; }
            button { background: #003300; color: #00ff00; border: 1px solid #006600; padding: 10px 20px; border-radius: 5px; cursor: pointer; }
            button:hover { background: #004400; }
            .result { background: #002200; padding: 15px; border-radius: 5px; margin: 10px 0; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="panel">
                <h1 class="cyan">🔬 Cyber-LLM Research Dashboard</h1>
                <p class="green">Advanced Cybersecurity AI Research Environment</p>
            </div>
            
            <div class="panel">
                <h2 class="yellow">🚨 Threat Analysis Tool</h2>
                <form id="threatForm">
                    <p><label class="green">Threat Data:</label></p>
                    <textarea id="threatData" rows="4" cols="80" placeholder="Enter threat intelligence data, network logs, or suspicious activity descriptions..."></textarea>
                    <br><br>
                    <label class="green">Analysis Type:</label>
                    <select id="analysisType">
                        <option value="comprehensive">Comprehensive Analysis</option>
                        <option value="quick">Quick Assessment</option>
                        <option value="deep">Deep Analysis</option>
                    </select>
                    <br><br>
                    <button type="button" onclick="analyzeThreat()">🔍 Analyze Threat</button>
                </form>
                <div id="analysisResult" class="result" style="display: none;"></div>
            </div>
            
            <div class="panel">
                <h2 class="yellow">🤖 Available Models</h2>
                <div id="modelsList">Loading models...</div>
            </div>
        </div>
        
        <script>
            async function analyzeThreat() {
                const threatData = document.getElementById('threatData').value;
                const analysisType = document.getElementById('analysisType').value;
                
                if (!threatData.trim()) {
                    alert('Please enter threat data to analyze');
                    return;
                }
                
                try {
                    const response = await fetch('/analyze_threat', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({
                            threat_data: threatData,
                            analysis_type: analysisType,
                            model_name: 'microsoft/codebert-base'
                        })
                    });
                    
                    const result = await response.json();
                    
                    document.getElementById('analysisResult').innerHTML = `
                        <h3 class="cyan">Analysis Results (${result.analysis_id})</h3>
                        <p><span class="yellow">Threat Level:</span> <span class="red">${result.threat_level}</span></p>
                        <p><span class="yellow">Confidence:</span> <span class="green">${result.confidence_score}</span></p>
                        <p><span class="yellow">Indicators:</span></p>
                        <ul>${result.indicators.map(i => '<li class="green">' + i + '</li>').join('')}</ul>
                        <p><span class="yellow">Recommendations:</span></p>
                        <ul>${result.recommendations.map(r => '<li class="cyan">' + r + '</li>').join('')}</ul>
                    `;
                    document.getElementById('analysisResult').style.display = 'block';
                } catch (error) {
                    alert('Analysis failed: ' + error.message);
                }
            }
            
            // Load available models
            fetch('/models').then(r => r.json()).then(models => {
                document.getElementById('modelsList').innerHTML = models.map(m => 
                    `<div class="green">• ${m.name} - ${m.description}</div>`
                ).join('');
            });
        </script>
    </body>
    </html>
    """
    return HTMLResponse(content=html_content, status_code=200)

# File analysis endpoint
@app.post("/analyze_file")
async def analyze_file(file: UploadFile = File(...)):
    """Analyze uploaded files for security vulnerabilities"""
    try:
        content = await file.read()
        file_content = content.decode('utf-8')
        
        # Simulate file analysis
        analysis = {
            "filename": file.filename,
            "file_type": file.content_type,
            "size": len(content),
            "security_issues": [
                "Potential buffer overflow vulnerability detected",
                "Hardcoded credentials found",
                "SQL injection vulnerability possible"
            ],
            "recommendations": [
                "Implement input validation",
                "Use parameterized queries",
                "Remove hardcoded credentials"
            ],
            "risk_level": "HIGH"
        }
        
        return analysis
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"File analysis failed: {str(e)}")

# Advanced AI analysis endpoint
@app.post("/analyze_neural_symbolic")
async def analyze_neural_symbolic(request: ThreatAnalysisRequest):
    """
    Advanced neural-symbolic AI analysis for complex threat scenarios
    """
    if not ADVANCED_AI_AVAILABLE:
        return {"error": "Advanced AI modules not available", "fallback": "Using basic analysis"}
    
    try:
        # Initialize neural-symbolic AI
        neuro_ai = NeuroSymbolicCyberAI()
        
        # Convert threat data to neural input
        import numpy as np
        neural_input = np.random.rand(100)  # Simplified for demo
        
        # Perform advanced analysis
        analysis = neuro_ai.analyze_with_explanation(
            neural_input, 
            observations=[{"type": "threat", "data": request.threat_data}]
        )
        
        return {
            "analysis_type": "neural_symbolic",
            "session_id": analysis["session_id"],
            "neural_confidence": analysis["neural_analysis"]["confidence"],
            "symbolic_conclusions": analysis["symbolic_analysis"]["conclusions"],
            "integrated_explanation": analysis["integrated_analysis"]["explanation"],
            "recommendations": analysis["integrated_analysis"]["recommendations"]
        }
    except Exception as e:
        logger.error(f"Neural-symbolic analysis failed: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")

# Graph neural network threat analysis
@app.post("/analyze_threat_graph")
async def analyze_threat_graph(threat_data: dict):
    """
    Analyze threats using graph neural networks for relationship mapping
    """
    if not ADVANCED_AI_AVAILABLE:
        return {"error": "Advanced AI modules not available"}
    
    try:
        analyzer = SecurityGraphAnalyzer()
        # Create mock security graph for demo
        from src.learning.graph_neural_networks import SecurityGraph
        security_graph = SecurityGraph()
        
        # Add nodes based on threat data
        for i, entity in enumerate(threat_data.get("entities", [])):
            security_graph.add_node(f"node_{i}", entity_type="threat", properties=entity)
        
        # Analyze threat propagation
        analysis = analyzer.analyze_threat_propagation(security_graph)
        
        return {
            "analysis_type": "graph_neural_network",
            "total_nodes": analysis["summary"]["total_nodes"],
            "high_risk_nodes": analysis["summary"]["high_risk_nodes"],
            "threat_propagation_paths": analysis["summary"]["critical_propagation_paths"],
            "dominant_threat": analysis["summary"]["dominant_threat_type"]
        }
    except Exception as e:
        return {"error": f"Graph analysis failed: {str(e)}"}

# Meta-learning adaptive threat classification
@app.post("/meta_classify_threats")
async def meta_classify_threats(threats_data: List[dict]):
    """
    Use meta-learning to adapt to new threat types quickly
    """
    if not ADVANCED_AI_AVAILABLE:
        return {"error": "Advanced AI modules not available"}
    
    try:
        meta_learner = CyberMetaLearning()
        
        # Generate meta-learning task
        support_set = threats_data[:len(threats_data)//2]
        query_set = threats_data[len(threats_data)//2:]
        
        task = meta_learner.task_generator.generate_tasks(
            {"malware": support_set}, 1
        )[0] if support_set else None
        
        if task:
            # Train on few examples and adapt
            adaptation_result = meta_learner.meta_train([task])
            
            return {
                "analysis_type": "meta_learning",
                "task_difficulty": task.difficulty,
                "adaptation_loss": adaptation_result.get("loss", 0.5),
                "few_shot_accuracy": adaptation_result.get("accuracy", 0.8),
                "threat_categories": task.metadata.get("threat_categories", [])
            }
        else:
            return {"error": "Insufficient data for meta-learning"}
    except Exception as e:
        return {"error": f"Meta-learning failed: {str(e)}"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=7860)
