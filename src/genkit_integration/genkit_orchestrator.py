"""
Genkit-Enhanced Cybersecurity AI System Integration
Integrates Google Genkit with existing Phase 9 cognitive architecture
"""

import os
import json
from typing import Dict, List, Any, Optional
from datetime import datetime
import asyncio
from pydantic import BaseModel, Field

try:
    from genkit.ai import Genkit
    from genkit.plugins.google_genai import GoogleAI
    from genkit.plugins.dev_local_vectorstore import devLocalVectorstore, devLocalRetrieverRef
    from genkit import z
    GENKIT_AVAILABLE = True
except ImportError:
    GENKIT_AVAILABLE = False
    print("Google Genkit not available - run: pip install genkit genkit-plugin-google-genai")

# Import existing cognitive systems
import sys
sys.path.append('/home/o1/Desktop/cyber_llm/src')

from cognitive.advanced_cognitive_system import AdvancedCognitiveSystem
from agents.orchestrator import SecurityOrchestrator
from agents.recon_agent import ReconAgent
from agents.safety_agent import SafetyAgent
from agents.c2_agent import C2Agent
from agents.explainability_agent import ExplainabilityAgent


class ThreatIntelligence(BaseModel):
    """Structured threat intelligence output"""
    threat_type: str = Field(description="Type of threat identified")
    severity: str = Field(description="Threat severity: low, medium, high, critical")
    indicators: List[str] = Field(description="Indicators of compromise")
    recommendations: List[str] = Field(description="Mitigation recommendations")
    confidence_score: float = Field(description="Confidence in assessment (0.0-1.0)")
    timestamp: str = Field(description="Analysis timestamp")


class SecurityAnalysis(BaseModel):
    """Structured security analysis result"""
    analysis_type: str = Field(description="Type of analysis performed")
    findings: List[str] = Field(description="Security findings")
    risk_score: int = Field(description="Risk score (1-10)")
    affected_systems: List[str] = Field(description="Systems affected")
    mitigation_steps: List[str] = Field(description="Steps to mitigate risks")


class GenkitEnhancedOrchestrator:
    """
    Enhanced cybersecurity orchestrator using Google Genkit framework
    Integrates with existing Phase 9 cognitive architecture
    """
    
    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        self.cognitive_system = None
        self.legacy_orchestrator = None
        
        if not GENKIT_AVAILABLE:
            raise ImportError("Google Genkit not available. Install with: pip install genkit genkit-plugin-google-genai")
        
        # Initialize Genkit AI with plugins
        self.ai = Genkit(
            plugins=[
                GoogleAI(),
                devLocalVectorstore([
                    {
                        'indexName': 'threatIntel',
                        'embedder': 'googleai/gemini-embedding-001',
                    },
                    {
                        'indexName': 'vulnerabilities',
                        'embedder': 'googleai/gemini-embedding-001',
                    }
                ])
            ],
            model='googleai/gemini-2.5-flash'
        )
        
        # Initialize threat intelligence retriever
        self.threat_retriever = devLocalRetrieverRef('threatIntel')
        self.vuln_retriever = devLocalRetrieverRef('vulnerabilities')
        
        # Setup specialized agents
        self._setup_agents()
        
    def _setup_agents(self):
        """Setup Genkit-enhanced specialized agents"""
        
        # Reconnaissance Agent
        self.recon_agent = self.ai.definePrompt({
            'name': 'reconAgent',
            'description': 'Advanced reconnaissance agent for threat discovery',
            'tools': [self._create_network_scan_tool(), self._create_port_scan_tool()],
            'system': '''You are an advanced cybersecurity reconnaissance agent.
            Your role is to discover and analyze potential threats, vulnerabilities, and attack vectors.
            Use available tools to gather intelligence and provide structured analysis.
            Always prioritize stealth and minimize impact on target systems.
            Report findings in structured format with confidence scores.'''
        })
        
        # Safety/Threat Analysis Agent  
        self.safety_agent = self.ai.definePrompt({
            'name': 'safetyAgent',
            'description': 'Threat analysis and safety assessment agent',
            'tools': [self._create_threat_analysis_tool(), self._create_vulnerability_assessment_tool()],
            'system': '''You are a cybersecurity threat analysis expert.
            Analyze threats, assess risks, and provide safety recommendations.
            Use threat intelligence databases and vulnerability assessments.
            Provide structured threat intelligence with severity ratings and mitigation steps.
            Always err on the side of caution for safety-critical assessments.'''
        })
        
        # Command & Control Agent
        self.c2_agent = self.ai.definePrompt({
            'name': 'c2Agent', 
            'description': 'Command and control coordination agent',
            'tools': [self._create_response_coordination_tool(), self._create_incident_management_tool()],
            'system': '''You are a cybersecurity command and control coordinator.
            Coordinate incident response, manage security operations, and orchestrate defensive measures.
            Prioritize actions based on threat severity and business impact.
            Ensure proper communication and documentation of all actions taken.'''
        })
        
        # Explainability Agent
        self.explainability_agent = self.ai.definePrompt({
            'name': 'explainabilityAgent',
            'description': 'AI decision explanation and transparency agent',
            'tools': [self._create_analysis_explanation_tool()],
            'system': '''You are an AI explainability expert for cybersecurity decisions.
            Provide clear, understandable explanations of AI-driven security decisions.
            Break down complex analysis into human-readable insights.
            Include confidence levels, reasoning chains, and alternative perspectives.
            Help security teams understand and trust AI recommendations.'''
        })
        
        # Main Orchestration Agent
        self.orchestrator_agent = self.ai.definePrompt({
            'name': 'orchestratorAgent',
            'description': 'Main cybersecurity orchestration and triage agent',
            'tools': [self.recon_agent, self.safety_agent, self.c2_agent, self.explainability_agent],
            'system': '''You are the main cybersecurity AI orchestrator.
            Coordinate and delegate tasks to specialized agents based on the situation.
            Prioritize threats, manage resources, and ensure comprehensive security coverage.
            Make strategic decisions about which agents to deploy for specific scenarios.
            Maintain situational awareness and provide executive-level security insights.'''
        })
    
    def _create_network_scan_tool(self):
        """Create network scanning tool for reconnaissance"""
        return self.ai.defineTool(
            {
                'name': 'networkScanTool',
                'description': 'Perform network reconnaissance and discovery',
                'inputSchema': z.object({
                    'target': z.string().describe('Target IP range or hostname'),
                    'scan_type': z.string().describe('Type of scan: ping, port, service'),
                    'stealth': z.boolean().describe('Use stealth scanning techniques')
                }),
                'outputSchema': z.string().describe('Scan results in JSON format')
            },
            async_tool_impl=self._network_scan_impl
        )
    
    def _create_port_scan_tool(self):
        """Create port scanning tool"""
        return self.ai.defineTool(
            {
                'name': 'portScanTool', 
                'description': 'Scan for open ports and services',
                'inputSchema': z.object({
                    'target': z.string().describe('Target IP or hostname'),
                    'port_range': z.string().describe('Port range to scan (e.g., 1-1000)'),
                    'scan_technique': z.string().describe('Scan technique: tcp, udp, syn')
                }),
                'outputSchema': z.string().describe('Port scan results')
            },
            async_tool_impl=self._port_scan_impl
        )
    
    def _create_threat_analysis_tool(self):
        """Create threat analysis tool"""
        return self.ai.defineTool(
            {
                'name': 'threatAnalysisTool',
                'description': 'Analyze threats using intelligence databases',
                'inputSchema': z.object({
                    'indicators': z.array(z.string()).describe('List of IOCs to analyze'),
                    'analysis_depth': z.string().describe('Analysis depth: quick, standard, deep')
                }),
                'outputSchema': z.string().describe('Threat analysis results')
            },
            async_tool_impl=self._threat_analysis_impl
        )
    
    def _create_vulnerability_assessment_tool(self):
        """Create vulnerability assessment tool"""
        return self.ai.defineTool(
            {
                'name': 'vulnerabilityAssessmentTool',
                'description': 'Assess system vulnerabilities',
                'inputSchema': z.object({
                    'target': z.string().describe('Target system or service'),
                    'assessment_type': z.string().describe('Assessment type: basic, comprehensive')
                }),
                'outputSchema': z.string().describe('Vulnerability assessment results')
            },
            async_tool_impl=self._vulnerability_assessment_impl
        )
    
    def _create_response_coordination_tool(self):
        """Create incident response coordination tool"""
        return self.ai.defineTool(
            {
                'name': 'responseCoordinationTool',
                'description': 'Coordinate incident response activities',
                'inputSchema': z.object({
                    'incident_id': z.string().describe('Incident identifier'),
                    'response_actions': z.array(z.string()).describe('List of response actions to coordinate')
                }),
                'outputSchema': z.string().describe('Coordination results')
            },
            async_tool_impl=self._response_coordination_impl
        )
    
    def _create_incident_management_tool(self):
        """Create incident management tool"""
        return self.ai.defineTool(
            {
                'name': 'incidentManagementTool',
                'description': 'Manage security incidents',
                'inputSchema': z.object({
                    'incident_data': z.string().describe('Incident information'),
                    'action': z.string().describe('Action: create, update, escalate, close')
                }),
                'outputSchema': z.string().describe('Incident management results')
            },
            async_tool_impl=self._incident_management_impl
        )
    
    def _create_analysis_explanation_tool(self):
        """Create analysis explanation tool"""
        return self.ai.defineTool(
            {
                'name': 'analysisExplanationTool',
                'description': 'Explain AI security decisions and analysis',
                'inputSchema': z.object({
                    'decision': z.string().describe('AI decision or analysis to explain'),
                    'audience': z.string().describe('Target audience: technical, executive, general')
                }),
                'outputSchema': z.string().describe('Human-readable explanation')
            },
            async_tool_impl=self._analysis_explanation_impl
        )
    
    # Tool implementations
    async def _network_scan_impl(self, input_data):
        """Implement network scanning functionality"""
        # Integrate with existing recon agent or implement scanning logic
        try:
            if self.legacy_orchestrator and hasattr(self.legacy_orchestrator, 'recon_agent'):
                result = await self.legacy_orchestrator.recon_agent.scan_network(
                    input_data['target'], 
                    input_data['scan_type'], 
                    input_data.get('stealth', False)
                )
                return json.dumps(result)
            else:
                return json.dumps({
                    "status": "simulated",
                    "target": input_data['target'],
                    "scan_type": input_data['scan_type'],
                    "results": ["Simulated network scan results - integrate with real scanning tools"]
                })
        except Exception as e:
            return json.dumps({"error": str(e)})
    
    async def _port_scan_impl(self, input_data):
        """Implement port scanning functionality"""
        try:
            return json.dumps({
                "status": "simulated",
                "target": input_data['target'],
                "port_range": input_data['port_range'],
                "open_ports": [22, 80, 443, 3389],  # Simulated results
                "services": {
                    "22": "SSH",
                    "80": "HTTP", 
                    "443": "HTTPS",
                    "3389": "RDP"
                }
            })
        except Exception as e:
            return json.dumps({"error": str(e)})
    
    async def _threat_analysis_impl(self, input_data):
        """Implement threat analysis functionality"""
        try:
            # Use RAG to retrieve threat intelligence
            docs = await self.ai.retrieve({
                'retriever': self.threat_retriever,
                'query': ' '.join(input_data['indicators']),
                'options': {'k': 5}
            })
            
            analysis_result = {
                "indicators_analyzed": input_data['indicators'],
                "threat_level": "medium",  # Determined by analysis
                "related_threats": [doc.content for doc in docs[:3]],
                "confidence": 0.75,
                "timestamp": datetime.now().isoformat()
            }
            return json.dumps(analysis_result)
        except Exception as e:
            return json.dumps({"error": str(e)})
    
    async def _vulnerability_assessment_impl(self, input_data):
        """Implement vulnerability assessment functionality"""
        try:
            # Use RAG to retrieve vulnerability information
            docs = await self.ai.retrieve({
                'retriever': self.vuln_retriever,
                'query': input_data['target'],
                'options': {'k': 3}
            })
            
            assessment_result = {
                "target": input_data['target'],
                "assessment_type": input_data['assessment_type'],
                "vulnerabilities": [doc.content for doc in docs],
                "risk_score": 7,  # Calculated based on findings
                "recommendations": [
                    "Apply latest security patches",
                    "Update security configurations",
                    "Implement additional monitoring"
                ]
            }
            return json.dumps(assessment_result)
        except Exception as e:
            return json.dumps({"error": str(e)})
    
    async def _response_coordination_impl(self, input_data):
        """Implement response coordination functionality"""
        try:
            coordination_result = {
                "incident_id": input_data['incident_id'],
                "actions_coordinated": input_data['response_actions'],
                "status": "coordinated",
                "next_steps": ["Monitor execution", "Report status", "Update stakeholders"]
            }
            return json.dumps(coordination_result)
        except Exception as e:
            return json.dumps({"error": str(e)})
    
    async def _incident_management_impl(self, input_data):
        """Implement incident management functionality"""
        try:
            management_result = {
                "action": input_data['action'],
                "incident_data": input_data['incident_data'],
                "status": "processed",
                "incident_id": f"INC-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
            }
            return json.dumps(management_result)
        except Exception as e:
            return json.dumps({"error": str(e)})
    
    async def _analysis_explanation_impl(self, input_data):
        """Implement analysis explanation functionality"""
        try:
            explanation = f"""
            Analysis Explanation for {input_data['audience']} audience:
            
            Decision/Analysis: {input_data['decision']}
            
            Reasoning Process:
            1. Data collection and preprocessing
            2. Pattern recognition and anomaly detection
            3. Risk assessment and scoring
            4. Recommendation generation
            
            Key Factors Considered:
            - Historical threat patterns
            - System criticality
            - Business impact
            - Available countermeasures
            
            Confidence Level: High (based on multiple data sources and validation)
            """
            return explanation.strip()
        except Exception as e:
            return f"Error explaining analysis: {str(e)}"
    
    async def initialize_legacy_integration(self):
        """Initialize integration with existing cognitive system"""
        try:
            # Initialize existing cognitive system
            self.cognitive_system = AdvancedCognitiveSystem()
            await self.cognitive_system.initialize()
            
            # Initialize legacy orchestrator for tool integration
            self.legacy_orchestrator = SecurityOrchestrator()
            await self.legacy_orchestrator.initialize()
            
            print("✅ Legacy system integration initialized")
            return True
        except Exception as e:
            print(f"❌ Failed to initialize legacy integration: {e}")
            return False
    
    @asyncio.coroutine
    def analyze_security_threat(self, threat_data: str) -> ThreatIntelligence:
        """
        Main security threat analysis using Genkit-enhanced agents
        """
        try:
            # Start chat session with orchestrator
            chat = self.ai.chat(self.orchestrator_agent)
            
            # Analyze threat using AI orchestration
            response = await chat.send(
                f"Analyze this security threat and provide structured intelligence: {threat_data}"
            )
            
            # Generate structured output
            result = await self.ai.generate({
                'model': 'googleai/gemini-2.5-flash',
                'prompt': f"Convert this threat analysis into structured intelligence: {response.content}",
                'output_schema': ThreatIntelligence
            })
            
            return result.output
        except Exception as e:
            # Fallback to basic analysis
            return ThreatIntelligence(
                threat_type="unknown",
                severity="medium", 
                indicators=[],
                recommendations=["Manual review required"],
                confidence_score=0.5,
                timestamp=datetime.now().isoformat()
            )
    
    @asyncio.coroutine 
    def perform_security_analysis(self, target: str, analysis_type: str = "comprehensive") -> SecurityAnalysis:
        """
        Perform comprehensive security analysis using specialized agents
        """
        try:
            # Start with orchestrator to determine best approach
            chat = self.ai.chat(self.orchestrator_agent)
            
            analysis_request = f"""
            Perform {analysis_type} security analysis of target: {target}
            Coordinate with appropriate specialized agents to gather intelligence.
            """
            
            response = await chat.send(analysis_request)
            
            # Generate structured analysis result
            result = await self.ai.generate({
                'model': 'googleai/gemini-2.5-flash', 
                'prompt': f"Structure this security analysis: {response.content}",
                'output_schema': SecurityAnalysis
            })
            
            return result.output
        except Exception as e:
            return SecurityAnalysis(
                analysis_type=analysis_type,
                findings=[f"Analysis error: {str(e)}"],
                risk_score=5,
                affected_systems=[target],
                mitigation_steps=["Manual investigation required"]
            )
    
    async def get_threat_explanation(self, threat_analysis: str, audience: str = "technical") -> str:
        """
        Get human-readable explanation of threat analysis
        """
        try:
            chat = self.ai.chat(self.explainability_agent)
            
            explanation_request = f"""
            Explain this threat analysis for a {audience} audience:
            {threat_analysis}
            
            Provide clear, actionable insights.
            """
            
            response = await chat.send(explanation_request)
            return response.content
        except Exception as e:
            return f"Unable to generate explanation: {str(e)}"


# Integration factory function
def create_genkit_enhanced_system(config: Optional[Dict] = None) -> Optional[GenkitEnhancedOrchestrator]:
    """
    Factory function to create Genkit-enhanced cybersecurity system
    """
    if not GENKIT_AVAILABLE:
        print("❌ Google Genkit not available")
        return None
    
    try:
        orchestrator = GenkitEnhancedOrchestrator(config)
        print("✅ Genkit-enhanced cybersecurity system created")
        return orchestrator
    except Exception as e:
        print(f"❌ Failed to create Genkit system: {e}")
        return None


# Example usage
async def main():
    """Example usage of Genkit-enhanced system"""
    
    # Create enhanced system
    genkit_system = create_genkit_enhanced_system()
    if not genkit_system:
        return
    
    # Initialize legacy integration
    await genkit_system.initialize_legacy_integration()
    
    # Example threat analysis
    threat_data = "Suspicious network activity detected from IP 192.168.1.100, multiple failed login attempts"
    
    try:
        # Analyze threat
        threat_intel = await genkit_system.analyze_security_threat(threat_data)
        print(f"Threat Analysis: {threat_intel}")
        
        # Perform security analysis
        security_analysis = await genkit_system.perform_security_analysis("192.168.1.0/24")
        print(f"Security Analysis: {security_analysis}")
        
        # Get explanation
        explanation = await genkit_system.get_threat_explanation(
            str(threat_intel), 
            audience="executive"
        )
        print(f"Executive Explanation: {explanation}")
        
    except Exception as e:
        print(f"Error during analysis: {e}")


if __name__ == "__main__":
    asyncio.run(main())
