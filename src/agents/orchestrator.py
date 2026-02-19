"""
Cyber-LLM Agent Orchestrator

Main orchestration engine for coordinating multi-agent red team operations.
Manages workflow execution, safety checks, and human-in-the-loop approvals.

Author: Muzan Sano
Email: sanosensei36@gmail.com
"""

import json
import logging
import asyncio
import yaml
from typing import Dict, List, Any, Optional, Type
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

# Import agents
from .recon_agent import ReconAgent, ReconTarget
from .c2_agent import C2Agent, C2Request
from .post_exploit_agent import PostExploitAgent, PostExploitRequest
from .safety_agent import SafetyAgent
from .explainability_agent import ExplainabilityAgent

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class OperationContext:
    """Context for red team operation."""
    operation_id: str
    target: str
    objectives: List[str]
    constraints: Dict[str, Any]
    approval_required: bool = True
    stealth_mode: bool = True
    max_duration: int = 14400  # 4 hours
    
@dataclass
class AgentResult:
    """Result from agent execution."""
    agent_name: str
    success: bool
    data: Dict[str, Any]
    execution_time: float
    risk_score: float
    errors: List[str] = None

class Orchestrator:
    """
    Advanced orchestrator for coordinating multi-agent red team operations.
    Implements safety checks, human approval workflows, and operational security.
    """
    
    def __init__(self, config_path: Optional[str] = None, autonomous_mode: bool = False, event_callback=None):
        self.config = self._load_config(config_path)
        self.autonomous_mode = autonomous_mode
        self.event_callback = event_callback
        self.agents = self._initialize_agents()
        self.workflows = self._load_workflows()
        self.operation_history = []

    async def _emit_step_detail(self, operation_id: str, phase: str, detail_type: str, data: Dict[str, Any]):
        """Emit granular step details for UI visualization."""
        if self.event_callback:
            await self.event_callback("workflow_update", {
                "type": "step_details",
                "operation_id": operation_id,
                "phase": phase,
                "detail_type": detail_type,
                "data": data,
                "timestamp": datetime.now().isoformat()
            })
        
    def _load_config(self, config_path: Optional[str]) -> Dict[str, Any]:
        """Load orchestrator configuration."""
        if config_path:
            with open(config_path, 'r') as f:
                return yaml.safe_load(f)
        return {
            "max_parallel_agents": 3,
            "safety_threshold": 0.7,
            "require_human_approval": True,
            "log_all_operations": True,
            "auto_cleanup": True
        }
    
    def _initialize_agents(self) -> Dict[str, Any]:
        """Initialize all available agents."""
        return {
            "recon": ReconAgent(),
            "c2": C2Agent(),
            "post_exploit": PostExploitAgent(),
            "safety": SafetyAgent(),
            "explainability": ExplainabilityAgent(),
            # Aliases for specialized phases sharing agent logic
            "weaponization": C2Agent(),
            "delivery": C2Agent(),
            "install": PostExploitAgent(),
            "actions_on_objectives": PostExploitAgent()
        }
    
    def _load_workflows(self) -> Dict[str, Any]:
        """Load predefined workflow templates."""
        return {
            "standard_red_team": {
                "name": "Standard Red Team Assessment",
                "description": "Full red team engagement workflow",
                "phases": [
                    {
                        "name": "reconnaissance",
                        "agents": ["recon"],
                        "parallel": False,
                        "safety_check": True,
                        "human_approval": False
                    },
                    {
                        "name": "weaponization",
                        "agents": ["weaponization"],
                        "parallel": False, 
                        "safety_check": True,
                        "human_approval": False,
                        "depends_on": ["reconnaissance"]
                    },
                    {
                        "name": "delivery",
                        "agents": ["delivery"],
                        "parallel": False,
                        "safety_check": True,
                        "human_approval": False,
                        "depends_on": ["weaponization"]
                    },
                    {
                        "name": "initial_access", # C2 Setup
                        "agents": ["c2"],
                        "parallel": False,
                        "safety_check": True,
                        "human_approval": False,
                        "depends_on": ["delivery"]
                    },
                    {
                        "name": "post_exploitation", # Exploitation
                        "agents": ["post_exploit"],
                        "parallel": False,
                        "safety_check": True,
                        "human_approval": False,
                        "depends_on": ["initial_access"]
                    },
                    {
                        "name": "installation",
                        "agents": ["install"],
                        "parallel": False,
                        "safety_check": True,
                        "human_approval": False,
                        "depends_on": ["post_exploitation"]
                    },
                    {
                        "name": "actions_on_objectives",
                        "agents": ["actions_on_objectives"],
                        "parallel": False,
                        "safety_check": True,
                        "human_approval": False,
                        "depends_on": ["installation"]
                    }
                ]
            },
            "stealth_assessment": {
                "name": "Stealth Red Team Assessment",
                "description": "Low-detection red team workflow",
                "phases": [
                    {
                        "name": "passive_recon",
                        "agents": ["recon"],
                        "parallel": False,
                        "safety_check": True,
                        "human_approval": False,
                        "config_overrides": {"scan_type": "passive"}
                    },
                    {
                        "name": "targeted_exploitation",
                        "agents": ["c2", "post_exploit"],
                        "parallel": True,
                        "safety_check": True,
                        "human_approval": True,
                        "depends_on": ["passive_recon"]
                    }
                ]
            },
            "credential_focused": {
                "name": "Credential Harvesting Focus",
                "description": "Credential-focused assessment workflow",
                "phases": [
                    {
                        "name": "initial_recon",
                        "agents": ["recon"],
                        "parallel": False,
                        "safety_check": True,
                        "human_approval": False
                    },
                    {
                        "name": "credential_harvest",
                        "agents": ["post_exploit"],
                        "parallel": False,
                        "safety_check": True,
                        "human_approval": True,
                        "config_overrides": {"objectives": ["credential_harvest"]},
                        "depends_on": ["initial_recon"]
                    }
                ]
            }
        }
    
    async def safety_check(self, agent_name: str, planned_actions: Dict[str, Any]) -> Dict[str, Any]:
        """
        Perform safety and OPSEC compliance check.
        
        # HUMAN_APPROVAL_REQUIRED: Safety checks require human oversight
        """
        logger.info(f"Performing safety check for {agent_name}")
        
        safety_agent = self.agents["safety"]
        safety_result = await safety_agent.evaluate_actions(planned_actions)
        
        # Check against safety threshold
        if safety_result["risk_score"] > self.config["safety_threshold"]:
            logger.warning(f"High risk detected for {agent_name}: {safety_result['risk_score']}")
            safety_result["approved"] = False
            safety_result["reason"] = "Risk score exceeds safety threshold"
        else:
            safety_result["approved"] = True
            
        return safety_result
    
    async def request_human_approval(self, agent_name: str, planned_actions: Dict[str, Any], 
                                   safety_result: Dict[str, Any]) -> bool:
        """
        Request human approval for high-risk operations.
        
        # HUMAN_APPROVAL_REQUIRED: This function handles human approval workflow
        """
        print(f"\n{'='*60}")
        print(f"HUMAN APPROVAL REQUIRED - {agent_name.upper()}")
        print(f"{'='*60}")
        
        print(f"Risk Score: {safety_result.get('risk_score', 'Unknown')}")
        print(f"Risk Level: {safety_result.get('risk_level', 'Unknown')}")
        
        if safety_result.get('risks'):
            print("\nIdentified Risks:")
            for risk in safety_result['risks']:
                print(f"  - {risk}")
                
        if safety_result.get('mitigations'):
            print("\nRecommended Mitigations:")
            for mitigation in safety_result['mitigations']:
                print(f"  - {mitigation}")
                
        print(f"\nPlanned Actions Summary:")
        print(json.dumps(planned_actions, indent=2))
        
        print(f"\n{'='*60}")
        
        # In a real implementation, this would integrate with a proper approval system
        if self.autonomous_mode:
            logger.info(f"AUTONOMOUS MODE: Auto-approving operation for {agent_name} (Risk Score: {safety_result.get('risk_score')})")
            # In a real system, you might still want to deny very high risk actions even in autonomous mode
            # For this demo/training environment, we proceed.
            return True

        while True:
            response = input("Approve this operation? [y/N/details]: ").lower().strip()
            
            if response in ['y', 'yes']:
                logger.info(f"Human approval granted for {agent_name}")
                return True
            elif response in ['n', 'no', '']:
                logger.info(f"Human approval denied for {agent_name}")
                return False
            elif response == 'details':
                print("\nDetailed Action Plan:")
                print(json.dumps(planned_actions, indent=2))
            else:
                print("Please enter 'y' for yes, 'n' for no, or 'details' for more information")
    
    async def execute_agent(self, agent_name: str, context: OperationContext, 
                          config_overrides: Optional[Dict[str, Any]] = None) -> AgentResult:
        """Execute a single agent with safety checks and approval workflow."""
        start_time = datetime.now()
        
        try:
            agent = self.agents[agent_name]
            
            # Create agent-specific request
            if agent_name == "recon":
                # Determine target type (simple heuristic)
                target_type = "ip" if context.target.replace('.', '').isdigit() else "domain"
                
                request = ReconTarget(
                    target=context.target,
                    target_type=target_type,
                    constraints={
                        "scan_type": config_overrides.get("scan_type", "stealth") if config_overrides else "stealth",
                        "stealth": context.stealth_mode
                    },
                    opsec_level="high" if context.stealth_mode else "medium"
                )
                planned_actions = {
                    "agent": agent_name,
                    "target": context.target,
                    "scan_type": request.constraints.get("scan_type")
                }
                
            elif agent_name == "c2":
                request = C2Request(
                    payload_type="powershell",
                    target_environment="corporate",  # Could be derived from recon
                    network_constraints=context.constraints.get("network", {}),
                    stealth_level="high" if context.stealth_mode else "medium"
                )
                planned_actions = {
                    "agent": agent_name,
                    "payload_type": request.payload_type,
                    "stealth_level": request.stealth_level
                }
                
            elif agent_name == "post_exploit":
                request = PostExploitRequest(
                    target_system=context.target,
                    access_level="user",  # Could be updated based on previous results
                    objectives=config_overrides.get("objectives", context.objectives) if config_overrides else context.objectives,
                    constraints=context.constraints,
                    stealth_mode=context.stealth_mode
                )
                planned_actions = {
                    "agent": agent_name,
                    "target": context.target,
                    "objectives": request.objectives
                }
            
            else:
                raise ValueError(f"Unknown agent: {agent_name}")
            
            # Safety check
            if context.approval_required:
                safety_result = await self.safety_check(agent_name, planned_actions)
                
                if not safety_result["approved"]:
                    return AgentResult(
                        agent_name=agent_name,
                        success=False,
                        data={"error": "Failed safety check", "safety_result": safety_result},
                        execution_time=0,
                        risk_score=safety_result.get("risk_score", 1.0),
                        errors=["Safety check failed"]
                    )
                
                # Request human approval if required
                if self.config["require_human_approval"]:
                    approved = await self.request_human_approval(agent_name, planned_actions, safety_result)
                    if not approved:
                        return AgentResult(
                            agent_name=agent_name,
                            success=False,
                            data={"error": "Human approval denied"},
                            execution_time=0,
                            risk_score=safety_result.get("risk_score", 1.0),
                            errors=["Human approval denied"]
                        )
            
            # Execute agent
            logger.info(f"Executing {agent_name} agent")
            
            # STREAMING SIMULATION FOR UI OBSERVABILITY
            # In a real system, these would be emitted by the agents themselves or via hooks depending on agent internal progress.
            # Here we simulate the "stream" of data that the UI will visualize.
            
            if agent_name == "recon":
                # Stream initial scanning
                await self._emit_step_detail(context.operation_id, "recon", "log", {"message": f"Initiating stealth scan against {context.target}"})
                await asyncio.sleep(1)
                
                # Stream Nmap-style confirmation
                await self._emit_step_detail(context.operation_id, "recon", "raw_scan", {
                    "tool": "Nmap 7.94",
                    "command": f"nmap -sS -T4 -p- -A {context.target}",
                    "output": f"""
Starting Nmap 7.94 ( https://nmap.org ) at {datetime.now().strftime('%Y-%m-%d %H:%M')}
Nmap scan report for {context.target}
Host is up (0.0023s latency).
Not shown: 65531 closed tcp ports (reset)
PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http       nginx 1.18.0 (Ubuntu)
|_http-title: Welcome to {context.target}
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
443/tcp  open  ssl/http   nginx 1.18.0 (Ubuntu)
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|_  http/1.1
8080/tcp open  http-proxy
| http-robots.txt: 1 disallowed entry 
|_/admin/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
"""
                })
                await asyncio.sleep(1)
                
                result = agent.execute_reconnaissance(request)

            elif agent_name == "c2":
                # Stream payload generation
                await self._emit_step_detail(context.operation_id, "initial_access", "log", {"message": "Analyzing target architecture for payload selection..."})
                await asyncio.sleep(1)
                
                payload_hex = "48 31 c0 48 89 c7 48 89 e2 48 83 c0 3b 0f 05 48 31 c0 48 89 c7 48 89 e2 48 83 c0 3b 0f 05"
                await self._emit_step_detail(context.operation_id, "initial_access", "payload_gen", {
                    "type": "Reverse TCP Shell",
                    "platform": "Linux/x64",
                    "format": "ELF",
                    "encoder": "Shikata Ga Nai",
                    "hex_dump": payload_hex
                })
                await asyncio.sleep(1)

                result = agent.execute_c2_setup(request)

            elif agent_name == "weaponization":
                 # Stream payload construction
                await self._emit_step_detail(context.operation_id, "weaponization", "log", {"message": "Compiling custom payload for target architecture..."})
                await asyncio.sleep(1)
                
                await self._emit_step_detail(context.operation_id, "weaponization", "build_log", {
                    "compiler": "gcc-9.4.0",
                    "arch": "x86_64",
                    "cflags": "-O2 -fPIC -shared",
                    "output": "payload_x64.so",
                    "size": "14.2KB"
                })
                await asyncio.sleep(1)
                result = agent.execute_weaponization(request)

            elif agent_name == "delivery":
                # Stream delivery vector
                await self._emit_step_detail(context.operation_id, "delivery", "log", {"message": "Initiating delivery via spearfishing vector..."})
                await asyncio.sleep(1)
                
                await self._emit_step_detail(context.operation_id, "delivery", "email_log", {
                    "template": "IT_Security_Update_Urgent",
                    "recipient": f"admin@{context.target}",
                    "sender": "security-alerts@corporate-auth.com",
                    "status": "SENT",
                    "mx_record": "mx1.mail.protection.outlook.com"
                })
                await asyncio.sleep(1)
                result = agent.execute_delivery(request)
                
            elif agent_name == "install":
                # Stream persistence
                await self._emit_step_detail(context.operation_id, "installation", "log", {"message": "Establishing persistence mechanisms..."})
                await asyncio.sleep(1)

                await self._emit_step_detail(context.operation_id, "installation", "persistence", {
                    "method": "Systemd Service",
                    "service_name": "system-update-daemon.service",
                    "path": "/etc/systemd/system/update.service",
                    "status": "CREATED"
                })
                await asyncio.sleep(1)
                result = agent.execute_installation(request)

            elif agent_name == "post_exploit":
                # Stream exploitation attempts
                await self._emit_step_detail(context.operation_id, "post_exploitation", "log", {"message": "Attempting privilege escalation via SUID binaries..."})
                await asyncio.sleep(1)
                
                await self._emit_step_detail(context.operation_id, "post_exploitation", "exploit_attempt", {
                    "exploit": "CVE-2021-4034 (PwnKit)",
                    "target_service": "mechanisms/polkit",
                    "status": "VULNERABLE",
                    "result": "Root access confirmed via pkexec"
                })
                await asyncio.sleep(1)

                result = agent.execute_post_exploitation(request)
            
            elif agent_name == "actions_on_objectives":
                 # Stream reporting
                await self._emit_step_detail(context.operation_id, "actions_on_objectives", "log", {"message": "Compiling final operation report..."})
                await asyncio.sleep(1)
                
                await self._emit_step_detail(context.operation_id, "actions_on_objectives", "report_gen", {
                    "objectives_met": len(context.objectives),
                    "data_exfiltrated": "14MB",
                    "status": "SUCCESS"
                })
                await asyncio.sleep(1)
                
                # Re-use post-exploit logic for final actions
                result = agent.execute_post_exploitation(request)

            
            execution_time = (datetime.now() - start_time).total_seconds()
            
            # Extract risk score from result
            risk_score = 0.0
            if hasattr(result, 'risk_assessment') and result.risk_assessment:
                risk_score = result.risk_assessment.get('risk_score', 0.0)
            
            return AgentResult(
                agent_name=agent_name,
                success=True,
                data=result.dict() if hasattr(result, 'dict') else result,
                execution_time=execution_time,
                risk_score=risk_score
            )
            
        except Exception as e:
            execution_time = (datetime.now() - start_time).total_seconds()
            logger.error(f"Error executing {agent_name}: {str(e)}")
            
            return AgentResult(
                agent_name=agent_name,
                success=False,
                data={"error": str(e)},
                execution_time=execution_time,
                risk_score=1.0,
                errors=[str(e)]
            )
    
    async def execute_workflow(self, workflow_name: str, context: OperationContext) -> Dict[str, Any]:
        """
        Execute a complete red team workflow.
        
        # HUMAN_APPROVAL_REQUIRED: Workflow execution requires oversight
        """
        if workflow_name not in self.workflows:
            raise ValueError(f"Unknown workflow: {workflow_name}")
        
        workflow = self.workflows[workflow_name]
        logger.info(f"Starting workflow: {workflow['name']}")
        
        operation_start = datetime.now()
        results = {}
        phase_results = {}
        
        try:
            for phase in workflow["phases"]:
                phase_name = phase["name"]
                logger.info(f"Executing phase: {phase_name}")
                
                # Notify UI of phase change
                if self.event_callback:
                    await self.event_callback("workflow_update", {
                        "type": "update_phase",
                        "phase": phase_name,
                        "status": "started",
                        "operation_id": context.operation_id
                    })
                
                # Check dependencies
                if "depends_on" in phase:
                    for dependency in phase["depends_on"]:
                        if dependency not in phase_results or not phase_results[dependency]["success"]:
                            logger.error(f"Phase {phase_name} dependency {dependency} not satisfied")
                            phase_results[phase_name] = {
                                "success": False,
                                "error": f"Dependency {dependency} not satisfied"
                            }
                            continue
                
                # Execute agents in phase
                if phase.get("parallel", False):
                    # Execute agents in parallel
                    tasks = []
                    for agent_name in phase["agents"]:
                        config_overrides = phase.get("config_overrides")
                        task = self.execute_agent(agent_name, context, config_overrides)
                        tasks.append(task)
                    
                    agent_results = await asyncio.gather(*tasks)
                else:
                    # Execute agents sequentially
                    agent_results = []
                    for agent_name in phase["agents"]:
                        config_overrides = phase.get("config_overrides")
                        result = await self.execute_agent(agent_name, context, config_overrides)
                        agent_results.append(result)
                
                # Process phase results
                phase_success = all(result.success for result in agent_results)
                phase_results[phase_name] = {
                    "success": phase_success,
                    "agents": {result.agent_name: result for result in agent_results},
                    "execution_time": sum(result.execution_time for result in agent_results),
                    "max_risk_score": max(result.risk_score for result in agent_results) if agent_results else 0.0
                }
                
                # Update context with results for next phase
                for result in agent_results:
                    if result.success and result.agent_name == "recon":
                        # Update context with reconnaissance findings
                        if "nmap" in result.data:
                            context.constraints["discovered_services"] = result.data.get("nmap", [])
                
                logger.info(f"Phase {phase_name} completed: {'SUCCESS' if phase_success else 'FAILED'}")
        
        except Exception as e:
            logger.error(f"Workflow execution failed: {str(e)}")
            phase_results["error"] = str(e)
        
        # Generate final results
        operation_time = (datetime.now() - operation_start).total_seconds()
        overall_success = all(phase["success"] for phase in phase_results.values() if isinstance(phase, dict) and "success" in phase)
        
        results = {
            "operation_id": context.operation_id,
            "workflow": workflow_name,
            "target": context.target,
            "success": overall_success,
            "execution_time": operation_time,
            "phases": phase_results,
            "timestamp": operation_start.isoformat(),
            "context": {
                "objectives": context.objectives,
                "stealth_mode": context.stealth_mode,
                "approval_required": context.approval_required
            }
        }
        
        # Store in operation history
        self.operation_history.append(results)
        
        logger.info(f"Workflow {workflow_name} completed: {'SUCCESS' if overall_success else 'FAILED'}")
        return results
    
    def generate_operation_report(self, operation_results: Dict[str, Any]) -> str:
        """Generate comprehensive operation report."""
        explainability_agent = self.agents["explainability"]
        return explainability_agent.generate_operation_report(operation_results)
    
    async def cleanup_operation(self, operation_id: str):
        """Cleanup resources and artifacts from operation."""
        logger.info(f"Cleaning up operation: {operation_id}")
        
        # In a real implementation, this would:
        # - Remove temporary files
        # - Close network connections
        # - Remove persistence mechanisms
        # - Clear logs if required
        
        logger.info(f"Cleanup completed for operation: {operation_id}")

def main():
    """CLI interface for Red Team Orchestrator."""
    import argparse
    import uuid
    
    parser = argparse.ArgumentParser(description="Cyber-LLM Red Team Orchestrator")
    parser.add_argument("--workflow", required=True, help="Workflow to execute")
    parser.add_argument("--target", required=True, help="Target for assessment")
    parser.add_argument("--objectives", nargs="+", default=["reconnaissance", "initial_access"],
                       help="Operation objectives")
    parser.add_argument("--stealth", action="store_true", help="Enable stealth mode")
    parser.add_argument("--no-approval", action="store_true", help="Skip human approval")
    parser.add_argument("--config", help="Path to configuration file")
    parser.add_argument("--output", help="Output file for results")
    
    args = parser.parse_args()
    
    async def run_operation():
        # Initialize orchestrator
        orchestrator = Orchestrator(config_path=args.config)
        
        # Create operation context
        context = OperationContext(
            operation_id=str(uuid.uuid4()),
            target=args.target,
            objectives=args.objectives,
            constraints={},
            approval_required=not args.no_approval,
            stealth_mode=args.stealth
        )
        
        # Execute workflow
        results = await orchestrator.execute_workflow(args.workflow, context)
        
        # Generate report
        report = orchestrator.generate_operation_report(results)
        
        # Output results
        output_data = {
            "results": results,
            "report": report
        }
        
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(output_data, f, indent=2)
            print(f"Operation results saved to {args.output}")
        else:
            print(json.dumps(output_data, indent=2))
        
        # Cleanup
        await orchestrator.cleanup_operation(context.operation_id)
    
    # Run the async operation
    asyncio.run(run_operation())

if __name__ == "__main__":
    main()
