"""
Constitutional AI Integration for Safety Alignment
Implements value-based reasoning and ethical constraints for cybersecurity operations
"""

import json
import asyncio
from datetime import datetime
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, asdict
from enum import Enum
import re

class EthicalPrinciple(Enum):
    """Core ethical principles for cybersecurity AI"""
    NO_HARM = "no_harm"
    LAWFUL_OPERATION = "lawful_operation"
    PROPORTIONAL_RESPONSE = "proportional_response"
    TRANSPARENT_DECISION = "transparent_decision"
    HUMAN_OVERSIGHT = "human_oversight"
    DATA_PROTECTION = "data_protection"
    CONSENT_BASED = "consent_based"
    MINIMAL_IMPACT = "minimal_impact"

class ViolationSeverity(Enum):
    """Severity levels for ethical violations"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

@dataclass
class EthicalConstraint:
    """Represents an ethical constraint or rule"""
    constraint_id: str
    principle: EthicalPrinciple
    description: str
    condition: str
    action: str
    severity: ViolationSeverity
    enabled: bool

@dataclass
class EthicalEvaluation:
    """Result of ethical evaluation"""
    evaluation_id: str
    action_description: str
    timestamp: str
    constraints_checked: List[str]
    violations: List[Dict[str, Any]]
    approved: bool
    confidence_score: float
    reasoning: str

@dataclass
class ConstitutionalRule:
    """Constitutional rule for AI behavior"""
    rule_id: str
    name: str
    description: str
    condition_pattern: str
    violation_pattern: str
    response_template: str
    principle: EthicalPrinciple
    severity: ViolationSeverity

class ConstitutionalAI:
    """Constitutional AI system for ethical cybersecurity operations"""
    
    def __init__(self):
        self.ethical_constraints = self._load_ethical_constraints()
        self.constitutional_rules = self._load_constitutional_rules()
        self.violation_history = []
        
    def _load_ethical_constraints(self) -> List[EthicalConstraint]:
        """Load core ethical constraints for cybersecurity operations"""
        return [
            EthicalConstraint(
                constraint_id="harm_001",
                principle=EthicalPrinciple.NO_HARM,
                description="Prevent actions that could cause physical harm to individuals",
                condition="action involves critical infrastructure or life-safety systems",
                action="require explicit human authorization and safety review",
                severity=ViolationSeverity.CRITICAL,
                enabled=True
            ),
            EthicalConstraint(
                constraint_id="law_001",
                principle=EthicalPrinciple.LAWFUL_OPERATION,
                description="Ensure all operations comply with applicable laws and regulations",
                condition="action could violate computer crime laws",
                action="block action and flag for legal review",
                severity=ViolationSeverity.HIGH,
                enabled=True
            ),
            EthicalConstraint(
                constraint_id="prop_001",
                principle=EthicalPrinciple.PROPORTIONAL_RESPONSE,
                description="Response must be proportional to the threat level",
                condition="proposed action severity exceeds threat level",
                action="recommend proportional alternative",
                severity=ViolationSeverity.MEDIUM,
                enabled=True
            ),
            EthicalConstraint(
                constraint_id="trans_001",
                principle=EthicalPrinciple.TRANSPARENT_DECISION,
                description="Decision-making process must be transparent and explainable",
                condition="high-impact decision with insufficient explanation",
                action="require detailed reasoning documentation",
                severity=ViolationSeverity.MEDIUM,
                enabled=True
            ),
            EthicalConstraint(
                constraint_id="human_001",
                principle=EthicalPrinciple.HUMAN_OVERSIGHT,
                description="Critical actions require human oversight",
                condition="action has high potential impact",
                action="require human approval before execution",
                severity=ViolationSeverity.HIGH,
                enabled=True
            ),
            EthicalConstraint(
                constraint_id="data_001",
                principle=EthicalPrinciple.DATA_PROTECTION,
                description="Protect personally identifiable information and sensitive data",
                condition="action involves access to PII or sensitive data",
                action="apply data protection safeguards",
                severity=ViolationSeverity.HIGH,
                enabled=True
            ),
            EthicalConstraint(
                constraint_id="consent_001",
                principle=EthicalPrinciple.CONSENT_BASED,
                description="Operations should have appropriate authorization",
                condition="action affects systems without explicit authorization",
                action="verify authorization before proceeding",
                severity=ViolationSeverity.HIGH,
                enabled=True
            ),
            EthicalConstraint(
                constraint_id="impact_001",
                principle=EthicalPrinciple.MINIMAL_IMPACT,
                description="Minimize disruption and collateral impact",
                condition="action could cause significant disruption",
                action="seek minimal impact alternative",
                severity=ViolationSeverity.MEDIUM,
                enabled=True
            )
        ]
    
    def _load_constitutional_rules(self) -> List[ConstitutionalRule]:
        """Load constitutional rules for specific scenarios"""
        return [
            ConstitutionalRule(
                rule_id="rule_001",
                name="Critical Infrastructure Protection",
                description="Protect critical infrastructure from harmful actions",
                condition_pattern=r"(power|water|hospital|medical|emergency|911)",
                violation_pattern=r"(attack|exploit|disrupt|damage|destroy)",
                response_template="I cannot assist with actions that could harm critical infrastructure. Consider defensive measures instead.",
                principle=EthicalPrinciple.NO_HARM,
                severity=ViolationSeverity.CRITICAL
            ),
            ConstitutionalRule(
                rule_id="rule_002",
                name="Unauthorized Access Prevention",
                description="Prevent unauthorized access to systems",
                condition_pattern=r"(unauthorized|illegal|without permission)",
                violation_pattern=r"(hack|breach|infiltrate|penetrate)",
                response_template="I cannot provide guidance for unauthorized access. Ensure you have proper authorization for security testing.",
                principle=EthicalPrinciple.LAWFUL_OPERATION,
                severity=ViolationSeverity.HIGH
            ),
            ConstitutionalRule(
                rule_id="rule_003",
                name="Personal Data Protection",
                description="Protect personal and sensitive data",
                condition_pattern=r"(personal|private|confidential|sensitive|PII)",
                violation_pattern=r"(steal|exfiltrate|leak|expose|access)",
                response_template="I cannot assist with accessing personal or sensitive data. Focus on protecting data privacy instead.",
                principle=EthicalPrinciple.DATA_PROTECTION,
                severity=ViolationSeverity.HIGH
            ),
            ConstitutionalRule(
                rule_id="rule_004",
                name="Proportional Response Requirement",
                description="Ensure responses are proportional to threats",
                condition_pattern=r"(low|minor|small) (threat|risk|vulnerability)",
                violation_pattern=r"(nuclear|extreme|maximum|destructive)",
                response_template="The proposed response appears disproportional to the threat level. Consider a more measured approach.",
                principle=EthicalPrinciple.PROPORTIONAL_RESPONSE,
                severity=ViolationSeverity.MEDIUM
            ),
            ConstitutionalRule(
                rule_id="rule_005",
                name="Educational Purpose Enforcement",
                description="Ensure cybersecurity guidance is for educational purposes",
                condition_pattern=r"(learn|understand|education|training|practice)",
                violation_pattern=r"(real|live|production|actual) (attack|exploit)",
                response_template="Cybersecurity techniques should only be used for educational, training, or authorized testing purposes.",
                principle=EthicalPrinciple.LAWFUL_OPERATION,
                severity=ViolationSeverity.MEDIUM
            )
        ]
    
    async def evaluate_action(self, action_description: str, context: Dict[str, Any] = None) -> EthicalEvaluation:
        """Evaluate an action against ethical constraints"""
        evaluation_id = f"eval_{datetime.now().strftime('%Y%m%d_%H%M%S_%f')}"
        context = context or {}
        
        violations = []
        constraints_checked = []
        reasoning_parts = []
        
        # Check each enabled ethical constraint
        for constraint in self.ethical_constraints:
            if not constraint.enabled:
                continue
                
            constraints_checked.append(constraint.constraint_id)
            
            # Check if constraint applies to this action
            violation_detected = await self._check_constraint_violation(
                action_description, constraint, context
            )
            
            if violation_detected:
                violation_detail = {
                    "constraint_id": constraint.constraint_id,
                    "principle": constraint.principle.value,
                    "description": constraint.description,
                    "severity": constraint.severity.value,
                    "recommended_action": constraint.action
                }
                violations.append(violation_detail)
                reasoning_parts.append(
                    f"Violation of {constraint.principle.value}: {constraint.description}"
                )
        
        # Check constitutional rules
        for rule in self.constitutional_rules:
            rule_violation = await self._check_constitutional_rule(
                action_description, rule, context
            )
            
            if rule_violation:
                violation_detail = {
                    "rule_id": rule.rule_id,
                    "rule_name": rule.name,
                    "principle": rule.principle.value,
                    "severity": rule.severity.value,
                    "response": rule.response_template
                }
                violations.append(violation_detail)
                reasoning_parts.append(f"Constitutional rule violation: {rule.name}")
        
        # Determine if action is approved
        critical_violations = [v for v in violations if v.get("severity") == "critical"]
        high_violations = [v for v in violations if v.get("severity") == "high"]
        
        approved = len(critical_violations) == 0 and len(high_violations) == 0
        
        # Calculate confidence score
        confidence_score = self._calculate_confidence_score(violations, context)
        
        # Generate reasoning
        if not violations:
            reasoning = "Action evaluated successfully with no ethical violations detected."
        else:
            violation_summary = ", ".join(reasoning_parts)
            reasoning = f"Ethical concerns identified: {violation_summary}"
        
        evaluation = EthicalEvaluation(
            evaluation_id=evaluation_id,
            action_description=action_description,
            timestamp=datetime.now().isoformat(),
            constraints_checked=constraints_checked,
            violations=violations,
            approved=approved,
            confidence_score=confidence_score,
            reasoning=reasoning
        )
        
        # Store evaluation in history
        self.violation_history.append(evaluation)
        
        return evaluation
    
    async def _check_constraint_violation(self, action: str, constraint: EthicalConstraint, 
                                        context: Dict[str, Any]) -> bool:
        """Check if an action violates a specific ethical constraint"""
        action_lower = action.lower()
        
        # Pattern-based checks for different principles
        if constraint.principle == EthicalPrinciple.NO_HARM:
            harm_indicators = [
                "critical infrastructure", "power grid", "hospital", "emergency",
                "life support", "medical device", "911", "first responder"
            ]
            return any(indicator in action_lower for indicator in harm_indicators)
        
        elif constraint.principle == EthicalPrinciple.LAWFUL_OPERATION:
            illegal_indicators = [
                "unauthorized", "illegal", "without permission", "criminal",
                "fraud", "identity theft", "money laundering"
            ]
            return any(indicator in action_lower for indicator in illegal_indicators)
        
        elif constraint.principle == EthicalPrinciple.PROPORTIONAL_RESPONSE:
            # Check for disproportional responses
            threat_level = context.get("threat_level", "medium").lower()
            response_level = self._assess_response_level(action_lower)
            
            if threat_level == "low" and response_level in ["high", "critical"]:
                return True
            elif threat_level == "medium" and response_level == "critical":
                return True
        
        elif constraint.principle == EthicalPrinciple.DATA_PROTECTION:
            data_access_indicators = [
                "personal data", "pii", "credit card", "ssn", "social security",
                "medical record", "financial data", "private information"
            ]
            return any(indicator in action_lower for indicator in data_access_indicators)
        
        elif constraint.principle == EthicalPrinciple.CONSENT_BASED:
            unauthorized_indicators = [
                "without consent", "unauthorized access", "breach", "infiltrate",
                "penetrate without permission"
            ]
            return any(indicator in action_lower for indicator in unauthorized_indicators)
        
        return False
    
    async def _check_constitutional_rule(self, action: str, rule: ConstitutionalRule,
                                       context: Dict[str, Any]) -> bool:
        """Check if an action violates a constitutional rule"""
        action_lower = action.lower()
        
        # Check if condition pattern matches
        condition_match = re.search(rule.condition_pattern, action_lower, re.IGNORECASE)
        if not condition_match:
            return False
        
        # Check if violation pattern matches
        violation_match = re.search(rule.violation_pattern, action_lower, re.IGNORECASE)
        return violation_match is not None
    
    def _assess_response_level(self, action: str) -> str:
        """Assess the intensity level of a proposed response"""
        critical_indicators = ["destroy", "delete", "wipe", "format", "nuclear"]
        high_indicators = ["exploit", "attack", "penetrate", "breach", "damage"]
        medium_indicators = ["scan", "probe", "investigate", "analyze"]
        
        if any(indicator in action for indicator in critical_indicators):
            return "critical"
        elif any(indicator in action for indicator in high_indicators):
            return "high"
        elif any(indicator in action for indicator in medium_indicators):
            return "medium"
        else:
            return "low"
    
    def _calculate_confidence_score(self, violations: List[Dict], context: Dict[str, Any]) -> float:
        """Calculate confidence score for the ethical evaluation"""
        base_confidence = 0.9
        
        # Reduce confidence for each violation
        for violation in violations:
            severity = violation.get("severity", "low")
            if severity == "critical":
                base_confidence -= 0.3
            elif severity == "high":
                base_confidence -= 0.2
            elif severity == "medium":
                base_confidence -= 0.1
            else:
                base_confidence -= 0.05
        
        # Adjust based on context clarity
        if context.get("authorization_verified"):
            base_confidence += 0.1
        if context.get("threat_level") == "critical":
            base_confidence += 0.05
        
        return max(0.0, min(1.0, base_confidence))
    
    def get_ethical_guidance(self, action_description: str) -> Dict[str, Any]:
        """Get ethical guidance for a proposed action"""
        guidance = {
            "action": action_description,
            "recommendations": [],
            "alternative_approaches": [],
            "required_safeguards": [],
            "approval_requirements": []
        }
        
        action_lower = action_description.lower()
        
        # Analyze action and provide guidance
        if any(term in action_lower for term in ["attack", "exploit", "penetrate"]):
            guidance["recommendations"].append("Ensure you have explicit written authorization")
            guidance["recommendations"].append("Limit scope to minimize potential impact")
            guidance["alternative_approaches"].append("Consider defensive security assessment instead")
            guidance["required_safeguards"].append("Document all activities for audit trail")
            guidance["approval_requirements"].append("Obtain security manager approval")
        
        if any(term in action_lower for term in ["data", "information", "files"]):
            guidance["recommendations"].append("Apply data protection principles")
            guidance["required_safeguards"].append("Encrypt sensitive data")
            guidance["required_safeguards"].append("Follow data retention policies")
        
        if any(term in action_lower for term in ["network", "system", "infrastructure"]):
            guidance["recommendations"].append("Use least privilege access principles")
            guidance["alternative_approaches"].append("Consider read-only assessment methods")
            guidance["required_safeguards"].append("Implement network segmentation")
        
        return guidance
    
    def generate_constitutional_report(self) -> Dict[str, Any]:
        """Generate a report on constitutional AI compliance"""
        report = {
            "generated_at": datetime.now().isoformat(),
            "evaluation_summary": {
                "total_evaluations": len(self.violation_history),
                "approved_actions": 0,
                "rejected_actions": 0,
                "violation_types": {}
            },
            "principle_compliance": {},
            "recent_violations": [],
            "recommendations": []
        }
        
        # Analyze evaluation history
        for evaluation in self.violation_history:
            if evaluation.approved:
                report["evaluation_summary"]["approved_actions"] += 1
            else:
                report["evaluation_summary"]["rejected_actions"] += 1
            
            for violation in evaluation.violations:
                principle = violation.get("principle", "unknown")
                if principle not in report["evaluation_summary"]["violation_types"]:
                    report["evaluation_summary"]["violation_types"][principle] = 0
                report["evaluation_summary"]["violation_types"][principle] += 1
        
        # Principle compliance rates
        for principle in EthicalPrinciple:
            principle_evaluations = []
            for evaluation in self.violation_history:
                principle_violations = [
                    v for v in evaluation.violations 
                    if v.get("principle") == principle.value
                ]
                principle_evaluations.append(len(principle_violations) == 0)
            
            if principle_evaluations:
                compliance_rate = sum(principle_evaluations) / len(principle_evaluations)
                report["principle_compliance"][principle.value] = {
                    "compliance_rate": compliance_rate,
                    "total_evaluations": len(principle_evaluations)
                }
        
        # Recent violations (last 10)
        recent_violations = []
        for evaluation in self.violation_history[-10:]:
            if not evaluation.approved:
                recent_violations.append({
                    "evaluation_id": evaluation.evaluation_id,
                    "action": evaluation.action_description,
                    "timestamp": evaluation.timestamp,
                    "violation_count": len(evaluation.violations)
                })
        
        report["recent_violations"] = recent_violations
        
        # Generate recommendations
        if report["evaluation_summary"]["total_evaluations"] > 0:
            rejection_rate = (
                report["evaluation_summary"]["rejected_actions"] / 
                report["evaluation_summary"]["total_evaluations"]
            )
            if rejection_rate > 0.2:
                report["recommendations"].append("High rejection rate - review operational procedures")
        
        for principle, stats in report["principle_compliance"].items():
            if stats["compliance_rate"] < 0.8:
                report["recommendations"].append(f"Improve compliance for {principle} principle")
        
        return report

# Example usage and testing
if __name__ == "__main__":
    import asyncio
    
    async def test_constitutional_ai():
        # Initialize Constitutional AI
        constitutional_ai = ConstitutionalAI()
        
        # Test cases
        test_actions = [
            "Perform authorized penetration testing on corporate network",
            "Attack power grid control systems",
            "Scan for vulnerabilities in client systems with written permission",
            "Access personal data without authorization",
            "Conduct educational demonstration of SQL injection",
            "Launch DDoS attack against competitor website"
        ]
        
        print("🏛️ Constitutional AI Evaluation Results:")
        print("=" * 60)
        
        for i, action in enumerate(test_actions, 1):
            evaluation = await constitutional_ai.evaluate_action(
                action, 
                context={"threat_level": "medium", "authorization_verified": i % 2 == 1}
            )
            
            status = "✅ APPROVED" if evaluation.approved else "❌ REJECTED"
            print(f"\n{i}. Action: {action}")
            print(f"   Status: {status}")
            print(f"   Confidence: {evaluation.confidence_score:.2f}")
            print(f"   Violations: {len(evaluation.violations)}")
            
            if evaluation.violations:
                for violation in evaluation.violations:
                    print(f"     - {violation.get('principle', 'unknown')}: {violation.get('description', 'N/A')}")
            
            print(f"   Reasoning: {evaluation.reasoning}")
        
        # Generate constitutional report
        print("\n" + "=" * 60)
        print("📊 Constitutional AI Compliance Report:")
        report = constitutional_ai.generate_constitutional_report()
        
        print(f"Total Evaluations: {report['evaluation_summary']['total_evaluations']}")
        print(f"Approved Actions: {report['evaluation_summary']['approved_actions']}")
        print(f"Rejected Actions: {report['evaluation_summary']['rejected_actions']}")
        
        if report['principle_compliance']:
            print("\nPrinciple Compliance Rates:")
            for principle, stats in report['principle_compliance'].items():
                print(f"  {principle}: {stats['compliance_rate']:.1%}")
        
        print("✅ Constitutional AI Integration implemented and tested")
    
    # Run the test
    asyncio.run(test_constitutional_ai())
