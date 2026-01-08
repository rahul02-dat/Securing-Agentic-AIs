import re
from typing import List, Tuple, Optional
from gateway.shared.schemas import (
    AnalysisResult, RiskLevel, SecurityDecision, 
    AgentRestrictions, SecurityAssessment
)


class PolicyEngine:
    """Makes security decisions and determines agent restrictions based on analysis."""
    
    def __init__(self):
        self.risk_weights = {
            "hidden_content_analyzer": 0.2,
            "prompt_injection_detector": 0.25,
            "exfiltration_detector": 0.25,
            "agentic_intent_detector": 0.3,
        }
        
        self.decision_thresholds = {
            "block": 0.8,
            "require_approval": 0.5,
            "sanitize": 0.3,
            "allow": 0.0,
        }
    
    def make_decision(
        self, 
        analysis_results: List[AnalysisResult],
        visible_text: str,
        hidden_elements: List[str]
    ) -> SecurityAssessment:
        """Generate comprehensive security assessment and decision."""
        
        overall_risk, risk_score = self._calculate_overall_risk(analysis_results)
        
        decision = self._determine_decision(overall_risk, risk_score, analysis_results)
        
        restrictions = self._determine_restrictions(overall_risk, analysis_results)
        
        sanitized_content = None
        if decision == SecurityDecision.SANITIZE:
            sanitized_content = self._sanitize_content(visible_text, analysis_results)
        
        reasoning = self._generate_reasoning(
            analysis_results, overall_risk, risk_score, decision
        )
        
        from datetime import datetime
        import uuid
        
        assessment = SecurityAssessment(
            input_id=str(uuid.uuid4()),
            timestamp=datetime.now(),
            input_type="text",
            source="gateway",
            content_blocks=[],
            analysis_results=analysis_results,
            overall_risk=overall_risk,
            risk_score=risk_score,
            decision=decision,
            restricted_capabilities=self._get_restricted_capabilities(restrictions),
            sanitized_content=sanitized_content,
            reasoning=reasoning
        )
        
        return assessment
    
    def _calculate_overall_risk(
        self, 
        results: List[AnalysisResult]
    ) -> Tuple[RiskLevel, float]:
        """Calculate weighted overall risk from all analysis modules."""
        
        risk_values = {
            RiskLevel.SAFE: 0.0,
            RiskLevel.LOW: 0.25,
            RiskLevel.MEDIUM: 0.5,
            RiskLevel.HIGH: 0.75,
            RiskLevel.CRITICAL: 1.0,
        }
        
        weighted_sum = 0.0
        total_weight = 0.0
        
        for result in results:
            weight = self.risk_weights.get(result.module_name, 0.2)
            
            risk_score = result.risk_score if result.risk_score > 0 else risk_values[result.risk_level]
            weighted_risk = risk_score * result.confidence * weight
            
            weighted_sum += weighted_risk
            total_weight += weight
        
        risk_score = weighted_sum / total_weight if total_weight > 0 else 0.0
        
        agentic_result = next(
            (r for r in results if r.module_name == "agentic_intent_detector"),
            None
        )
        
        if agentic_result and agentic_result.risk_level != RiskLevel.SAFE:
            risk_score = max(risk_score, 0.5)
        
        if risk_score >= 0.8:
            overall_risk = RiskLevel.CRITICAL
        elif risk_score >= 0.6:
            overall_risk = RiskLevel.HIGH
        elif risk_score >= 0.4:
            overall_risk = RiskLevel.MEDIUM
        elif risk_score >= 0.15:
            overall_risk = RiskLevel.LOW
        else:
            overall_risk = RiskLevel.SAFE
        
        return overall_risk, risk_score
    
    def _determine_decision(
        self, 
        risk_level: RiskLevel, 
        risk_score: float,
        analysis_results: List[AnalysisResult]
    ) -> SecurityDecision:
        """Determine action based on risk assessment."""
        
        agentic_result = next(
            (r for r in analysis_results if r.module_name == "agentic_intent_detector"),
            None
        )
        
        has_agentic_intent = (
            agentic_result and 
            agentic_result.risk_level not in [RiskLevel.SAFE, RiskLevel.LOW]
        )
        
        if has_agentic_intent:
            has_bypass = any(
                f.get('type') == 'permission_bypass'
                for f in agentic_result.findings
            )
            
            if has_bypass or risk_score >= 0.8:
                return SecurityDecision.BLOCK
            elif risk_score >= 0.4:
                return SecurityDecision.REQUIRE_APPROVAL
            else:
                return SecurityDecision.SANITIZE
        
        if risk_level == RiskLevel.CRITICAL or risk_score >= self.decision_thresholds["block"]:
            return SecurityDecision.BLOCK
        
        elif risk_score >= self.decision_thresholds["require_approval"]:
            return SecurityDecision.REQUIRE_APPROVAL
        
        elif risk_score >= self.decision_thresholds["sanitize"]:
            return SecurityDecision.SANITIZE
        
        else:
            return SecurityDecision.ALLOW
    
    def _determine_restrictions(
        self, 
        risk_level: RiskLevel, 
        results: List[AnalysisResult]
    ) -> AgentRestrictions:
        """Determine agent capability restrictions based on threats detected."""
        
        restrictions = AgentRestrictions()
        
        has_exfiltration = any(
            r.module_name == "exfiltration_detector" and 
            r.risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]
            for r in results
        )
        
        has_injection = any(
            r.module_name == "prompt_injection_detector" and 
            r.risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]
            for r in results
        )
        
        agentic_result = next(
            (r for r in results if r.module_name == "agentic_intent_detector"),
            None
        )
        
        has_agentic_intent = (
            agentic_result and 
            agentic_result.risk_level not in [RiskLevel.SAFE, RiskLevel.LOW]
        )
        
        has_permission_bypass = False
        if agentic_result:
            has_permission_bypass = any(
                f.get('type') == 'permission_bypass'
                for f in agentic_result.findings
            )
        
        if has_permission_bypass:
            restrictions.mode = "ACTION_DISABLED"
            restrictions.allow_web_access = False
            restrictions.allow_file_write = False
            restrictions.allow_code_execution = False
            restrictions.allow_tool_use = False
            restrictions.max_output_length = 500
            restrictions.requires_approval = True
            restrictions.approval_reason = "Permission bypass detected - all actions disabled"
        
        elif risk_level == RiskLevel.CRITICAL:
            restrictions.mode = "ACTION_DISABLED"
            restrictions.allow_web_access = False
            restrictions.allow_file_write = False
            restrictions.allow_code_execution = False
            restrictions.allow_tool_use = False
            restrictions.max_output_length = 500
        
        elif has_agentic_intent:
            restrictions.mode = "APPROVAL_REQUIRED"
            restrictions.allow_web_access = False
            restrictions.allow_file_write = False
            restrictions.allow_code_execution = False
            restrictions.allow_tool_use = False
            restrictions.max_output_length = 1000
            restrictions.requires_approval = True
            restrictions.approval_reason = "Agentic action request requires human approval"
        
        elif risk_level == RiskLevel.HIGH:
            restrictions.mode = "RESTRICTED"
            restrictions.allow_web_access = not has_exfiltration
            restrictions.allow_file_write = False
            restrictions.allow_code_execution = False
            restrictions.allow_tool_use = not has_injection
            restrictions.max_output_length = 1000
        
        elif risk_level == RiskLevel.MEDIUM:
            restrictions.mode = "READ_ONLY"
            restrictions.allow_web_access = not has_exfiltration
            restrictions.allow_file_write = False
            restrictions.allow_code_execution = False
            restrictions.max_output_length = 2000
        
        if has_exfiltration:
            restrictions.blocked_patterns.extend([
                r'https?://',
                r'send\s+to',
                r'post\s+to',
                r'upload'
            ])
        
        return restrictions
    
    def _sanitize_content(
        self, 
        content: str, 
        results: List[AnalysisResult]
    ) -> str:
        """Remove or neutralize dangerous content."""
        
        sanitized = content
        
        all_findings = []
        for result in results:
            all_findings.extend(result.findings)
        
        suspicious_phrases = []
        for finding in all_findings:
            if "matched_text" in finding:
                suspicious_phrases.append(finding["matched_text"])
        
        for phrase in suspicious_phrases:
            sanitized = sanitized.replace(phrase, "[REDACTED]")
        
        url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
        sanitized = re.sub(url_pattern, '[URL_REMOVED]', sanitized)
        
        suspicious_keywords = [
            'ignore previous', 'disregard', 'forget instructions',
            'new instructions', 'override', 'bypass'
        ]
        
        for keyword in suspicious_keywords:
            sanitized = re.sub(
                keyword, 
                '[SANITIZED]', 
                sanitized, 
                flags=re.IGNORECASE
            )
        
        return sanitized
    
    def _generate_reasoning(
        self,
        results: List[AnalysisResult],
        risk_level: RiskLevel,
        risk_score: float,
        decision: SecurityDecision
    ) -> str:
        """Generate human-readable explanation of the decision."""
        
        reasoning_parts = [
            f"Risk Assessment: {risk_level.value.upper()} (score: {risk_score:.2f})",
            f"Decision: {decision.value.upper()}",
            ""
        ]
        
        agentic_result = next(
            (r for r in results if r.module_name == "agentic_intent_detector"),
            None
        )
        
        if agentic_result and agentic_result.risk_level != RiskLevel.SAFE:
            reasoning_parts.append("AGENTIC INTENT DETECTED:")
            reasoning_parts.append(f"- {agentic_result.details}")
            
            requested_actions = []
            for finding in agentic_result.findings:
                if finding.get('type') == 'action_request':
                    requested_actions.append(finding.get('action'))
            
            if requested_actions:
                reasoning_parts.append(f"- Requested actions: {', '.join(set(requested_actions))}")
            
            has_bypass = any(
                f.get('type') == 'permission_bypass'
                for f in agentic_result.findings
            )
            
            if has_bypass:
                reasoning_parts.append("- CRITICAL: Attempts to bypass user permission/approval")
            
            reasoning_parts.append("")
        
        critical_findings = []
        high_findings = []
        
        for result in results:
            if result.module_name == "agentic_intent_detector":
                continue
            
            if result.risk_level == RiskLevel.CRITICAL:
                critical_findings.append(
                    f"- {result.module_name}: {result.details}"
                )
            elif result.risk_level == RiskLevel.HIGH:
                high_findings.append(
                    f"- {result.module_name}: {result.details}"
                )
        
        if critical_findings:
            reasoning_parts.append("Critical Threats:")
            reasoning_parts.extend(critical_findings)
            reasoning_parts.append("")
        
        if high_findings:
            reasoning_parts.append("High-Risk Findings:")
            reasoning_parts.extend(high_findings)
            reasoning_parts.append("")
        
        if decision == SecurityDecision.BLOCK:
            reasoning_parts.append(
                "Action: Content BLOCKED due to critical security threats."
            )
        elif decision == SecurityDecision.REQUIRE_APPROVAL:
            reasoning_parts.append(
                "Action: HUMAN APPROVAL REQUIRED - agentic action detected without user consent."
            )
        elif decision == SecurityDecision.SANITIZE:
            reasoning_parts.append(
                "Action: Content sanitized - suspicious elements removed before processing."
            )
        else:
            reasoning_parts.append(
                "Action: Content allowed with standard safety measures."
            )
        
        return "\n".join(reasoning_parts)
    
    def _get_restricted_capabilities(
        self, 
        restrictions: AgentRestrictions
    ) -> List[str]:
        """Extract list of restricted capabilities for logging."""
        
        restricted = []
        
        if restrictions.mode != "NORMAL":
            restricted.append(f"mode:{restrictions.mode}")
        
        if not restrictions.allow_web_access:
            restricted.append("web_access")
        if not restrictions.allow_file_write:
            restricted.append("file_write")
        if not restrictions.allow_code_execution:
            restricted.append("code_execution")
        if not restrictions.allow_tool_use:
            restricted.append("tool_use")
        if restrictions.max_output_length:
            restricted.append(f"output_limited_to_{restrictions.max_output_length}")
        if restrictions.requires_approval:
            restricted.append("requires_human_approval")
        
        return restricted