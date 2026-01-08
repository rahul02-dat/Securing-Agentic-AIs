import re
from typing import List, Tuple, Optional
from gateway.shared.schemas import (
    AnalysisResult, RiskLevel, SecurityDecision, 
    AgentRestrictions, SecurityAssessment, ContentIntent
)


class PolicyEngine:
    """Makes security decisions and determines agent restrictions based on analysis."""
    
    def __init__(self):
        self.risk_weights = {
            "intent_classifier": 0.35,
            "hidden_content_analyzer": 0.15,
            "prompt_injection_detector": 0.2,
            "exfiltration_detector": 0.15,
            "agentic_intent_detector": 0.15,
        }
        
        self.decision_thresholds = {
            "block": 0.75,
            "require_approval": 0.4,
            "sanitize": 0.2,
            "allow": 0.0,
        }
        
        self.intent_risk_floors = {
            ContentIntent.MALICIOUS: 0.95,
            ContentIntent.CONDITIONAL_INSTRUCTIONAL: 0.7,
            ContentIntent.INSTRUCTIONAL: 0.5,
            ContentIntent.AMBIGUOUS: 0.3,
            ContentIntent.DESCRIPTIVE: 0.0,
        }
    
    def make_decision(
        self, 
        analysis_results: List[AnalysisResult],
        visible_text: str,
        hidden_elements: List[str]
    ) -> SecurityAssessment:
        """Generate comprehensive security assessment and decision."""
        
        overall_risk, risk_score = self._calculate_overall_risk(analysis_results)
        
        primary_intent, intent_confidence = self._determine_primary_intent(analysis_results)
        
        decision = self._determine_decision(
            overall_risk, 
            risk_score, 
            analysis_results,
            primary_intent
        )
        
        restrictions = self._determine_restrictions(
            overall_risk, 
            analysis_results,
            primary_intent
        )
        
        sanitized_content = None
        if decision == SecurityDecision.SANITIZE:
            sanitized_content = self._sanitize_content(visible_text, analysis_results)
        
        reasoning = self._generate_reasoning(
            analysis_results, overall_risk, risk_score, decision, primary_intent
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
            reasoning=reasoning,
            primary_intent=primary_intent,
            intent_confidence=intent_confidence
        )
        
        return assessment
    
    def _calculate_overall_risk(
        self, 
        results: List[AnalysisResult]
    ) -> Tuple[RiskLevel, float]:
        """Calculate weighted overall risk from all analysis modules with intent-first approach."""
        
        risk_values = {
            RiskLevel.SAFE: 0.0,
            RiskLevel.LOW: 0.25,
            RiskLevel.MEDIUM: 0.5,
            RiskLevel.HIGH: 0.75,
            RiskLevel.CRITICAL: 1.0,
        }
        
        intent_result = next(
            (r for r in results if r.module_name == "intent_classifier"),
            None
        )
        
        if intent_result and intent_result.detected_intent:
            intent_floor = self.intent_risk_floors.get(
                intent_result.detected_intent, 
                0.0
            )
        else:
            intent_floor = 0.0
        
        weighted_sum = 0.0
        total_weight = 0.0
        
        for result in results:
            weight = self.risk_weights.get(result.module_name, 0.1)
            
            risk_score = result.risk_score if result.risk_score > 0 else risk_values[result.risk_level]
            weighted_risk = risk_score * result.confidence * weight
            
            weighted_sum += weighted_risk
            total_weight += weight
        
        calculated_risk = weighted_sum / total_weight if total_weight > 0 else 0.0
        
        risk_score = max(calculated_risk, intent_floor)
        
        agentic_result = next(
            (r for r in results if r.module_name == "agentic_intent_detector"),
            None
        )
        
        if agentic_result and agentic_result.risk_level not in [RiskLevel.SAFE, RiskLevel.LOW]:
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
    
    def _determine_primary_intent(
        self,
        analysis_results: List[AnalysisResult]
    ) -> Tuple[ContentIntent, float]:
        """Determine primary content intent from analysis results."""
        
        intent_result = next(
            (r for r in analysis_results if r.module_name == "intent_classifier"),
            None
        )
        
        if intent_result and intent_result.detected_intent:
            return intent_result.detected_intent, intent_result.confidence
        
        return ContentIntent.AMBIGUOUS, 0.5
    
    def _determine_decision(
        self, 
        risk_level: RiskLevel, 
        risk_score: float,
        analysis_results: List[AnalysisResult],
        primary_intent: ContentIntent
    ) -> SecurityDecision:
        """Determine action based on risk assessment with intent-first enforcement."""
        
        if primary_intent == ContentIntent.MALICIOUS:
            return SecurityDecision.BLOCK
        
        if primary_intent == ContentIntent.CONDITIONAL_INSTRUCTIONAL:
            if risk_score >= 0.8:
                return SecurityDecision.BLOCK
            else:
                return SecurityDecision.REQUIRE_APPROVAL
        
        if primary_intent == ContentIntent.INSTRUCTIONAL:
            if risk_score >= 0.8:
                return SecurityDecision.BLOCK
            elif risk_score >= 0.5:
                return SecurityDecision.REQUIRE_APPROVAL
            else:
                return SecurityDecision.SANITIZE
        
        if primary_intent == ContentIntent.AMBIGUOUS:
            if risk_score >= 0.6:
                return SecurityDecision.BLOCK
            elif risk_score >= 0.3:
                return SecurityDecision.REQUIRE_APPROVAL
            else:
                return SecurityDecision.SANITIZE
        
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
                f.get('type') in ['permission_bypass', 'link_action']
                for f in agentic_result.findings
            )
            
            if has_bypass or risk_score >= 0.75:
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
        
        elif primary_intent == ContentIntent.DESCRIPTIVE and risk_score < 0.15:
            return SecurityDecision.ALLOW
        
        else:
            return SecurityDecision.SANITIZE
    
    def _determine_restrictions(
        self, 
        risk_level: RiskLevel, 
        results: List[AnalysisResult],
        primary_intent: ContentIntent
    ) -> AgentRestrictions:
        """Determine agent capability restrictions based on threats detected."""
        
        restrictions = AgentRestrictions()
        
        if primary_intent in [ContentIntent.MALICIOUS, ContentIntent.CONDITIONAL_INSTRUCTIONAL]:
            restrictions.mode = "ACTION_DISABLED"
            restrictions.allow_web_access = False
            restrictions.allow_file_write = False
            restrictions.allow_code_execution = False
            restrictions.allow_tool_use = False
            restrictions.max_output_length = 500
            restrictions.requires_approval = True
            restrictions.approval_reason = f"Content classified as {primary_intent.value}"
            return restrictions
        
        if primary_intent == ContentIntent.INSTRUCTIONAL:
            restrictions.mode = "APPROVAL_REQUIRED"
            restrictions.allow_web_access = False
            restrictions.allow_file_write = False
            restrictions.allow_code_execution = False
            restrictions.allow_tool_use = False
            restrictions.max_output_length = 1000
            restrictions.requires_approval = True
            restrictions.approval_reason = "Instructional content requires approval"
            return restrictions
        
        if primary_intent == ContentIntent.AMBIGUOUS:
            restrictions.mode = "READ_ONLY"
            restrictions.allow_web_access = False
            restrictions.allow_file_write = False
            restrictions.allow_code_execution = False
            restrictions.allow_tool_use = False
            restrictions.max_output_length = 1500
            return restrictions
        
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
        has_link_actions = False
        if agentic_result:
            has_permission_bypass = any(
                f.get('type') == 'permission_bypass'
                for f in agentic_result.findings
            )
            has_link_actions = any(
                f.get('type') == 'link_action'
                for f in agentic_result.findings
            )
        
        if has_permission_bypass or has_link_actions:
            restrictions.mode = "ACTION_DISABLED"
            restrictions.allow_web_access = False
            restrictions.allow_file_write = False
            restrictions.allow_code_execution = False
            restrictions.allow_tool_use = False
            restrictions.max_output_length = 500
            restrictions.requires_approval = True
            restrictions.approval_reason = "Permission bypass or link action detected"
        
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
        
        if has_exfiltration or has_link_actions:
            restrictions.blocked_patterns.extend([
                r'https?://',
                r'send\s+to',
                r'post\s+to',
                r'upload',
                r'append\s+to',
                r'transmit'
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
        decision: SecurityDecision,
        primary_intent: ContentIntent
    ) -> str:
        """Generate human-readable explanation of the decision."""
        
        reasoning_parts = [
            f"PRIMARY INTENT: {primary_intent.value.upper()}",
            f"Risk Assessment: {risk_level.value.upper()} (score: {risk_score:.2f})",
            f"Decision: {decision.value.upper()}",
            ""
        ]
        
        intent_result = next(
            (r for r in results if r.module_name == "intent_classifier"),
            None
        )
        
        if intent_result:
            reasoning_parts.append("Intent Analysis:")
            reasoning_parts.append(f"- {intent_result.details}")
            reasoning_parts.append("")
        
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
            
            has_link_actions = any(
                f.get('type') == 'link_action'
                for f in agentic_result.findings
            )
            
            if has_bypass:
                reasoning_parts.append("- CRITICAL: Attempts to bypass user permission/approval")
            
            if has_link_actions:
                reasoning_parts.append("- CRITICAL: Link-based action or data exfiltration detected")
            
            reasoning_parts.append("")
        
        critical_findings = []
        high_findings = []
        
        for result in results:
            if result.module_name in ["agentic_intent_detector", "intent_classifier"]:
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
                "Action: Content BLOCKED due to critical security threats or malicious intent."
            )
        elif decision == SecurityDecision.REQUIRE_APPROVAL:
            reasoning_parts.append(
                "Action: HUMAN APPROVAL REQUIRED - instructional or agentic content detected."
            )
        elif decision == SecurityDecision.SANITIZE:
            reasoning_parts.append(
                "Action: Content sanitized - suspicious elements removed before processing."
            )
        else:
            reasoning_parts.append(
                "Action: Content allowed - classified as purely descriptive with minimal risk."
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