import re
from typing import List, Tuple, Optional
from gateway.shared.schemas import (
    AnalysisResult, RiskLevel, SecurityDecision, 
    AgentRestrictions, SecurityAssessment, ContentIntent
)
from gateway.shared.config_loader import get_config


class PolicyEngine:
    """
    Enhanced policy engine with intent-first enforcement and fail-closed defaults.
    Implements strict security rules to prevent instructional content from bypassing controls.
    """
    
    def __init__(self):
        self.config = get_config()
        
        # Load from config with fallbacks
        self.risk_weights = self.config.get_risk_weights()
        self.decision_thresholds = self.config.get_decision_thresholds()
        self.intent_risk_floors = self._convert_intent_floors()
        self.baseline_risks = self.config.get_baseline_risks()
        
        # Enforcement flags
        self.fail_closed = self.config.get('enforcement', 'fail_closed', default=True)
        self.strict_intent_enforcement = self.config.get('enforcement', 'strict_intent_enforcement', default=True)
    
    def _convert_intent_floors(self) -> dict:
        """Convert string intent keys to ContentIntent enum keys."""
        raw_floors = self.config.get_intent_risk_floors()
        
        intent_map = {
            'malicious': ContentIntent.MALICIOUS,
            'conditional_instructional': ContentIntent.CONDITIONAL_INSTRUCTIONAL,
            'instructional': ContentIntent.INSTRUCTIONAL,
            'ambiguous': ContentIntent.AMBIGUOUS,
            'descriptive': ContentIntent.DESCRIPTIVE,
        }
        
        return {intent_map[k]: v for k, v in raw_floors.items() if k in intent_map}
    
    def make_decision(
        self, 
        analysis_results: List[AnalysisResult],
        visible_text: str,
        hidden_elements: List[str]
    ) -> SecurityAssessment:
        """Generate comprehensive security assessment with strict enforcement."""
        
        overall_risk, risk_score = self._calculate_overall_risk(analysis_results)
        
        primary_intent, intent_confidence = self._determine_primary_intent(analysis_results)
        
        # INTENT-FIRST ENFORCEMENT: Intent determines minimum decision level
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
        """
        Calculate weighted overall risk with intent-first approach and baseline floors.
        Ensures risk is monotonic and cumulative.
        """
        
        risk_values = {
            RiskLevel.SAFE: 0.0,
            RiskLevel.LOW: 0.25,
            RiskLevel.MEDIUM: 0.5,
            RiskLevel.HIGH: 0.75,
            RiskLevel.CRITICAL: 1.0,
        }
        
        # 1. Get intent-based risk floor
        intent_result = next(
            (r for r in results if r.module_name == "intent_classifier"),
            None
        )
        
        intent_floor = 0.0
        if intent_result and intent_result.detected_intent:
            intent_floor = self.intent_risk_floors.get(
                intent_result.detected_intent, 
                0.3  # Default floor for unknown intent
            )
        
        # 2. Calculate weighted risk from all modules
        weighted_sum = 0.0
        total_weight = 0.0
        
        for result in results:
            weight = self.risk_weights.get(result.module_name, 0.05)
            
            # Use explicit risk_score if available, otherwise convert risk_level
            risk_score = result.risk_score if result.risk_score > 0 else risk_values[result.risk_level]
            weighted_risk = risk_score * result.confidence * weight
            
            weighted_sum += weighted_risk
            total_weight += weight
        
        calculated_risk = weighted_sum / total_weight if total_weight > 0 else 0.0
        
        # 3. Apply intent floor (risk cannot be below intent-based minimum)
        risk_score = max(calculated_risk, intent_floor)
        
        # 4. Add baseline risks for specific content types
        risk_score = self._apply_baseline_risks(risk_score, results)
        
        # 5. Boost risk for high-severity modules
        agentic_result = next(
            (r for r in results if r.module_name == "agentic_intent_detector"),
            None
        )
        
        if agentic_result and agentic_result.risk_level not in [RiskLevel.SAFE, RiskLevel.LOW]:
            risk_score = max(risk_score, 0.5)  # Agentic intent floor
        
        deobfuscator_result = next(
            (r for r in results if r.module_name == "content_deobfuscator"),
            None
        )
        
        if deobfuscator_result and deobfuscator_result.risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]:
            # Decoded content with high risk is very suspicious
            risk_score = max(risk_score, 0.6)
        
        # 6. Ensure risk is non-zero for non-descriptive content
        if intent_result and intent_result.detected_intent != ContentIntent.DESCRIPTIVE:
            risk_score = max(risk_score, 0.2)  # Minimum for any instructional content
        
        # 7. Convert to risk level
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
        
        return overall_risk, min(1.0, risk_score)
    
    def _apply_baseline_risks(self, current_risk: float, results: List[AnalysisResult]) -> float:
        """Apply baseline risk increases for specific content types."""
        
        risk = current_risk
        
        # OCR content baseline
        ocr_result = next(
            (r for r in results if r.module_name == "ocr_content_analyzer"),
            None
        )
        if ocr_result and ocr_result.risk_level != RiskLevel.SAFE:
            baseline = self.baseline_risks.get('ocr_extracted', 0.25)
            risk = max(risk, baseline)
        
        # Decoded content baseline
        deobfuscator_result = next(
            (r for r in results if r.module_name == "content_deobfuscator"),
            None
        )
        if deobfuscator_result and deobfuscator_result.risk_level != RiskLevel.SAFE:
            baseline = self.baseline_risks.get('decoded_content', 0.20)
            risk = max(risk, baseline)
        
        # Hidden content baseline
        hidden_result = next(
            (r for r in results if r.module_name == "hidden_content_analyzer"),
            None
        )
        if hidden_result and hidden_result.risk_level != RiskLevel.SAFE:
            baseline = self.baseline_risks.get('hidden_elements', 0.15)
            risk = max(risk, baseline)
        
        return risk
    
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
        
        # Fail closed: treat unknown intent as ambiguous
        return ContentIntent.AMBIGUOUS, 0.5
    
    def _determine_decision(
        self, 
        risk_level: RiskLevel, 
        risk_score: float,
        analysis_results: List[AnalysisResult],
        primary_intent: ContentIntent
    ) -> SecurityDecision:
        """
        STRICT INTENT-FIRST ENFORCEMENT.
        
        Hard rules:
        - MALICIOUS intent → BLOCK
        - CONDITIONAL_INSTRUCTIONAL → BLOCK or REQUIRE_APPROVAL (never ALLOW)
        - INSTRUCTIONAL → BLOCK, REQUIRE_APPROVAL, or SANITIZE (never ALLOW)
        - AMBIGUOUS → Fail closed (REQUIRE_APPROVAL or SANITIZE)
        - DESCRIPTIVE + low risk → Can ALLOW
        """
        
        # RULE 1: Malicious intent = immediate block
        if primary_intent == ContentIntent.MALICIOUS:
            return SecurityDecision.BLOCK
        
        # RULE 2: Conditional AI-targeted instructions
        if primary_intent == ContentIntent.CONDITIONAL_INSTRUCTIONAL:
            if risk_score >= 0.8:
                return SecurityDecision.BLOCK
            else:
                return SecurityDecision.REQUIRE_APPROVAL  # Never ALLOW
        
        # RULE 3: General instructional content
        if primary_intent == ContentIntent.INSTRUCTIONAL:
            if self.strict_intent_enforcement:
                # Strict mode: instructions never auto-allow
                if risk_score >= 0.8:
                    return SecurityDecision.BLOCK
                elif risk_score >= 0.5:
                    return SecurityDecision.REQUIRE_APPROVAL
                else:
                    return SecurityDecision.SANITIZE  # Minimum: sanitize
            else:
                # Legacy mode (not recommended)
                if risk_score >= 0.8:
                    return SecurityDecision.BLOCK
                elif risk_score >= 0.5:
                    return SecurityDecision.REQUIRE_APPROVAL
                else:
                    return SecurityDecision.SANITIZE
        
        # RULE 4: Ambiguous intent - fail closed
        if primary_intent == ContentIntent.AMBIGUOUS:
            if self.fail_closed:
                if risk_score >= 0.6:
                    return SecurityDecision.BLOCK
                elif risk_score >= 0.3:
                    return SecurityDecision.REQUIRE_APPROVAL
                else:
                    return SecurityDecision.SANITIZE  # Don't allow ambiguous
            else:
                if risk_score >= 0.6:
                    return SecurityDecision.BLOCK
                elif risk_score >= 0.3:
                    return SecurityDecision.REQUIRE_APPROVAL
                else:
                    return SecurityDecision.SANITIZE
        
        # RULE 5: Check for agentic intent (overrides descriptive classification)
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
        
        # RULE 6: Threshold-based decisions (for descriptive content)
        if risk_score >= self.decision_thresholds["block"]:
            return SecurityDecision.BLOCK
        
        elif risk_score >= self.decision_thresholds["require_approval"]:
            return SecurityDecision.REQUIRE_APPROVAL
        
        elif risk_score >= self.decision_thresholds["sanitize"]:
            return SecurityDecision.SANITIZE
        
        # RULE 7: ALLOW only for truly safe descriptive content
        elif primary_intent == ContentIntent.DESCRIPTIVE and risk_score < self.decision_thresholds["allow"]:
            return SecurityDecision.ALLOW
        
        else:
            # Default: sanitize (fail safe)
            return SecurityDecision.SANITIZE
    
    def _determine_restrictions(
        self, 
        risk_level: RiskLevel, 
        results: List[AnalysisResult],
        primary_intent: ContentIntent
    ) -> AgentRestrictions:
        """Determine agent capability restrictions based on threats detected."""
        
        restrictions = AgentRestrictions()
        
        # Intent-based restriction modes
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
        
        # Threat-specific restrictions
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
        
        # Include semantic analysis if present
        semantic_result = next(
            (r for r in results if r.module_name == "semantic_threat_detector"),
            None
        )
        
        if semantic_result and semantic_result.risk_level != RiskLevel.SAFE:
            reasoning_parts.append("Semantic Analysis:")
            reasoning_parts.append(f"- {semantic_result.details}")
            reasoning_parts.append("")
        
        # Include deobfuscation results if present
        deobfuscator_result = next(
            (r for r in results if r.module_name == "content_deobfuscator"),
            None
        )
        
        if deobfuscator_result and deobfuscator_result.risk_level != RiskLevel.SAFE:
            reasoning_parts.append("De-obfuscation Analysis:")
            reasoning_parts.append(f"- {deobfuscator_result.details}")
            reasoning_parts.append("")
        
        # Include OCR results if present
        ocr_result = next(
            (r for r in results if r.module_name == "ocr_content_analyzer"),
            None
        )
        
        if ocr_result and ocr_result.risk_level != RiskLevel.SAFE:
            reasoning_parts.append("OCR Analysis:")
            reasoning_parts.append(f"- {ocr_result.details}")
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
            if result.module_name in ["agentic_intent_detector", "intent_classifier", 
                                      "semantic_threat_detector", "content_deobfuscator", 
                                      "ocr_content_analyzer"]:
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
                "Action: Content BLOCKED due to critical security threats or malicious/instructional intent."
            )
        elif decision == SecurityDecision.REQUIRE_APPROVAL:
            reasoning_parts.append(
                "Action: HUMAN APPROVAL REQUIRED - instructional, agentic, or ambiguous content detected."
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