import re
from typing import List, Tuple, Optional
from gateway.shared.schemas import (
    AnalysisResult, RiskLevel, SecurityDecision, 
    AgentRestrictions, SecurityAssessment, ContentIntent
)
from gateway.shared.config_loader import get_config


class PolicyEngine:
    
    def __init__(self):
        self.config = get_config()
        
        self.risk_weights = self.config.get_risk_weights()
        self.decision_thresholds = self.config.get_decision_thresholds()
        self.intent_risk_floors = self._convert_intent_floors()
        self.baseline_risks = self.config.get_baseline_risks()
        
        self.fail_closed = self.config.get('enforcement', 'fail_closed', default=True)
        self.strict_intent_enforcement = self.config.get('enforcement', 'strict_intent_enforcement', default=True)
    
    def _convert_intent_floors(self) -> dict:
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
        
        intent_floor = 0.0
        if intent_result and intent_result.detected_intent:
            intent_floor = self.intent_risk_floors.get(
                intent_result.detected_intent, 
                0.3
            )
        
        weighted_sum = 0.0
        total_weight = 0.0
        
        for result in results:
            weight = self.risk_weights.get(result.module_name, 0.05)
            
            risk_score = result.risk_score if result.risk_score > 0 else risk_values[result.risk_level]
            weighted_risk = risk_score * result.confidence * weight
            
            weighted_sum += weighted_risk
            total_weight += weight
        
        calculated_risk = weighted_sum / total_weight if total_weight > 0 else 0.0
        
        risk_score = max(calculated_risk, intent_floor)
        
        risk_score = self._apply_baseline_risks_refined(risk_score, results)
        
        risk_score = self._apply_houyi_boost(risk_score, results)
        
        agentic_result = next(
            (r for r in results if r.module_name == "agentic_intent_detector"),
            None
        )
        
        if agentic_result and agentic_result.risk_level not in [RiskLevel.SAFE, RiskLevel.LOW]:
            agentic_has_threat_findings = any(
                f.get('severity') in ['high', 'critical']
                for f in agentic_result.findings
            )
            if agentic_has_threat_findings:
                risk_score = max(risk_score, 0.5)
        
        deobfuscator_result = next(
            (r for r in results if r.module_name == "content_deobfuscator"),
            None
        )
        
        if deobfuscator_result and deobfuscator_result.risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]:
            decoded_has_threats = any(
                f.get('type') == 'decoded_content' and f.get('suspicious_patterns')
                for f in deobfuscator_result.findings
            )
            if decoded_has_threats:
                risk_score = max(risk_score, 0.6)
        
        if intent_result and intent_result.detected_intent not in [ContentIntent.DESCRIPTIVE, ContentIntent.AMBIGUOUS]:
            risk_score = max(risk_score, 0.2)
        
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
    
    def _apply_baseline_risks_refined(self, current_risk: float, results: List[AnalysisResult]) -> float:
        
        risk = current_risk
        
        ocr_result = next(
            (r for r in results if r.module_name == "ocr_content_analyzer"),
            None
        )
        if ocr_result and ocr_result.risk_level not in [RiskLevel.SAFE, RiskLevel.LOW]:
            ocr_has_threats = any(
                f.get('type') in ['ocr_instruction', 'ocr_suspicious_keywords']
                for f in ocr_result.findings
            )
            if ocr_has_threats:
                baseline = self.baseline_risks.get('ocr_extracted', 0.25)
                risk = max(risk, baseline)
        
        deobfuscator_result = next(
            (r for r in results if r.module_name == "content_deobfuscator"),
            None
        )
        if deobfuscator_result and deobfuscator_result.risk_level not in [RiskLevel.SAFE, RiskLevel.LOW]:
            decoded_has_suspicious = any(
                f.get('type') == 'decoded_content' and f.get('suspicious_patterns')
                for f in deobfuscator_result.findings
            )
            if decoded_has_suspicious:
                baseline = self.baseline_risks.get('decoded_content', 0.20)
                risk = max(risk, baseline)
        
        hidden_result = next(
            (r for r in results if r.module_name == "hidden_content_analyzer"),
            None
        )
        if hidden_result and hidden_result.risk_level not in [RiskLevel.SAFE, RiskLevel.LOW]:
            hidden_has_threats = any(
                f.get('type') in ['instruction_keyword', 'dangerous_script']
                for f in hidden_result.findings
            )
            if hidden_has_threats:
                baseline = self.baseline_risks.get('hidden_elements', 0.15)
                risk = max(risk, baseline)
        
        return risk
    
    def _apply_houyi_boost(self, current_risk: float, results: List[AnalysisResult]) -> float:
        
        houyi_result = next(
            (r for r in results if r.module_name == "houyi_pattern_detector"),
            None
        )
        
        if not houyi_result:
            return current_risk
        
        if houyi_result.risk_level == RiskLevel.SAFE:
            return current_risk
        
        houyi_risk = houyi_result.risk_score
        
        has_all_components = False
        component_count = 0
        
        for finding in houyi_result.findings:
            if finding.get('type') in ['framework_component', 'separator', 'closure_separator', 'language_switch']:
                component_count += 1
                break
        
        for finding in houyi_result.findings:
            if finding.get('type') in ['task_redefinition', 'prompt_leak', 'output_shaping']:
                component_count += 1
                break
        
        has_all_components = component_count >= 2
        
        if has_all_components:
            boosted_risk = max(current_risk, houyi_risk)
            
            has_prompt_leak = any(
                f.get('type') == 'prompt_leak'
                for f in houyi_result.findings
            )
            
            has_retasking = any(
                f.get('type') == 'data_to_question_retasking'
                for f in houyi_result.findings
            )
            
            if has_prompt_leak:
                boosted_risk = min(1.0, boosted_risk + 0.2)
            
            if has_retasking:
                boosted_risk = min(1.0, boosted_risk + 0.15)
            
            return boosted_risk
        else:
            return max(current_risk, houyi_risk * 0.6)
    
    def _determine_primary_intent(
        self,
        analysis_results: List[AnalysisResult]
    ) -> Tuple[ContentIntent, float]:
        
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
        
        if primary_intent == ContentIntent.MALICIOUS:
            return SecurityDecision.BLOCK
        
        houyi_result = next(
            (r for r in analysis_results if r.module_name == "houyi_pattern_detector"),
            None
        )
        
        if houyi_result and houyi_result.risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]:
            has_prompt_leak = any(
                f.get('type') == 'prompt_leak'
                for f in houyi_result.findings
            )
            
            has_full_pattern = False
            component_types = set()
            for finding in houyi_result.findings:
                ftype = finding.get('type')
                if ftype in ['framework_component', 'separator', 'closure_separator']:
                    component_types.add('separator')
                elif ftype in ['task_redefinition', 'prompt_leak', 'output_shaping']:
                    component_types.add('disruptor')
            
            has_full_pattern = len(component_types) >= 2
            
            if has_prompt_leak or (has_full_pattern and houyi_result.risk_score >= 0.75):
                return SecurityDecision.BLOCK
            elif has_full_pattern:
                return SecurityDecision.REQUIRE_APPROVAL
        
        if primary_intent == ContentIntent.CONDITIONAL_INSTRUCTIONAL:
            if risk_score >= 0.8:
                return SecurityDecision.BLOCK
            else:
                return SecurityDecision.REQUIRE_APPROVAL
        
        if primary_intent == ContentIntent.INSTRUCTIONAL:
            if self.strict_intent_enforcement:
                if risk_score >= 0.8:
                    return SecurityDecision.BLOCK
                elif risk_score >= 0.5:
                    return SecurityDecision.REQUIRE_APPROVAL
                else:
                    return SecurityDecision.SANITIZE
            else:
                if risk_score >= 0.8:
                    return SecurityDecision.BLOCK
                elif risk_score >= 0.5:
                    return SecurityDecision.REQUIRE_APPROVAL
                else:
                    return SecurityDecision.SANITIZE
        
        if primary_intent == ContentIntent.AMBIGUOUS:
            if self.fail_closed:
                if risk_score >= 0.6:
                    return SecurityDecision.BLOCK
                elif risk_score >= 0.3:
                    return SecurityDecision.REQUIRE_APPROVAL
                else:
                    return SecurityDecision.SANITIZE
            else:
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
        
        if risk_score >= self.decision_thresholds["block"]:
            return SecurityDecision.BLOCK
        
        elif risk_score >= self.decision_thresholds["require_approval"]:
            return SecurityDecision.REQUIRE_APPROVAL
        
        elif risk_score >= self.decision_thresholds["sanitize"]:
            return SecurityDecision.SANITIZE
        
        elif primary_intent == ContentIntent.DESCRIPTIVE and risk_score < self.decision_thresholds["allow"]:
            return SecurityDecision.ALLOW
        
        else:
            return SecurityDecision.SANITIZE
    
    def _determine_restrictions(
        self, 
        risk_level: RiskLevel, 
        results: List[AnalysisResult],
        primary_intent: ContentIntent
    ) -> AgentRestrictions:
        
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
        
        houyi_result = next(
            (r for r in results if r.module_name == "houyi_pattern_detector"),
            None
        )
        
        if houyi_result and houyi_result.risk_level != RiskLevel.SAFE:
            reasoning_parts.append("HOUYI Pattern Analysis:")
            reasoning_parts.append(f"- {houyi_result.details}")
            
            critical_houyi = [f for f in houyi_result.findings if f.get('severity') == 'critical']
            if critical_houyi:
                reasoning_parts.append(f"- {len(critical_houyi)} critical HOUYI indicator(s)")
            
            reasoning_parts.append("")
        
        semantic_result = next(
            (r for r in results if r.module_name == "semantic_threat_detector"),
            None
        )
        
        if semantic_result and semantic_result.risk_level != RiskLevel.SAFE:
            reasoning_parts.append("Semantic Analysis:")
            reasoning_parts.append(f"- {semantic_result.details}")
            reasoning_parts.append("")
        
        deobfuscator_result = next(
            (r for r in results if r.module_name == "content_deobfuscator"),
            None
        )
        
        if deobfuscator_result and deobfuscator_result.risk_level != RiskLevel.SAFE:
            reasoning_parts.append("De-obfuscation Analysis:")
            reasoning_parts.append(f"- {deobfuscator_result.details}")
            reasoning_parts.append("")
        
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
                                      "ocr_content_analyzer", "houyi_pattern_detector"]:
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