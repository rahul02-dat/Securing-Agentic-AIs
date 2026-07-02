import sys
import pickle
import numpy as np
from pathlib import Path
from typing import List, Tuple, Optional

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from gateway.shared.schemas import (
    AnalysisResult, RiskLevel, SecurityDecision, 
    AgentRestrictions, SecurityAssessment, ContentIntent
)
from gateway.shared.config_loader import get_config
from gateway.analysis.intent_strength_scorer import IntentStrengthScorer, IntentStrength
from gateway.decision_engine.policy_engine import SystemPromptContextAnalyzer


class MLPolicyEngine:
    
    def __init__(self, model_path: str = None):
        self.config = get_config()
        
        self.ml_model = None
        self.feature_extractor = None
        self.ml_available = False
        
        if model_path:
            self._load_ml_model(model_path)
        
        self.risk_weights = self.config.get_risk_weights()
        self.decision_thresholds = self.config.get_decision_thresholds()
        self.intent_risk_floors = self._convert_intent_floors()
        self.baseline_risks = self.config.get_baseline_risks()
        
        self.fail_closed = self.config.get('enforcement', 'fail_closed', default=True)
        
        self.intent_strength_scorer = IntentStrengthScorer()
        self.system_prompt_analyzer = SystemPromptContextAnalyzer()
        
        print(f"PolicyEngine initialized (ML model: {self.ml_available})")
    
    def _load_ml_model(self, model_path: str):
        try:
            from gateway.learning.feature_extractor import FeatureExtractor
            
            model_path = Path(model_path)
            if not model_path.exists():
                print(f"Warning: Model file not found: {model_path}")
                return
            
            with open(model_path, 'rb') as f:
                model_data = pickle.load(f)
            
            self.ml_model = model_data['model']
            self.feature_extractor = FeatureExtractor()
            self.ml_available = True
            
            print(f"ML model loaded from {model_path}")
            metadata = model_data.get('metadata', {})
            print(f"  Model type: {metadata.get('model_type', 'unknown')}")
            print(f"  Val F1: {metadata.get('val_f1', 0):.4f}")
            
        except Exception as e:
            print(f"Warning: Could not load ML model: {e}")
            print("Falling back to rule-based decision making")
            self.ml_available = False
    
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
        hidden_elements: List[str],
        raw_input: Optional[str] = None,
        agent_system_prompt: Optional[str] = None
    ) -> SecurityAssessment:
        
        context_analysis = self.system_prompt_analyzer.analyze(visible_text, agent_system_prompt)
        
        ml_risk_score = None
        if self.ml_available and raw_input:
            ml_risk_score = self._get_ml_prediction(raw_input)
        
        rule_based_risk, rule_risk_score = self._calculate_rule_based_risk(analysis_results)
        
        primary_intent, intent_confidence = self._determine_primary_intent(analysis_results)
        
        if ml_risk_score is not None:
            overall_risk_score = ml_risk_score
            decision_source = "ml_model"
        else:
            overall_risk_score = rule_risk_score
            decision_source = "rule_based"
        
        override_applied = False
        override_reason = None
        
        hidden_result = next(
            (r for r in analysis_results if r.module_name == "hidden_content_analyzer"),
            None
        )
        if hidden_result:
            has_dangerous_script = any(
                f.get('type') == 'dangerous_script' for f in hidden_result.findings
            )
            if has_dangerous_script:
                overall_risk_score = max(overall_risk_score, 0.90)
                override_applied = True
                override_reason = "dangerous_script_detected"
        
        deobf_result = next(
            (r for r in analysis_results if r.module_name == "content_deobfuscator"),
            None
        )
        if deobf_result and deobf_result.risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]:
            has_suspicious = any(
                f.get('type') == 'decoded_content' and f.get('suspicious_patterns')
                for f in deobf_result.findings
            )
            if has_suspicious:
                overall_risk_score = max(overall_risk_score, 0.75)
                override_applied = True
                override_reason = "obfuscated_suspicious_content"
        
        agentic_result = next(
            (r for r in analysis_results if r.module_name == "agentic_intent_detector"),
            None
        )
        if agentic_result:
            has_bypass = any(
                f.get('type') in ['permission_bypass', 'link_action']
                for f in agentic_result.findings
            )
            if has_bypass:
                overall_risk_score = max(overall_risk_score, 0.85)
                override_applied = True
                override_reason = "permission_bypass_attempt"
        
        if context_analysis:
            adjustment = context_analysis.get("risk_adjustment", 0.0)
            malicious_floor = 0.90 if (
                primary_intent == ContentIntent.MALICIOUS
            ) else 0.0
            overall_risk_score = max(malicious_floor, min(1.0, overall_risk_score + adjustment))
            
        overall_risk = self._score_to_risk_level(overall_risk_score)
        
        decision = self._determine_decision(
            overall_risk, 
            overall_risk_score, 
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
            analysis_results, overall_risk, overall_risk_score, decision, 
            primary_intent, decision_source, override_applied, override_reason,
            context_analysis
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
            risk_score=overall_risk_score,
            decision=decision,
            restricted_capabilities=self._get_restricted_capabilities(restrictions),
            sanitized_content=sanitized_content,
            reasoning=reasoning,
            primary_intent=primary_intent,
            intent_confidence=intent_confidence
        )
        
        return assessment
    
    def _get_ml_prediction(self, raw_input: str) -> float:
        try:
            features = self.feature_extractor.extract_features(raw_input)
            features = features.reshape(1, -1)
            
            risk_score = self.ml_model.predict_proba(features)[0, 1]
            
            return float(risk_score)
            
        except Exception as e:
            print(f"Warning: ML prediction failed: {e}")
            return None
    
    def _calculate_rule_based_risk(
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
        
        weighted_sum = 0.0
        total_weight = 0.0
        
        for result in results:
            weight = self.risk_weights.get(result.module_name, 0.05)
            risk_score = result.risk_score if result.risk_score > 0 else risk_values[result.risk_level]
            weighted_risk = risk_score * result.confidence * weight
            
            weighted_sum += weighted_risk
            total_weight += weight
        
        calculated_risk = weighted_sum / total_weight if total_weight > 0 else 0.0
        
        intent_result = next(
            (r for r in results if r.module_name == "intent_classifier"),
            None
        )
        
        intent_floor = 0.0
        if intent_result and intent_result.detected_intent:
            intent_floor = self.intent_risk_floors.get(intent_result.detected_intent, 0.0)
        
        risk_score = max(calculated_risk, intent_floor)
        risk_level = self._score_to_risk_level(risk_score)
        
        return risk_level, min(1.0, risk_score)
    
    def _score_to_risk_level(self, score: float) -> RiskLevel:
        if score >= 0.8:
            return RiskLevel.CRITICAL
        elif score >= 0.6:
            return RiskLevel.HIGH
        elif score >= 0.4:
            return RiskLevel.MEDIUM
        elif score >= 0.15:
            return RiskLevel.LOW
        else:
            return RiskLevel.SAFE
    
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
        
        if risk_score >= self.decision_thresholds["block"]:
            return SecurityDecision.BLOCK
        
        elif risk_score >= self.decision_thresholds["require_approval"]:
            signal_count = self._count_threat_signals(analysis_results)
            if signal_count >= 2:
                return SecurityDecision.REQUIRE_APPROVAL
            else:
                return SecurityDecision.SANITIZE
        
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
        
        if risk_level == RiskLevel.CRITICAL:
            restrictions.mode = "ACTION_DISABLED"
            restrictions.allow_web_access = False
            restrictions.allow_file_write = False
            restrictions.allow_code_execution = False
            restrictions.allow_tool_use = False
            restrictions.max_output_length = 500
        
        elif risk_level == RiskLevel.HIGH:
            restrictions.mode = "APPROVAL_REQUIRED"
            restrictions.allow_web_access = False
            restrictions.allow_file_write = False
            restrictions.allow_code_execution = False
            restrictions.allow_tool_use = False
            restrictions.requires_approval = True
            restrictions.approval_reason = "High-risk content detected"
        
        elif risk_level == RiskLevel.MEDIUM:
            restrictions.mode = "READ_ONLY"
            restrictions.allow_web_access = False
            restrictions.allow_file_write = False
            restrictions.allow_code_execution = False
        
        return restrictions
    
    def _sanitize_content(
        self, 
        content: str, 
        results: List[AnalysisResult]
    ) -> str:
        import re
        
        sanitized = content
        
        all_findings = []
        for result in results:
            all_findings.extend(result.findings)
        
        for finding in all_findings:
            if "matched_text" in finding:
                phrase = finding["matched_text"]
                sanitized = sanitized.replace(phrase, "[REDACTED]")
        
        url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
        sanitized = re.sub(url_pattern, '[URL_REMOVED]', sanitized)
        
        return sanitized
    
    def _generate_reasoning(
        self,
        results: List[AnalysisResult],
        risk_level: RiskLevel,
        risk_score: float,
        decision: SecurityDecision,
        primary_intent: ContentIntent,
        decision_source: str,
        override_applied: bool,
        override_reason: str,
        context_analysis: Optional[dict] = None
    ) -> str:
        parts = [
            f"DECISION SOURCE: {decision_source.upper()}",
            f"PRIMARY INTENT: {primary_intent.value.upper()}",
            f"Risk Level: {risk_level.value.upper()} (score: {risk_score:.2f})",
            f"Decision: {decision.value.upper()}",
            ""
        ]
        
        if override_applied:
            parts.append(f"CRITICAL OVERRIDE APPLIED: {override_reason}")
            parts.append("")
            
        if context_analysis and context_analysis.get("explanation"):
            adj = context_analysis.get("risk_adjustment", 0.0)
            if adj != 0.0:
                parts.append("System-Prompt Context Analysis:")
                parts.append(
                    f"- {context_analysis['explanation']} (adjustment: {adj:+.2f})"
                )
                parts.append("")
        
        critical_results = [r for r in results if r.risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]]
        if critical_results:
            parts.append("Critical Findings:")
            for result in critical_results[:5]:
                parts.append(f"  - {result.module_name}: {result.details}")
            parts.append("")
        
        return "\n".join(parts)
    
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
        
        return restricted
    
    def _count_threat_signals(self, analysis_results: List[AnalysisResult]) -> int:
        signal_count = 0
        
        hidden_result = next(
            (r for r in analysis_results if r.module_name == "hidden_content_analyzer"),
            None
        )
        if hidden_result and hidden_result.risk_score > 0.4:
            signal_count += 1
        
        injection_result = next(
            (r for r in analysis_results if r.module_name == "prompt_injection_detector"),
            None
        )
        if injection_result and injection_result.risk_score > 0.4:
            signal_count += 1
        
        deobf_result = next(
            (r for r in analysis_results if r.module_name == "content_deobfuscator"),
            None
        )
        if deobf_result and deobf_result.risk_score > 0.4:
            signal_count += 1
        
        return signal_count