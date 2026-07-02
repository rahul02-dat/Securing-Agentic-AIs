import re
from typing import List, Tuple, Optional, Set
from gateway.shared.schemas import (
    AnalysisResult, RiskLevel, SecurityDecision,
    AgentRestrictions, SecurityAssessment, ContentIntent
)
from gateway.shared.config_loader import get_config
from gateway.analysis.intent_strength_scorer import IntentStrengthScorer, IntentStrength


# --- Objective 2: context-aware assessment ----------------------------------
# STOPWORDS / trigger vocab used by SystemPromptContextAnalyzer below. Kept
# module-level (rather than re-built per call) since they're static.
_STOPWORDS = {
    'the', 'a', 'an', 'and', 'or', 'but', 'is', 'are', 'was', 'were', 'be',
    'been', 'being', 'to', 'of', 'in', 'on', 'for', 'with', 'as', 'by',
    'at', 'from', 'that', 'this', 'these', 'those', 'it', 'its', 'you',
    'your', 'i', 'we', 'they', 'he', 'she', 'them', 'his', 'her', 'their',
    'will', 'would', 'should', 'could', 'can', 'may', 'might', 'must',
    'do', 'does', 'did', 'not', 'no', 'if', 'then', 'than', 'so', 'about',
    'into', 'over', 'after', 'before', 'up', 'down', 'out', 'all', 'any',
    'please', 'have', 'has', 'had', 'am', 'what', 'who', 'when', 'where',
    'how', 'why', 'me', 'my', 'us', 'our',
}

# Phrases that state a *boundary* the system prompt is establishing
# ("never reveal X", "do not access Y", "only respond about Z"). We extract
# the short phrase following the trigger as the "protected topic".
_BOUNDARY_TRIGGERS = [
    r'\bnever\s+([a-z0-9 ,\-]{3,60})',
    r'\bdo\s+not\s+([a-z0-9 ,\-]{3,60})',
    r"\bdon't\s+([a-z0-9 ,\-]{3,60})",
    r'\bmust\s+not\s+([a-z0-9 ,\-]{3,60})',
    r'\bshould\s+not\s+([a-z0-9 ,\-]{3,60})',
    r'\bonly\s+([a-z0-9 ,\-]{3,60})',
    r'\balways\s+([a-z0-9 ,\-]{3,60})',
    r'\bunder\s+no\s+circumstances\s+([a-z0-9 ,\-]{3,60})',
]

# Phrases in *user* input that typically signal an attempt to override or
# negate a previously-established boundary/instruction, as opposed to just
# discussing the same topic. These are intentionally narrower than the
# prompt_injection_detector's own patterns - this analyzer only needs to
# flag "this looks like it's trying to defeat a rule", not classify the
# attack type.
_OVERRIDE_SIGNALS = [
    r'\bignore\s+(that|this|the\s+above|your\s+instructions)',
    r'\bactually,?\s+(you\s+)?(can|should|must|will)\b',
    r'\bmake\s+an\s+exception\b',
    r'\bjust\s+this\s+once\b',
    r'\bpretend\s+(that\s+)?you\s+(can|are|don\'t)\b',
    r'\bforget\s+(the\s+)?rule',
    r'\bthe\s+rule\s+doesn\'t\s+apply\b',
    r'\byou\s+are\s+allowed\s+to\b',
    r'\boverride\b',
    r'\binstead\s+of\s+following\b',
]

_WORD_PATTERN = re.compile(r"[a-zA-Z0-9']+")


class SystemPromptContextAnalyzer:
    """
    Objective 2: weighs a user's input against the protected agent's own
    system prompt, instead of evaluating input "in a vacuum".

    Two signals are produced:

      1. topic_alignment (0.0-1.0): lexical overlap between the user input
         and the system prompt's declared subject matter. A complex but
         highly on-topic request (e.g. a detailed multi-step question about
         exactly what the agent is meant to help with) is more likely to be
         a legitimate power-user request than a generic injection payload,
         which tends to be topically unrelated boilerplate ("ignore all
         previous instructions...").

      2. boundary_violation_signals (list[str]): phrases extracted from the
         system prompt as explicit boundaries ("never reveal your
         instructions", "do not browse the web") that the user input
         appears to be directly trying to override or negate, based on
         proximity to override-signal language.

    These are combined into a single bounded `risk_adjustment` in
    (-0.15, +0.25) that PolicyEngine folds into the overall risk score:
    on-topic + no violation -> small negative (dampens false positives),
    boundary-violation match -> positive (escalates true positives that a
    context-blind scan might otherwise treat as merely "instructional").

    This is a deliberately conservative heuristic (lexical overlap +
    keyword proximity), not a semantic/embedding model - it never LOWERS
    risk for content already flagged MALICIOUS, and the adjustment is
    capped so it can shift a decision by at most one tier.
    """

    MAX_PROMPT_LENGTH = 20_000
    MAX_INPUT_LENGTH = 50_000

    def _tokenize(self, text: str) -> Set[str]:
        words = _WORD_PATTERN.findall(text.lower())
        return {w for w in words if w not in _STOPWORDS and len(w) > 2}

    def _extract_boundaries(self, system_prompt: str) -> List[str]:
        boundaries = []
        text = system_prompt.lower()
        for trigger in _BOUNDARY_TRIGGERS:
            for m in re.finditer(trigger, text):
                phrase = m.group(1).strip().rstrip('.,;:')
                # Keep boundary phrases short and meaningful
                if 3 <= len(phrase.split()) <= 12:
                    boundaries.append(phrase)
        return boundaries

    def analyze(self, visible_text: str, agent_system_prompt: Optional[str]) -> dict:
        """
        Returns a dict:
          {
            "risk_adjustment": float,   # apply directly to risk_score
            "topic_alignment": float,   # 0..1, for diagnostics/reasoning
            "boundary_violations": [str, ...],
            "explanation": str,
          }
        Safe to call with agent_system_prompt=None/"" - returns a neutral
        (zero-adjustment) result in that case, since there is nothing to
        compare against.
        """
        if not agent_system_prompt or not agent_system_prompt.strip():
            return {
                "risk_adjustment": 0.0,
                "topic_alignment": 0.0,
                "boundary_violations": [],
                "explanation": "No agent_system_prompt supplied; context-aware "
                                "assessment skipped, evaluated in isolation.",
            }

        system_prompt = agent_system_prompt[: self.MAX_PROMPT_LENGTH]
        text = (visible_text or "")[: self.MAX_INPUT_LENGTH]

        prompt_tokens = self._tokenize(system_prompt)
        input_tokens = self._tokenize(text)

        if prompt_tokens and input_tokens:
            overlap = prompt_tokens & input_tokens
            union = prompt_tokens | input_tokens
            topic_alignment = len(overlap) / len(union) if union else 0.0
        else:
            topic_alignment = 0.0

        # Boundary-violation detection: for each declared boundary phrase,
        # check whether the user input contains both (a) meaningful lexical
        # overlap with that specific boundary's topic words, and (b) an
        # override-signal phrase nearby. Requiring both avoids flagging
        # ordinary on-topic conversation about the same subject area.
        boundaries = self._extract_boundaries(system_prompt)
        text_lower = text.lower()
        has_override_signal = any(re.search(sig, text_lower) for sig in _OVERRIDE_SIGNALS)

        boundary_violations = []
        if has_override_signal and boundaries:
            for boundary in boundaries:
                boundary_tokens = self._tokenize(boundary)
                if not boundary_tokens:
                    continue
                shared = boundary_tokens & input_tokens
                # >=1 shared significant word between the boundary phrase and
                # the user input, combined with an override signal elsewhere
                # in the input, is treated as an attempted override.
                if shared:
                    boundary_violations.append(boundary)

        risk_adjustment = 0.0
        explanation_parts = []

        if boundary_violations:
            # Escalate: user input appears to target a specific boundary the
            # system prompt establishes, alongside override-style phrasing.
            risk_adjustment += min(0.25, 0.12 * len(boundary_violations))
            explanation_parts.append(
                f"Input contains override-style language directed at "
                f"{len(boundary_violations)} system-prompt boundary/boundaries: "
                f"{', '.join(boundary_violations[:3])}"
                + ("..." if len(boundary_violations) > 3 else "")
            )
        elif topic_alignment >= 0.08:
            # Dampen: on-topic overlap with the agent's declared purpose,
            # and no boundary-override language detected. This is the
            # "legitimate complex power-user request" case. The 0.08
            # threshold is deliberately modest: Jaccard overlap over full
            # vocabularies is naturally low even for clearly on-topic text
            # (system prompts contain a lot of scaffolding language), so a
            # stricter threshold under-triggers on real traffic. Tune via
            # this constant if false-positive/false-negative rates in
            # production suggest otherwise.
            risk_adjustment -= min(0.15, topic_alignment * 0.3)
            explanation_parts.append(
                f"Input is topically aligned with the agent's system prompt "
                f"(overlap={topic_alignment:.2f}) with no boundary-override "
                f"language detected; risk dampened to reduce false positives."
            )
        else:
            explanation_parts.append(
                f"Input shows low topical overlap with the agent's system "
                f"prompt (overlap={topic_alignment:.2f}); no adjustment applied."
            )

        return {
            "risk_adjustment": risk_adjustment,
            "topic_alignment": topic_alignment,
            "boundary_violations": boundary_violations,
            "explanation": " ".join(explanation_parts),
        }


class PolicyEngine:

    def __init__(self):
        self.config = get_config()

        self.risk_weights = self.config.get_risk_weights()
        self.decision_thresholds = self.config.get_decision_thresholds()
        self.intent_risk_floors = self._convert_intent_floors()
        self.baseline_risks = self.config.get_baseline_risks()

        self.fail_closed = self.config.get('enforcement', 'fail_closed', default=True)
        self.strict_intent_enforcement = self.config.get('enforcement', 'strict_intent_enforcement', default=True)

        # Initialize intent strength scorer for multi-signal detection
        self.intent_strength_scorer = IntentStrengthScorer()

        # Objective 2: context-aware analyzer that compares user input
        # against the protected agent's own system prompt, when supplied.
        self.system_prompt_analyzer = SystemPromptContextAnalyzer()

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
        agent_system_prompt: Optional[str] = None,
    ) -> SecurityAssessment:
        """
        Args:
            analysis_results: Outputs of all analyzer modules.
            visible_text: Visible content extracted from the input.
            hidden_elements: Hidden content elements extracted from the input.
            raw_input: The original, unprocessed input string, if available.
                Accepted for forward-compatibility with callers (e.g.
                gateway/main.py) that already pass it through; not required
                for the current decision logic.
            agent_system_prompt: Objective 2 - the protected LLM agent's own
                system prompt. When supplied, PolicyEngine weighs the user's
                input against the boundaries and declared purpose of that
                system prompt, instead of evaluating the input in isolation.
                Optional and defaults to None, which preserves prior
                (context-blind) behavior exactly.
        """

        context_analysis = self.system_prompt_analyzer.analyze(visible_text, agent_system_prompt)

        overall_risk, risk_score = self._calculate_overall_risk(analysis_results, context_analysis)

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
            analysis_results, overall_risk, risk_score, decision, primary_intent,
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
        results: List[AnalysisResult],
        context_analysis: Optional[dict] = None,
    ) -> Tuple[RiskLevel, float]:
        """
        Calculate overall risk with intent-aware and multi-signal requirements.

        Key improvements:
        1. Lowered intent floors - weak instructional intent doesn't auto-escalate
        2. Multi-signal requirement - weak intent needs hidden + threat combo
        3. Benign hidden content (metadata, comments) doesn't elevate risk alone
        4. (Objective 2) Context-aware adjustment based on the agent's own
           system prompt - see SystemPromptContextAnalyzer.
        """

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

        # IMPROVED: Lowered intent floors - weak intent doesn't force escalation
        # Only instructional/conditional should have meaningful floors
        intent_floor = 0.0
        intent_strength = IntentStrength.WEAK  # Default assumption

        if intent_result and intent_result.detected_intent:
            # Score the strength of instructional intent
            visible_context = ""  # Can be passed if needed
            intent_strength, _ = self.intent_strength_scorer.score_intent_strength(
                visible_context,
                intent_result.detected_intent.value
            )

            # CALIBRATED FLOORS (lowered from original)
            intent_floor_map = {
                ContentIntent.MALICIOUS: 0.90,              # Still very high
                ContentIntent.CONDITIONAL_INSTRUCTIONAL: 0.50,  # Lowered from 0.70
                ContentIntent.INSTRUCTIONAL: 0.30,          # Lowered from 0.50
                ContentIntent.AMBIGUOUS: 0.15,              # Lowered from 0.30
                ContentIntent.DESCRIPTIVE: 0.0,             # Unchanged
            }
            intent_floor = intent_floor_map.get(intent_result.detected_intent, 0.15)

        weighted_sum = 0.0
        total_weight = 0.0

        for result in results:
            weight = self.risk_weights.get(result.module_name, 0.05)

            risk_score = result.risk_score if result.risk_score > 0 else risk_values[result.risk_level]
            weighted_risk = risk_score * result.confidence * weight

            weighted_sum += weighted_risk
            total_weight += weight

        calculated_risk = weighted_sum / total_weight if total_weight > 0 else 0.0

        # IMPROVED: Apply intent floor based on strength
        # Weak intent: floor is very low (0.1), needs other signals
        # Strong intent: floor is higher, single signal can trigger concern
        if intent_strength == IntentStrength.WEAK:
            intent_floor = min(intent_floor, 0.10)  # Weak intent floor capped at 0.1
        elif intent_strength == IntentStrength.STRONG:
            intent_floor = max(intent_floor, 0.40)  # Strong intent floor at least 0.4

        risk_score = max(calculated_risk, intent_floor)

        risk_score = self._apply_baseline_risks_refined(risk_score, results, intent_strength)

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

        # Objective 2: apply the system-prompt-aware adjustment last, after
        # all other signals have set the baseline risk_score. We deliberately
        # do NOT let this adjustment pull risk_score below the MALICIOUS
        # intent floor (0.90) or above 1.0 - it can shift borderline cases
        # but never override a clear malicious classification, and never
        # exceed the natural [0, 1] bound.
        if context_analysis:
            adjustment = context_analysis.get("risk_adjustment", 0.0)
            malicious_floor = 0.90 if (
                intent_result and intent_result.detected_intent == ContentIntent.MALICIOUS
            ) else 0.0
            risk_score = max(malicious_floor, min(1.0, risk_score + adjustment))

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

    def _apply_baseline_risks_refined(
        self, current_risk: float, results: List[AnalysisResult],
        intent_strength: IntentStrength = IntentStrength.WEAK
    ) -> float:
        """
        Apply baseline risks with intent-aware adjustments.

        IMPROVED: Don't escalate benign hidden content (metadata, comments) to REQUIRE_APPROVAL.
        Only escalate when multiple signals align.
        """

        risk = current_risk

        # OCR extracted text - only escalate if it has actual threat patterns
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
                # Apply baseline only if strong intent or multiple threats
                if intent_strength == IntentStrength.STRONG:
                    baseline = self.baseline_risks.get('ocr_extracted', 0.15)  # Lowered from 0.25
                    risk = max(risk, baseline)

        # Deobfuscator results - obfuscation itself is a threat signal
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
                baseline = self.baseline_risks.get('decoded_content', 0.15)  # Lowered from 0.20
                risk = max(risk, baseline)

        # Hidden elements baseline - LOWERED and made conditional
        # Only apply if there are actual threat findings, not just presence
        hidden_result = next(
            (r for r in results if r.module_name == "hidden_content_analyzer"),
            None
        )
        if hidden_result and hidden_result.risk_level not in [RiskLevel.SAFE]:
            has_actual_threats = any(
                f.get('type') in ['instruction_keyword', 'dangerous_script', 'obfuscation']
                for f in hidden_result.findings
            )
            if has_actual_threats:
                # Weak intent doesn't get baseline boost
                if intent_strength != IntentStrength.WEAK:
                    baseline = self.baseline_risks.get('hidden_elements', 0.08)  # Lowered from 0.15
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
        """
        Determine security decision with multi-signal requirement.

        IMPROVED: Require multiple aligned signals before REQUIRE_APPROVAL,
        while maintaining fail-safe for strong hidden injections.
        """

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

        # IMPROVED: Conditional instructional now requires multiple signals
        if primary_intent == ContentIntent.CONDITIONAL_INSTRUCTIONAL:
            signal_count = self._count_threat_signals(analysis_results)
            if risk_score >= 0.8:
                return SecurityDecision.BLOCK
            elif risk_score >= 0.6 and signal_count >= 2:
                # Multiple signals align = escalate
                return SecurityDecision.REQUIRE_APPROVAL
            elif risk_score >= 0.6:
                # Single signal = sanitize, don't require approval
                return SecurityDecision.SANITIZE
            else:
                return SecurityDecision.SANITIZE

        # IMPROVED: Instructional intent with multi-signal requirement
        if primary_intent == ContentIntent.INSTRUCTIONAL:
            signal_count = self._count_threat_signals(analysis_results)
            if risk_score >= 0.8:
                return SecurityDecision.BLOCK
            elif risk_score >= 0.55 and signal_count >= 2:
                # Multiple signals (hidden + threat) = require approval
                return SecurityDecision.REQUIRE_APPROVAL
            elif risk_score >= 0.55:
                # Single signal = sanitize
                return SecurityDecision.SANITIZE
            else:
                return SecurityDecision.SANITIZE

        # IMPROVED: Ambiguous intent - require multiple signals before escalation
        if primary_intent == ContentIntent.AMBIGUOUS:
            signal_count = self._count_threat_signals(analysis_results)
            if self.fail_closed:
                if risk_score >= 0.75:
                    return SecurityDecision.BLOCK
                elif risk_score >= 0.55 and signal_count >= 2:
                    # Multiple signals in ambiguous content = require approval
                    return SecurityDecision.REQUIRE_APPROVAL
                elif risk_score >= 0.40:
                    # Single weak signal = sanitize
                    return SecurityDecision.SANITIZE
                else:
                    return SecurityDecision.SANITIZE
            else:
                if risk_score >= 0.75:
                    return SecurityDecision.BLOCK
                elif risk_score >= 0.55 and signal_count >= 2:
                    return SecurityDecision.REQUIRE_APPROVAL
                elif risk_score >= 0.40:
                    return SecurityDecision.SANITIZE
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
            elif risk_score >= 0.50:
                # Agentic intent with threat = escalate
                return SecurityDecision.REQUIRE_APPROVAL
            else:
                return SecurityDecision.SANITIZE

        # IMPROVED: Threshold-based decisions with multi-signal awareness
        if risk_score >= self.decision_thresholds["block"]:
            return SecurityDecision.BLOCK

        elif risk_score >= self.decision_thresholds["require_approval"]:
            # Multi-signal check before requiring approval
            signal_count = self._count_threat_signals(analysis_results)
            if signal_count >= 2:
                return SecurityDecision.REQUIRE_APPROVAL
            else:
                # Single weak signal = sanitize instead
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
        primary_intent: ContentIntent,
        context_analysis: Optional[dict] = None,
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

        # Objective 2: surface the context-aware adjustment in the reasoning
        # output so a human reviewer can see *why* the score moved.
        if context_analysis and context_analysis.get("explanation"):
            adj = context_analysis.get("risk_adjustment", 0.0)
            if adj != 0.0:
                reasoning_parts.append("System-Prompt Context Analysis:")
                reasoning_parts.append(
                    f"- {context_analysis['explanation']} (adjustment: {adj:+.2f})"
                )
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

    def _count_threat_signals(self, analysis_results: List[AnalysisResult]) -> int:
        """
        Count aligned threat signals for multi-signal decision making.

        Signals:
        1. Hidden content with instructions (hidden_content_analyzer)
        2. Prompt injection patterns (prompt_injection_detector)
        3. Obfuscation/encoding (deobfuscator)
        4. Agentic intent (agentic_intent_detector)
        5. Suspicious patterns (houyi_pattern_detector)

        Returns: Count of detected threat signals (0-5)
        """
        signal_count = 0

        # Signal 1: Hidden content with threats
        hidden_result = next(
            (r for r in analysis_results if r.module_name == "hidden_content_analyzer"),
            None
        )
        if hidden_result and hidden_result.risk_level not in [RiskLevel.SAFE, RiskLevel.LOW]:
            has_real_threats = any(
                f.get('type') in ['instruction_keyword', 'dangerous_script', 'obfuscation']
                for f in hidden_result.findings
            )
            if has_real_threats:
                signal_count += 1

        # Signal 2: Prompt injection patterns
        injection_result = next(
            (r for r in analysis_results if r.module_name == "prompt_injection_detector"),
            None
        )
        if injection_result and injection_result.risk_level not in [RiskLevel.SAFE, RiskLevel.LOW]:
            if injection_result.risk_score > 0.4:
                signal_count += 1

        # Signal 3: Obfuscation/encoding
        deobf_result = next(
            (r for r in analysis_results if r.module_name == "content_deobfuscator"),
            None
        )
        if deobf_result and deobf_result.risk_level not in [RiskLevel.SAFE, RiskLevel.LOW]:
            has_suspicious = any(
                f.get('type') == 'decoded_content' and f.get('suspicious_patterns')
                for f in deobf_result.findings
            )
            if has_suspicious:
                signal_count += 1

        # Signal 4: Agentic intent
        agentic_result = next(
            (r for r in analysis_results if r.module_name == "agentic_intent_detector"),
            None
        )
        if agentic_result and agentic_result.risk_level not in [RiskLevel.SAFE, RiskLevel.LOW]:
            if agentic_result.risk_score > 0.4:
                signal_count += 1

        # Signal 5: Houyi patterns
        houyi_result = next(
            (r for r in analysis_results if r.module_name == "houyi_pattern_detector"),
            None
        )
        if houyi_result and houyi_result.risk_level not in [RiskLevel.SAFE, RiskLevel.LOW]:
            if houyi_result.risk_score > 0.5:
                signal_count += 1

        return signal_count