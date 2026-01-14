import re
from typing import List, Dict, Optional, Tuple
from gateway.shared.schemas import (
    AnalysisResult, RiskLevel, ContentChannel, InjectionFinding, LocationReference
)
from gateway.shared.location_tracker import LocationTracker
from gateway.analysis.intent_strength_scorer import IntentStrengthScorer, IntentStrength


class HiddenContentAnalyzer:
    """
    Analyzes hidden content with location tracking.
    Detects threats in CSS-hidden, script, iframe, and other hidden elements.
    
    Now includes intent-strength scoring to distinguish benign hidden content
    (metadata, comments, OCR noise) from actual prompt injection threats.
    """
    
    def __init__(self):
        self.instruction_keywords = [
            'ignore previous', 'disregard', 'forget instructions',
            'new instructions', 'system prompt', 'assistant rules',
            'override', 'bypass', 'jailbreak', 'prompt injection',
        ]
        
        self.obfuscation_patterns = [
            r'&#x?[0-9a-fA-F]+;',
            r'\\x[0-9a-fA-F]{2}',
            r'\\u[0-9a-fA-F]{4}',
            r'fromCharCode',
            r'String\.fromCharCode',
        ]
        
        self.dangerous_script_patterns = [
            r'eval\s*\(',
            r'Function\s*\(',
            r'document\.cookie',
            r'window\.location\s*=',
            r'XMLHttpRequest',
            r'fetch\s*\(',
        ]
        
        # Initialize intent strength scorer for better discrimination
        self.intent_scorer = IntentStrengthScorer()
    
    def analyze(self, visible_text: str, hidden_elements: List[str], 
                location_map: Optional[Dict] = None, 
                intent_strength: Optional[IntentStrength] = None) -> AnalysisResult:
        """
        Analyze hidden content with location tracking and intent-aware scoring.
        
        Args:
            visible_text: Visible content
            hidden_elements: List of hidden elements
            location_map: Map of element locations (from LinkInputHandler)
            intent_strength: Intent strength (from IntentStrengthScorer) for better decisions
            
        Returns:
            AnalysisResult with localized findings
        """
        
        findings = []
        risk_scores = []
        
        if not hidden_elements:
            return AnalysisResult(
                module_name="hidden_content_analyzer",
                risk_level=RiskLevel.SAFE,
                confidence=0.95,
                findings=[],
                details="No hidden content detected.",
                risk_score=0.0
            )
        
        # Check instruction keywords with locations and intent-awareness
        keyword_findings, keyword_risks = self._check_instruction_keywords(
            hidden_elements, location_map, intent_strength
        )
        findings.extend(keyword_findings)
        if keyword_risks:
            risk_scores.extend(keyword_risks)
        
        # Check obfuscation patterns (always concerning)
        obfuscation_findings, obfuscation_risks = self._check_obfuscation(
            hidden_elements, location_map
        )
        findings.extend(obfuscation_findings)
        if obfuscation_risks:
            risk_scores.extend(obfuscation_risks)
        
        # Check size anomalies (weak signal, needs corroboration)
        size_findings = self._check_size_anomalies(visible_text, hidden_elements)
        findings.extend(size_findings)
        if size_findings:
            risk_scores.append(0.25)  # Reduced from 0.4
        
        # Check dangerous scripts (always high risk if present)
        script_findings, script_risks = self._check_dangerous_scripts(
            hidden_elements, location_map
        )
        findings.extend(script_findings)
        if script_risks:
            risk_scores.extend(script_risks)
        
        # Remove benign findings (metadata, comments) that shouldn't elevate risk
        finding_dicts = []
        benign_findings = []
        for finding in findings:
            if isinstance(finding, InjectionFinding):
                finding_dict = finding.to_dict()
                if not self._is_benign_finding(finding_dict, hidden_elements):
                    finding_dicts.append(finding_dict)
                else:
                    benign_findings.append(finding_dict)
        
        # Recalculate risk scores excluding benign findings
        threat_risk_scores = []
        for i, finding in enumerate(findings):
            if isinstance(finding, InjectionFinding):
                finding_dict = finding.to_dict()
                if not self._is_benign_finding(finding_dict, hidden_elements):
                    threat_risk_scores.append(risk_scores[i] if i < len(risk_scores) else 0.5)
        
        if not finding_dicts:
            return AnalysisResult(
                module_name="hidden_content_analyzer",
                risk_level=RiskLevel.SAFE,
                confidence=0.85,
                findings=[],
                details=f"Hidden content present ({len(hidden_elements)} elements) but no threats detected.",
                risk_score=0.0
            )
        
        avg_risk = sum(threat_risk_scores) / len(threat_risk_scores) if threat_risk_scores else 0.0
        
        # Apply intent-aware floor: weak intent hidden content needs strong signal
        if intent_strength == IntentStrength.WEAK and avg_risk < 0.5:
            avg_risk = max(avg_risk, 0.1)  # Keep it low unless multiple signals align
        
        risk_level = self._calculate_risk_level(avg_risk)
        
        return AnalysisResult(
            module_name="hidden_content_analyzer",
            risk_level=risk_level,
            confidence=min(0.95, avg_risk + 0.2),
            findings=finding_dicts,
            details=f"Detected {len(finding_dicts)} threat patterns in hidden content.",
            risk_score=avg_risk
        )
    
    def _check_instruction_keywords(
        self, hidden_elements: List[str], location_map: Optional[Dict] = None,
        intent_strength: Optional[IntentStrength] = None
    ) -> Tuple[List[InjectionFinding], List[float]]:
        """Check for instruction manipulation keywords with locations and intent-aware scoring."""
        findings = []
        risks = []
        
        for idx, element in enumerate(hidden_elements):
            text_lower = element.lower()
            
            for keyword in self.instruction_keywords:
                if keyword in text_lower:
                    # Find position in element
                    match_start = text_lower.find(keyword)
                    
                    # Get location info if available
                    location = None
                    if location_map and f"hidden_{idx}" in location_map:
                        loc_info = location_map[f"hidden_{idx}"]
                        location = LocationReference(
                            channel=ContentChannel.HIDDEN,
                            tag_name=loc_info.get("tag_name"),
                            tag_id=loc_info.get("tag_id"),
                            tag_class=loc_info.get("tag_class"),
                            css_style=loc_info.get("css_style"),
                            context_before=loc_info.get("text_preview", "")[:50]
                        )
                    else:
                        # Create location from text position
                        location = LocationTracker.track_text_location(
                            element, match_start, match_start + len(keyword),
                            ContentChannel.HIDDEN
                        )
                    
                    # Intent-aware risk scoring:
                    # - Weak instructional intent in hidden content = lower risk (0.4)
                    # - Strong intent or dangerous elements = high risk (0.85)
                    if intent_strength == IntentStrength.WEAK:
                        risk_score = 0.4  # Weak intent keyword needs other signals
                    elif intent_strength == IntentStrength.MEDIUM:
                        risk_score = 0.65
                    else:
                        risk_score = 0.85  # Strong intent or no context
                    
                    finding = InjectionFinding(
                        type="instruction_keyword",
                        detector="keyword_detector",
                        severity="high" if risk_score > 0.7 else "medium",
                        risk_score=risk_score,
                        matched_text=keyword,
                        description=f"Instruction manipulation keyword in hidden content: '{keyword}'",
                        locations=[location],
                        reasoning=f"Instruction keyword with intent strength: {intent_strength.name if intent_strength else 'unknown'}"
                    )
                    findings.append(finding)
                    risks.append(risk_score)
        
        return findings, risks
    
    def _check_obfuscation(
        self, hidden_elements: List[str], location_map: Optional[Dict] = None
    ) -> Tuple[List[InjectionFinding], List[float]]:
        """Check for obfuscation patterns with locations."""
        findings = []
        risks = []
        
        for idx, element in enumerate(hidden_elements):
            for pattern in self.obfuscation_patterns:
                matches = list(re.finditer(pattern, element, re.IGNORECASE))
                for match in matches:
                    matched_text = element[match.start():match.end()]
                    
                    location = LocationTracker.track_text_location(
                        element, match.start(), match.end(), ContentChannel.HIDDEN
                    )
                    
                    # Add metadata if available
                    if location_map and f"hidden_{idx}" in location_map:
                        loc_info = location_map[f"hidden_{idx}"]
                        location.tag_name = loc_info.get("tag_name")
                        location.channel = ContentChannel(loc_info.get("channel", "hidden"))
                    
                    finding = InjectionFinding(
                        type="obfuscation",
                        detector="obfuscation_detector",
                        severity="medium",
                        risk_score=0.65,
                        pattern=pattern,
                        matched_text=matched_text,
                        description=f"Obfuscation detected in hidden content: {pattern}",
                        locations=[location],
                        reasoning="Content obfuscation hides true intent from detection",
                        encoding_trace=["html_entity" if "&#" in matched_text else "unicode"]
                    )
                    findings.append(finding)
                    risks.append(0.65)
        
        return findings, risks
    
    def _check_size_anomalies(self, visible: str, hidden: List[str]) -> List[InjectionFinding]:
        """Check for suspicious size ratios (weak signal, needs corroboration)."""
        findings = []
        
        visible_len = len(visible)
        hidden_len = sum(len(h) for h in hidden)
        
        # Only flag if hidden is MUCH larger than visible (weak signal)
        if visible_len > 0 and hidden_len > visible_len * 5:  # Increased from 3x
            finding = InjectionFinding(
                type="size_anomaly",
                detector="size_anomaly_detector",
                severity="low",  # Changed from medium to low
                risk_score=0.25,  # Reduced from 0.4 - weak signal
                description=f"Hidden content ({hidden_len} chars) much larger than visible ({visible_len} chars)",
                reasoning="Large hidden content may indicate attempt to hide instructions (weak signal - needs other indicators)"
            )
            findings.append(finding)
        
        return findings
    
    def _check_dangerous_scripts(
        self, hidden_elements: List[str], location_map: Optional[Dict] = None
    ) -> Tuple[List[InjectionFinding], List[float]]:
        """Check for dangerous JavaScript patterns with locations."""
        findings = []
        risks = []
        
        for idx, element in enumerate(hidden_elements):
            if '<script' in element.lower():
                for pattern in self.dangerous_script_patterns:
                    matches = list(re.finditer(pattern, element, re.IGNORECASE))
                    for match in matches:
                        matched_text = element[match.start():match.end()]
                        
                        location = LocationTracker.track_text_location(
                            element, match.start(), match.end(), ContentChannel.SCRIPT
                        )
                        
                        if location_map and f"hidden_{idx}" in location_map:
                            loc_info = location_map[f"hidden_{idx}"]
                            location.tag_name = "script"
                            location.channel = ContentChannel.SCRIPT
                        
                        finding = InjectionFinding(
                            type="dangerous_script",
                            detector="script_analyzer",
                            severity="critical",
                            risk_score=0.9,
                            pattern=pattern,
                            matched_text=matched_text,
                            description=f"Dangerous JavaScript pattern in hidden script: {pattern}",
                            locations=[location],
                            reasoning="Hidden scripts with dangerous operations pose execution risk"
                        )
                        findings.append(finding)
                        risks.append(0.9)
        
        return findings, risks
    
    def _calculate_risk_level(self, score: float) -> RiskLevel:
        """Calculate risk level from score."""
        if score >= 0.8:
            return RiskLevel.CRITICAL
        elif score >= 0.6:
            return RiskLevel.HIGH
        elif score >= 0.4:
            return RiskLevel.MEDIUM
        elif score >= 0.2:
            return RiskLevel.LOW
        else:
            return RiskLevel.SAFE
    
    def _is_benign_finding(self, finding: Dict, hidden_elements: List[str]) -> bool:
        """
        Check if a finding is benign (metadata, comments, OCR noise).
        These should not escalate risk.
        """
        finding_type = finding.get('type', '')
        
        # All obfuscation and dangerous scripts are threats, not benign
        if finding_type in ['obfuscation', 'dangerous_script']:
            return False
        
        # Size anomalies alone are very weak signals
        if finding_type == 'size_anomaly':
            return True  # Benign on its own, needs corroboration
        
        # Check if it's just metadata/comments (benign)
        description = finding.get('description', '').lower()
        if any(term in description for term in ['metadata', 'generator', 'charset', 'viewport', 'comment']):
            return True
        
        # Check matched text for benign patterns
        matched_text = finding.get('matched_text', '').lower()
        benign_keywords = ['<meta', 'charset', 'viewport', 'generator', 'created', 'built with']
        if any(kw in matched_text for kw in benign_keywords):
            return True
        
        return False
