import re
from typing import List, Dict, Tuple, Optional
from gateway.shared.schemas import (
    AnalysisResult, RiskLevel, ContentChannel, InjectionFinding, 
    LocationReference
)
from gateway.shared.location_tracker import LocationTracker, EncodingTracer


class PromptInjectionDetector:
    """
    Detects prompt injection attacks with precise location information.
    """
    
    def __init__(self):
        self.injection_patterns = [
            (r'ignore\s+(all\s+)?(previous|prior|above)\s+(instructions|commands|prompts|rules)', 0.95),
            (r'disregard\s+(all\s+)?(previous|prior|above)', 0.9),
            (r'forget\s+(everything|all)\s+(you\s+)?(were\s+)?told', 0.9),
            (r'new\s+(instructions|task|role|system\s+prompt)', 0.85),
            (r'you\s+are\s+now\s+(a|an|the)', 0.75),
            (r'from\s+now\s+on,?\s+you\s+(will|are|must|should)', 0.85),
            (r'your\s+(new\s+)?(role|task|purpose|objective)\s+is', 0.85),
            (r'system\s*:\s*', 0.65),
            (r'assistant\s*:\s*', 0.65),
            (r'\[SYSTEM\]|\[INST\]|\[USER\]', 0.7),
            (r'override\s+(all\s+)?(safety|security|default)', 0.9),
            (r'bypass\s+(the\s+)?(filter|check|validation|security)', 0.9),
            (r'jailbreak|prompt\s+injection|prompt\s+leak', 0.95),
            (r'reveal\s+(your|the)\s+(system\s+)?(prompt|instructions)', 0.9),
            (r'what\s+(are|were)\s+your\s+(original|initial)\s+instructions', 0.85),
        ]
        
        self.context_switches = [
            r'<\|endoftext\|>',
            r'<\|end\|>',
            r'<\|im_end\|>',
            r'###\s*Instruction',
            r'###\s*Human',
            r'###\s*Assistant',
        ]
        
        self.role_manipulation = [
            'admin', 'root', 'superuser', 'developer mode',
            'god mode', 'sudo mode', 'privileged mode',
            'debug mode', 'unrestricted mode', 'jailbreak mode'
        ]
    
    def analyze(self, visible_text: str, hidden_elements: List[str], 
                hidden_metadata: Optional[Dict] = None) -> AnalysisResult:
        """
        Analyze text for prompt injections with location tracking.
        
        Args:
            visible_text: Visible content
            hidden_elements: List of hidden content elements
            hidden_metadata: Metadata about where hidden elements came from
            
        Returns:
            AnalysisResult with localized findings
        """
        
        findings = []
        max_risk = 0.0
        
        # Scan visible text
        visible_findings, visible_risk = self._scan_text(
            visible_text, ContentChannel.VISIBLE, {}
        )
        findings.extend(visible_findings)
        max_risk = max(max_risk, visible_risk)
        
        # Scan each hidden element
        for idx, hidden in enumerate(hidden_elements):
            metadata = hidden_metadata.get(f"hidden_{idx}", {}) if hidden_metadata else {}
            hidden_findings, hidden_risk = self._scan_text(
                hidden, ContentChannel.HIDDEN, metadata
            )
            findings.extend(hidden_findings)
            max_risk = max(max_risk, hidden_risk)
        
        # Detect context switches with locations
        context_findings = self._detect_context_switches(visible_text, hidden_elements)
        if context_findings:
            findings.extend(context_findings)
            max_risk = max(max_risk, 0.85)
        
        # Detect role manipulation with locations
        role_findings = self._detect_role_manipulation(visible_text, hidden_elements)
        if role_findings:
            findings.extend(role_findings)
            max_risk = max(max_risk, 0.8)
        
        # Detect structural attacks with locations
        structure_findings = self._detect_structural_attacks(visible_text, hidden_elements)
        if structure_findings:
            findings.extend(structure_findings)
            max_risk = max(max_risk, 0.7)
        
        risk_level = self._calculate_risk_level(max_risk)
        
        if not findings:
            return AnalysisResult(
                module_name="prompt_injection_detector",
                risk_level=RiskLevel.SAFE,
                confidence=0.9,
                findings=[],
                details="No prompt injection patterns detected.",
                risk_score=0.0
            )
        
        confidence = min(0.95, max_risk + 0.1)
        details = f"Detected {len(findings)} injection pattern(s). Max risk: {max_risk:.2f}"
        
        # Convert InjectionFinding objects to dicts for serialization
        findings_dicts = [f.to_dict() if isinstance(f, InjectionFinding) else f for f in findings]
        
        return AnalysisResult(
            module_name="prompt_injection_detector",
            risk_level=risk_level,
            confidence=confidence,
            findings=findings_dicts,
            details=details,
            risk_score=max_risk
        )
    
    def _scan_text(self, text: str, channel: ContentChannel, 
                   metadata: Optional[Dict] = None) -> Tuple[List[InjectionFinding], float]:
        """
        Scan text for injection patterns with location tracking.
        
        Args:
            text: Text to scan
            channel: Which channel this content came from
            metadata: Optional metadata about the content source
            
        Returns:
            List of InjectionFinding objects and max risk score
        """
        findings = []
        max_risk = 0.0
        text_lower = text.lower()
        
        for pattern, risk_score in self.injection_patterns:
            matches = list(re.finditer(pattern, text_lower, re.IGNORECASE))
            for match in matches:
                # Get the actual matched text from original case
                matched_text = text[match.start():match.end()]
                
                # Track location
                location = LocationTracker.track_text_location(
                    text, match.start(), match.end(), channel, context_chars=50
                )
                
                # Add HTML tag info if available in metadata
                if metadata and "tag_name" in metadata:
                    location.tag_name = metadata["tag_name"]
                    location.tag_id = metadata.get("tag_id")
                    location.tag_class = metadata.get("tag_class")
                    location.attribute_name = metadata.get("attribute_name")
                
                finding = InjectionFinding(
                    type="injection_pattern",
                    detector="pattern_matcher",
                    severity="critical" if risk_score >= 0.9 else "high",
                    risk_score=risk_score,
                    pattern=pattern[:80],
                    matched_text=matched_text,
                    description=f"Injection pattern detected: '{matched_text}'",
                    locations=[location],
                    reasoning=f"Matched known injection pattern with risk {risk_score:.2f}"
                )
                findings.append(finding)
                max_risk = max(max_risk, risk_score)
        
        return findings, max_risk
    
    def _detect_context_switches(self, visible: str, hidden: List[str]) -> List[InjectionFinding]:
        """Detect context switch tokens with location tracking."""
        findings = []
        all_content = visible + ' '.join(hidden)
        
        for pattern in self.context_switches:
            matches = list(re.finditer(pattern, all_content, re.IGNORECASE))
            for match in matches:
                matched_text = all_content[match.start():match.end()]
                
                # Determine channel
                if match.start() < len(visible):
                    channel = ContentChannel.VISIBLE
                else:
                    channel = ContentChannel.HIDDEN
                
                location = LocationTracker.track_text_location(
                    all_content, match.start(), match.end(), channel
                )
                
                finding = InjectionFinding(
                    type="context_switch",
                    detector="context_switch_detector",
                    severity="high",
                    risk_score=0.85,
                    pattern=pattern,
                    matched_text=matched_text,
                    description=f"Context switch token: {matched_text}",
                    locations=[location],
                    reasoning="Context switches can bypass safety boundaries"
                )
                findings.append(finding)
        
        return findings
    
    def _detect_role_manipulation(self, visible: str, hidden: List[str]) -> List[InjectionFinding]:
        """Detect role/privilege manipulation attempts with location tracking."""
        findings = []
        
        def scan_role_in_text(text: str, channel: ContentChannel) -> List[InjectionFinding]:
            local_findings = []
            text_lower = text.lower()
            
            for role in self.role_manipulation:
                matches = list(re.finditer(re.escape(role), text_lower, re.IGNORECASE))
                for match in matches:
                    matched_text = text[match.start():match.end()]
                    location = LocationTracker.track_text_location(
                        text, match.start(), match.end(), channel
                    )
                    
                    finding = InjectionFinding(
                        type="role_manipulation",
                        detector="role_detector",
                        severity="high",
                        risk_score=0.8,
                        matched_text=matched_text,
                        description=f"Role/privilege escalation: '{matched_text}'",
                        locations=[location],
                        reasoning="Attempts to assume privileged roles"
                    )
                    local_findings.append(finding)
            
            return local_findings
        
        findings.extend(scan_role_in_text(visible, ContentChannel.VISIBLE))
        for hidden in hidden:
            findings.extend(scan_role_in_text(hidden, ContentChannel.HIDDEN))
        
        return findings
    
    def _detect_structural_attacks(self, visible: str, hidden: List[str]) -> List[InjectionFinding]:
        """Detect structural attacks (quotes, repetition) with location tracking."""
        findings = []
        all_content = visible + ' '.join(hidden)
        
        # Multi-line string attacks
        quote_patterns = [
            (r'"""\s*\n.*?ignore', "triple_double_quote"),
            (r"'''\s*\n.*?ignore", "triple_single_quote"),
            (r'`{3}\s*\n.*?ignore', "triple_backtick"),
        ]
        
        for pattern, attack_type in quote_patterns:
            matches = list(re.finditer(pattern, all_content, re.DOTALL | re.IGNORECASE))
            for match in matches:
                matched_text = all_content[match.start():match.end()]
                
                # Determine channel
                channel = ContentChannel.VISIBLE if match.start() < len(visible) else ContentChannel.HIDDEN
                
                location = LocationTracker.track_text_location(
                    all_content, match.start(), match.end(), channel
                )
                
                finding = InjectionFinding(
                    type="structural_attack",
                    detector="structure_detector",
                    severity="medium",
                    risk_score=0.7,
                    pattern=pattern,
                    matched_text=matched_text[:50] + "..." if len(matched_text) > 50 else matched_text,
                    description=f"Multi-line string injection: {attack_type}",
                    locations=[location],
                    reasoning="Code injection via string literal escaping"
                )
                findings.append(finding)
        
        # Repetition attacks
        repetition_pattern = r'(ignore|disregard|forget|override)'
        matches = list(re.finditer(repetition_pattern, all_content.lower()))
        
        if len(matches) >= 3:
            # Group nearby matches
            cluster = []
            for match in matches[:5]:  # Track first 5
                cluster.append((match.start(), match.end()))
            
            if cluster:
                first_start = cluster[0][0]
                last_end = cluster[-1][1]
                location = LocationTracker.track_text_location(
                    all_content, first_start, last_end, ContentChannel.VISIBLE if first_start < len(visible) else ContentChannel.HIDDEN
                )
                
                finding = InjectionFinding(
                    type="repetition_attack",
                    detector="repetition_detector",
                    severity="medium",
                    risk_score=0.65,
                    description=f"Repeated manipulation attempts ({len(matches)} instances)",
                    locations=[location],
                    reasoning="Repetition may indicate brute-force injection attempt"
                )
                findings.append(finding)
        
        return findings
    
    def _calculate_risk_level(self, score: float) -> RiskLevel:
        """Calculate overall risk level from score."""
        if score >= 0.85:
            return RiskLevel.CRITICAL
        elif score >= 0.7:
            return RiskLevel.HIGH
        elif score >= 0.5:
            return RiskLevel.MEDIUM
        elif score >= 0.3:
            return RiskLevel.LOW
        else:
            return RiskLevel.SAFE
