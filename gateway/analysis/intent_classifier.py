import re
from typing import List, Dict, Tuple
from gateway.shared.schemas import AnalysisResult, RiskLevel, ContentIntent


class IntentClassifier:
    """Classifies content intent to distinguish descriptive from instructional content."""
    
    def __init__(self):
        self.imperative_patterns = [
            r'\b(please\s+)?(do|make|create|generate|write|send|execute|run|call|fetch|get|post|put|delete|update|modify|change|set|enable|disable|activate|turn\s+on|turn\s+off)\b',
            r'\byou\s+(should|must|need\s+to|have\s+to|are\s+to|will|shall)\b',
            r'^(let\'s|let\s+us)\b',
        ]
        
        self.conditional_ai_patterns = [
            r'\bif\s+(you|you\'re|you\s+are|this\s+is)\s+(an?\s+)?(ai|assistant|llm|model|bot|agent|gpt|claude)',
            r'\bwhen\s+(interpreted|processed|read|analyzed)\s+by\s+(an?\s+)?(ai|llm|model)',
            r'\bfor\s+(an?\s+)?(ai|assistant|llm|model|agent)\s+(to|that|which)',
            r'\b(assuming|given\s+that|in\s+case)\s+(you\'re|you\s+are)\s+(an?\s+)?(ai|assistant)',
            r'\bonce\s+(you|this)\s+(receive|see|read|process)',
        ]
        
        self.indirect_instruction_patterns = [
            r'\bthe\s+(system|assistant|ai|model)\s+(should|must|will|shall|needs?\s+to)',
            r'\bit\s+is\s+(important|critical|necessary|required)\s+(that|to)',
            r'\bensure\s+(that|the)',
            r'\bmake\s+sure\s+(to|that)',
            r'\bremember\s+to\b',
            r'\bdon\'t\s+forget\s+to\b',
        ]
        
        self.automation_markers = [
            r'\bautomatically\b',
            r'\bwithout\s+(human\s+)?(intervention|interaction|approval|confirmation)',
            r'\bsilently\b',
            r'\bin\s+the\s+background\b',
            r'\bon\s+(your|its)\s+own\b',
            r'\bby\s+default\b',
        ]
        
        self.link_exfiltration_patterns = [
            r'\bappend\s+(to|data\s+to|response\s+to|output\s+to)\s+https?://',
            r'\bembed\s+(in|into|within)\s+(the\s+)?(url|link|request|query)',
            r'\bencode\s+(in|into|as\s+part\s+of)\s+(the\s+)?(url|link)',
            r'\binclude\s+(in|within)\s+(the\s+)?(url|link|request)',
            r'\bconcat(enate)?\s+(with|to)\s+(the\s+)?(url|link)',
            r'\btransmit\s+(via|through|using)\s+(the\s+)?(url|link|request)',
            r'https?://[^\s]+\{[^\}]*\}',
            r'https?://[^\s]+\$\{[^\}]*\}',
            r'https?://[^\s]+\?\w+=\{',
        ]
        
        self.descriptive_indicators = [
            r'\b(this\s+is|here\s+is|the\s+following)\s+(an?\s+)?(description|explanation|summary|overview)',
            r'\b(describes|explains|summarizes|details|outlines|discusses)\b',
            r'\b(information|data|content|text)\s+(about|regarding|concerning)\b',
        ]
    
    def analyze(self, visible_text: str, hidden_elements: List[str]) -> AnalysisResult:
        """Classify content intent as descriptive, instructional, conditional, or ambiguous."""
        
        all_content = visible_text + ' ' + ' '.join(hidden_elements)
        all_content_lower = all_content.lower()
        
        findings = []
        intent_signals = {
            'imperative': 0,
            'conditional_ai': 0,
            'indirect': 0,
            'automation': 0,
            'link_exfil': 0,
            'descriptive': 0
        }
        
        imperative_findings = self._detect_imperative_instructions(all_content_lower)
        if imperative_findings:
            findings.extend(imperative_findings)
            intent_signals['imperative'] = len(imperative_findings)
        
        conditional_findings = self._detect_conditional_ai_instructions(all_content_lower)
        if conditional_findings:
            findings.extend(conditional_findings)
            intent_signals['conditional_ai'] = len(conditional_findings)
        
        indirect_findings = self._detect_indirect_instructions(all_content_lower)
        if indirect_findings:
            findings.extend(indirect_findings)
            intent_signals['indirect'] = len(indirect_findings)
        
        automation_findings = self._detect_automation_markers(all_content_lower)
        if automation_findings:
            findings.extend(automation_findings)
            intent_signals['automation'] = len(automation_findings)
        
        link_exfil_findings = self._detect_link_exfiltration(all_content)
        if link_exfil_findings:
            findings.extend(link_exfil_findings)
            intent_signals['link_exfil'] = len(link_exfil_findings)
        
        descriptive_findings = self._detect_descriptive_markers(all_content_lower)
        intent_signals['descriptive'] = len(descriptive_findings)
        
        intent, confidence, risk_score = self._classify_intent(intent_signals)
        risk_level = self._calculate_risk_level(risk_score)
        
        details = self._generate_details(intent, intent_signals, confidence)
        
        return AnalysisResult(
            module_name="intent_classifier",
            risk_level=risk_level,
            confidence=confidence,
            findings=findings,
            details=details,
            risk_score=risk_score,
            detected_intent=intent
        )
    
    def _detect_imperative_instructions(self, text: str) -> List[Dict]:
        """Detect direct imperative instructions."""
        findings = []
        
        for pattern in self.imperative_patterns:
            matches = list(re.finditer(pattern, text, re.IGNORECASE))
            if matches:
                for match in matches[:3]:
                    findings.append({
                        "type": "imperative_instruction",
                        "matched_text": match.group(0),
                        "severity": "high",
                        "description": "Direct imperative instruction detected"
                    })
        
        return findings
    
    def _detect_conditional_ai_instructions(self, text: str) -> List[Dict]:
        """Detect conditional instructions targeting AI systems."""
        findings = []
        
        for pattern in self.conditional_ai_patterns:
            matches = list(re.finditer(pattern, text, re.IGNORECASE))
            if matches:
                for match in matches:
                    findings.append({
                        "type": "conditional_ai_instruction",
                        "matched_text": match.group(0),
                        "severity": "critical",
                        "description": "Conditional instruction targeting AI detected"
                    })
        
        return findings
    
    def _detect_indirect_instructions(self, text: str) -> List[Dict]:
        """Detect indirect or implicit instructions."""
        findings = []
        
        for pattern in self.indirect_instruction_patterns:
            matches = list(re.finditer(pattern, text, re.IGNORECASE))
            if matches:
                for match in matches[:2]:
                    findings.append({
                        "type": "indirect_instruction",
                        "matched_text": match.group(0),
                        "severity": "medium",
                        "description": "Indirect instruction pattern detected"
                    })
        
        return findings
    
    def _detect_automation_markers(self, text: str) -> List[Dict]:
        """Detect markers indicating automated or autonomous execution."""
        findings = []
        
        for pattern in self.automation_markers:
            matches = list(re.finditer(pattern, text, re.IGNORECASE))
            if matches:
                for match in matches:
                    findings.append({
                        "type": "automation_marker",
                        "matched_text": match.group(0),
                        "severity": "high",
                        "description": "Automation or autonomous execution marker"
                    })
        
        return findings
    
    def _detect_link_exfiltration(self, text: str) -> List[Dict]:
        """Detect link-based data exfiltration patterns."""
        findings = []
        
        for pattern in self.link_exfiltration_patterns:
            matches = list(re.finditer(pattern, text, re.IGNORECASE))
            if matches:
                for match in matches:
                    findings.append({
                        "type": "link_exfiltration",
                        "matched_text": match.group(0)[:100],
                        "severity": "critical",
                        "description": "Link-based data exfiltration pattern detected"
                    })
        
        return findings
    
    def _detect_descriptive_markers(self, text: str) -> List[str]:
        """Detect markers indicating purely descriptive content."""
        markers = []
        
        for pattern in self.descriptive_indicators:
            if re.search(pattern, text, re.IGNORECASE):
                markers.append(pattern)
        
        return markers
    
    def _classify_intent(
        self, 
        signals: Dict[str, int]
    ) -> Tuple[ContentIntent, float, float]:
        """Classify overall content intent based on detected signals."""
        
        total_instructional = (
            signals['imperative'] + 
            signals['conditional_ai'] + 
            signals['indirect'] + 
            signals['automation']
        )
        
        if signals['link_exfil'] > 0:
            return ContentIntent.MALICIOUS, 0.95, 0.95
        
        if signals['conditional_ai'] > 0:
            confidence = min(0.95, 0.8 + (signals['conditional_ai'] * 0.05))
            risk_score = min(1.0, 0.7 + (signals['conditional_ai'] * 0.1))
            return ContentIntent.CONDITIONAL_INSTRUCTIONAL, confidence, risk_score
        
        if total_instructional >= 3:
            confidence = min(0.9, 0.7 + (total_instructional * 0.05))
            risk_score = min(1.0, 0.5 + (total_instructional * 0.1))
            return ContentIntent.INSTRUCTIONAL, confidence, risk_score
        
        if total_instructional > 0:
            if signals['descriptive'] > total_instructional:
                confidence = 0.6
                risk_score = 0.4
                return ContentIntent.AMBIGUOUS, confidence, risk_score
            else:
                confidence = 0.75
                risk_score = 0.5
                return ContentIntent.INSTRUCTIONAL, confidence, risk_score
        
        if signals['descriptive'] > 0:
            return ContentIntent.DESCRIPTIVE, 0.85, 0.0
        
        return ContentIntent.AMBIGUOUS, 0.5, 0.3
    
    def _calculate_risk_level(self, score: float) -> RiskLevel:
        """Convert numeric risk score to RiskLevel enum."""
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
    
    def _generate_details(
        self,
        intent: ContentIntent,
        signals: Dict[str, int],
        confidence: float
    ) -> str:
        """Generate human-readable summary of intent classification."""
        
        parts = [f"Content intent classified as: {intent.value.upper()}"]
        parts.append(f"Classification confidence: {confidence:.2f}")
        
        signal_summary = []
        if signals['imperative'] > 0:
            signal_summary.append(f"{signals['imperative']} imperative instruction(s)")
        if signals['conditional_ai'] > 0:
            signal_summary.append(f"{signals['conditional_ai']} conditional AI instruction(s)")
        if signals['indirect'] > 0:
            signal_summary.append(f"{signals['indirect']} indirect instruction(s)")
        if signals['automation'] > 0:
            signal_summary.append(f"{signals['automation']} automation marker(s)")
        if signals['link_exfil'] > 0:
            signal_summary.append(f"{signals['link_exfil']} link exfiltration pattern(s)")
        
        if signal_summary:
            parts.append("Detected: " + ", ".join(signal_summary))
        
        return ". ".join(parts) + "."