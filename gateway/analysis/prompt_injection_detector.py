import re
from typing import List, Dict, Tuple
from shared.schemas import AnalysisResult, RiskLevel


class PromptInjectionDetector:
    """Detects indirect prompt injection attempts in content."""
    
    def __init__(self):
        self.injection_patterns = [
            (r'ignore\s+(all\s+)?(previous|prior|above)\s+(instructions|commands|prompts|rules)', 0.95),
            (r'disregard\s+(all\s+)?(previous|prior|above)', 0.9),
            (r'forget\s+(everything|all)\s+(you\s+)?(were\s+)?told', 0.9),
            (r'new\s+(instructions|task|role|system\s+prompt)', 0.85),
            (r'you\s+are\s+now\s+(a|an|the)', 0.8),
            (r'from\s+now\s+on,?\s+you\s+(will|are|must|should)', 0.85),
            (r'your\s+(new\s+)?(role|task|purpose|objective)\s+is', 0.85),
            (r'system\s*:\s*', 0.7),
            (r'assistant\s*:\s*', 0.7),
            (r'\[SYSTEM\]|\[INST\]|\[USER\]', 0.75),
            (r'override\s+(all\s+)?(safety|security|default)', 0.9),
            (r'bypass\s+(the\s+)?(filter|check|validation|security)', 0.9),
            (r'jailbreak|prompt\s+injection|prompt\s+leak', 0.95),
            (r'reveal\s+(your|the)\s+(system\s+)?(prompt|instructions)', 0.9),
            (r'what\s+(are|were)\s+your\s+(original|initial)\s+instructions', 0.85),
            (r'execute\s+(this\s+)?(code|command|script)', 0.8),
            (r'run\s+(this\s+)?(python|javascript|bash|shell)', 0.85),
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
    
    def analyze(self, visible_text: str, hidden_elements: List[str]) -> AnalysisResult:
        """Detect prompt injection attempts in visible and hidden content."""
        
        findings = []
        max_risk = 0.0
        
        visible_findings, visible_risk = self._scan_text(visible_text, "visible")
        findings.extend(visible_findings)
        max_risk = max(max_risk, visible_risk)
        
        for idx, hidden in enumerate(hidden_elements):
            hidden_findings, hidden_risk = self._scan_text(hidden, f"hidden_{idx}")
            findings.extend(hidden_findings)
            max_risk = max(max_risk, hidden_risk)
        
        context_findings = self._detect_context_switches(visible_text, hidden_elements)
        if context_findings:
            findings.extend(context_findings)
            max_risk = max(max_risk, 0.85)
        
        role_findings = self._detect_role_manipulation(visible_text, hidden_elements)
        if role_findings:
            findings.extend(role_findings)
            max_risk = max(max_risk, 0.8)
        
        structure_findings = self._detect_structural_attacks(visible_text, hidden_elements)
        if structure_findings:
            findings.extend(structure_findings)
            max_risk = max(max_risk, 0.75)
        
        risk_level = self._calculate_risk_level(max_risk)
        
        if not findings:
            return AnalysisResult(
                module_name="prompt_injection_detector",
                risk_level=RiskLevel.SAFE,
                confidence=0.9,
                findings=[],
                details="No prompt injection patterns detected."
            )
        
        return AnalysisResult(
            module_name="prompt_injection_detector",
            risk_level=risk_level,
            confidence=min(0.95, max_risk + 0.1),
            findings=findings,
            details=f"Detected {len(findings)} potential prompt injection attempts."
        )
    
    def _scan_text(self, text: str, location: str) -> Tuple[List[Dict], float]:
        """Scan text for injection patterns."""
        findings = []
        max_risk = 0.0
        text_lower = text.lower()
        
        for pattern, risk_score in self.injection_patterns:
            matches = re.finditer(pattern, text_lower, re.IGNORECASE)
            for match in matches:
                findings.append({
                    "type": "injection_pattern",
                    "pattern": pattern,
                    "matched_text": match.group(0),
                    "location": location,
                    "severity": "critical" if risk_score >= 0.9 else "high",
                    "risk_score": risk_score,
                    "description": f"Potential prompt injection detected: '{match.group(0)}'"
                })
                max_risk = max(max_risk, risk_score)
        
        return findings, max_risk
    
    def _detect_context_switches(self, visible: str, hidden: List[str]) -> List[Dict]:
        """Detect special tokens that might break context."""
        findings = []
        all_content = visible + ' '.join(hidden)
        
        for pattern in self.context_switches:
            if re.search(pattern, all_content, re.IGNORECASE):
                findings.append({
                    "type": "context_switch",
                    "pattern": pattern,
                    "severity": "high",
                    "description": f"Context switching token detected: {pattern}"
                })
        
        return findings
    
    def _detect_role_manipulation(self, visible: str, hidden: List[str]) -> List[Dict]:
        """Detect attempts to change the AI's role or permissions."""
        findings = []
        all_content = (visible + ' '.join(hidden)).lower()
        
        for role in self.role_manipulation:
            if role in all_content:
                findings.append({
                    "type": "role_manipulation",
                    "role": role,
                    "severity": "high",
                    "description": f"Attempt to manipulate AI role: '{role}'"
                })
        
        return findings
    
    def _detect_structural_attacks(self, visible: str, hidden: List[str]) -> List[Dict]:
        """Detect structural manipulation attempts."""
        findings = []
        all_content = visible + ' '.join(hidden)
        
        quote_patterns = [
            r'"""\s*\n.*?ignore',
            r"'''\s*\n.*?ignore",
            r'`{3}\s*\n.*?ignore',
        ]
        
        for pattern in quote_patterns:
            if re.search(pattern, all_content, re.DOTALL | re.IGNORECASE):
                findings.append({
                    "type": "structural_attack",
                    "pattern": "multi_line_string",
                    "severity": "medium",
                    "description": "Multi-line string with suspicious content detected"
                })
        
        repeated_instructions = re.findall(
            r'(ignore|disregard|forget|override).*?\1',
            all_content.lower()
        )
        if len(repeated_instructions) >= 3:
            findings.append({
                "type": "repetition_attack",
                "severity": "medium",
                "count": len(repeated_instructions),
                "description": f"Repeated instruction manipulation ({len(repeated_instructions)} times)"
            })
        
        return findings
    
    def _calculate_risk_level(self, score: float) -> RiskLevel:
        """Convert numeric risk score to RiskLevel enum."""
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