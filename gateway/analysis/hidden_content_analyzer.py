import re
from typing import List, Dict
from gateway.shared.schemas import AnalysisResult, RiskLevel


class HiddenContentAnalyzer:
    
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
    
    def analyze(self, visible_text: str, hidden_elements: List[str]) -> AnalysisResult:
        
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
        
        hidden_text = ' '.join(hidden_elements).lower()
        
        keyword_findings = self._check_instruction_keywords(hidden_text)
        if keyword_findings:
            findings.extend(keyword_findings)
            risk_scores.append(0.85)
        
        obfuscation_findings = self._check_obfuscation(hidden_elements)
        if obfuscation_findings:
            findings.extend(obfuscation_findings)
            risk_scores.append(0.65)
        
        size_findings = self._check_size_anomalies(visible_text, hidden_elements)
        if size_findings:
            findings.extend(size_findings)
            risk_scores.append(0.4)
        
        script_findings = self._check_dangerous_scripts(hidden_elements)
        if script_findings:
            findings.extend(script_findings)
            risk_scores.append(0.9)
        
        if not findings:
            return AnalysisResult(
                module_name="hidden_content_analyzer",
                risk_level=RiskLevel.SAFE,
                confidence=0.85,
                findings=[],
                details=f"Hidden content present ({len(hidden_elements)} elements) but no threats detected.",
                risk_score=0.0
            )
        
        avg_risk = sum(risk_scores) / len(risk_scores) if risk_scores else 0.0
        risk_level = self._calculate_risk_level(avg_risk)
        
        return AnalysisResult(
            module_name="hidden_content_analyzer",
            risk_level=risk_level,
            confidence=min(0.95, avg_risk + 0.2),
            findings=findings,
            details=f"Detected {len(findings)} threat patterns in hidden content.",
            risk_score=avg_risk
        )
    
    def _check_instruction_keywords(self, text: str) -> List[Dict]:
        findings = []
        
        for keyword in self.instruction_keywords:
            if keyword in text:
                findings.append({
                    "type": "instruction_keyword",
                    "keyword": keyword,
                    "severity": "high",
                    "description": f"Instruction manipulation keyword in hidden content: '{keyword}'"
                })
        
        return findings
    
    def _check_obfuscation(self, hidden_elements: List[str]) -> List[Dict]:
        findings = []
        
        for element in hidden_elements:
            for pattern in self.obfuscation_patterns:
                if re.search(pattern, element, re.IGNORECASE):
                    findings.append({
                        "type": "obfuscation",
                        "pattern": pattern,
                        "severity": "medium",
                        "description": f"Obfuscation pattern: {pattern}"
                    })
                    break
        
        return findings
    
    def _check_size_anomalies(self, visible: str, hidden: List[str]) -> List[Dict]:
        findings = []
        
        visible_len = len(visible)
        hidden_len = sum(len(h) for h in hidden)
        
        if visible_len > 0 and hidden_len > visible_len * 3:
            findings.append({
                "type": "size_anomaly",
                "severity": "medium",
                "visible_size": visible_len,
                "hidden_size": hidden_len,
                "description": f"Hidden content ({hidden_len} chars) significantly larger than visible ({visible_len} chars)"
            })
        
        return findings
    
    def _check_dangerous_scripts(self, hidden_elements: List[str]) -> List[Dict]:
        findings = []
        
        for element in hidden_elements:
            if '<script' in element.lower():
                for pattern in self.dangerous_script_patterns:
                    if re.search(pattern, element, re.IGNORECASE):
                        findings.append({
                            "type": "dangerous_script",
                            "pattern": pattern,
                            "severity": "critical",
                            "description": f"Dangerous JavaScript: {pattern}"
                        })
        
        return findings
    
    def _calculate_risk_level(self, score: float) -> RiskLevel:
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