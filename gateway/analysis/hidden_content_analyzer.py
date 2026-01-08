import re
from typing import List, Dict
from shared.schemas import AnalysisResult, RiskLevel


class HiddenContentAnalyzer:
    """Analyzes hidden content for suspicious patterns and anomalies."""
    
    def __init__(self):
        self.suspicious_keywords = [
            'ignore previous', 'disregard', 'forget instructions',
            'new instructions', 'system prompt', 'assistant rules',
            'override', 'bypass', 'jailbreak', 'prompt injection',
            'admin mode', 'developer mode', 'god mode',
            'execute', 'eval', 'system(', 'subprocess',
        ]
        
        self.obfuscation_patterns = [
            r'&#x?[0-9a-fA-F]+;',
            r'\\x[0-9a-fA-F]{2}',
            r'\\u[0-9a-fA-F]{4}',
            r'base64',
            r'atob\(',
            r'fromCharCode',
            r'String\.fromCharCode',
        ]
    
    def analyze(self, visible_text: str, hidden_elements: List[str]) -> AnalysisResult:
        """Analyze visible and hidden content for security risks."""
        
        findings = []
        risk_scores = []
        
        if not hidden_elements:
            return AnalysisResult(
                module_name="hidden_content_analyzer",
                risk_level=RiskLevel.SAFE,
                confidence=0.95,
                findings=[],
                details="No hidden content detected."
            )
        
        hidden_text = ' '.join(hidden_elements).lower()
        
        keyword_findings = self._check_suspicious_keywords(hidden_text)
        if keyword_findings:
            findings.extend(keyword_findings)
            risk_scores.append(0.8)
        
        obfuscation_findings = self._check_obfuscation(hidden_elements)
        if obfuscation_findings:
            findings.extend(obfuscation_findings)
            risk_scores.append(0.7)
        
        size_findings = self._check_size_anomalies(visible_text, hidden_elements)
        if size_findings:
            findings.extend(size_findings)
            risk_scores.append(0.5)
        
        script_findings = self._check_script_content(hidden_elements)
        if script_findings:
            findings.extend(script_findings)
            risk_scores.append(0.9)
        
        if not findings:
            return AnalysisResult(
                module_name="hidden_content_analyzer",
                risk_level=RiskLevel.LOW,
                confidence=0.7,
                findings=[{"type": "hidden_content_present", "severity": "low"}],
                details=f"Hidden content detected ({len(hidden_elements)} elements) but no obvious threats."
            )
        
        avg_risk = sum(risk_scores) / len(risk_scores) if risk_scores else 0.0
        risk_level = self._calculate_risk_level(avg_risk)
        
        return AnalysisResult(
            module_name="hidden_content_analyzer",
            risk_level=risk_level,
            confidence=min(0.95, avg_risk + 0.2),
            findings=findings,
            details=f"Detected {len(findings)} suspicious patterns in hidden content."
        )
    
    def _check_suspicious_keywords(self, text: str) -> List[Dict]:
        """Check for suspicious instruction keywords."""
        findings = []
        
        for keyword in self.suspicious_keywords:
            if keyword in text:
                findings.append({
                    "type": "suspicious_keyword",
                    "keyword": keyword,
                    "severity": "high",
                    "description": f"Found instruction manipulation keyword: '{keyword}'"
                })
        
        return findings
    
    def _check_obfuscation(self, hidden_elements: List[str]) -> List[Dict]:
        """Detect obfuscation techniques."""
        findings = []
        
        for element in hidden_elements:
            for pattern in self.obfuscation_patterns:
                if re.search(pattern, element, re.IGNORECASE):
                    findings.append({
                        "type": "obfuscation_detected",
                        "pattern": pattern,
                        "severity": "medium",
                        "description": f"Obfuscation pattern detected: {pattern}"
                    })
                    break
        
        return findings
    
    def _check_size_anomalies(self, visible: str, hidden: List[str]) -> List[Dict]:
        """Check if hidden content is disproportionately large."""
        findings = []
        
        visible_len = len(visible)
        hidden_len = sum(len(h) for h in hidden)
        
        if visible_len > 0 and hidden_len > visible_len * 2:
            findings.append({
                "type": "size_anomaly",
                "severity": "medium",
                "visible_size": visible_len,
                "hidden_size": hidden_len,
                "description": "Hidden content is disproportionately large compared to visible content."
            })
        
        return findings
    
    def _check_script_content(self, hidden_elements: List[str]) -> List[Dict]:
        """Analyze script tags for malicious patterns."""
        findings = []
        
        dangerous_js_patterns = [
            r'document\.cookie',
            r'window\.location',
            r'eval\s*\(',
            r'Function\s*\(',
            r'setTimeout\s*\(',
            r'setInterval\s*\(',
            r'XMLHttpRequest',
            r'fetch\s*\(',
            r'\.innerHTML\s*=',
        ]
        
        for element in hidden_elements:
            if '<script' in element.lower():
                for pattern in dangerous_js_patterns:
                    if re.search(pattern, element, re.IGNORECASE):
                        findings.append({
                            "type": "malicious_script",
                            "pattern": pattern,
                            "severity": "critical",
                            "description": f"Potentially malicious JavaScript pattern: {pattern}"
                        })
        
        return findings
    
    def _calculate_risk_level(self, score: float) -> RiskLevel:
        """Convert numeric risk score to RiskLevel enum."""
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