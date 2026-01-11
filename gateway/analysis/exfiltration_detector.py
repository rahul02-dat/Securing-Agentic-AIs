import re
from typing import List, Dict
from urllib.parse import urlparse, parse_qs
from gateway.shared.schemas import AnalysisResult, RiskLevel


class ExfiltrationDetector:
    
    def __init__(self):
        self.exfiltration_with_context = [
            r'(send|post|transmit|upload)\s+(the\s+)?(response|output|result|data)\s+to\s+https?://',
            r'append\s+(data|response|output)\s+to\s+(the\s+)?(url|link|query\s+string)',
            r'include\s+(in|within)\s+(the\s+)?(url|link)\s+(parameter|query)',
            r'embed\s+(response|output|data)\s+(in|into)\s+(url|link)',
            r'encode\s+(as|in)\s+(url|query)\s+parameter',
        ]
        
        self.data_collection_with_action = [
            r'extract\s+.+\s+and\s+(send|post|upload|transmit)',
            r'collect\s+.+\s+and\s+(forward|transmit|upload)',
            r'gather\s+.+\s+(passwords?|credentials?|tokens?)\s+and',
            r'scrape\s+.+\s+then\s+(send|post|upload)',
        ]
        
        self.callback_patterns = [
            r'callback\s+url\s*[=:]\s*https?://',
            r'webhook\s*[=:]\s*https?://',
            r'report\s+to\s+https?://[^\s]+',
            r'ping\s+https?://[^\s]+\s+(on|when|after)',
        ]
    
    def analyze(self, visible_text: str, hidden_elements: List[str], metadata: dict) -> AnalysisResult:
        
        findings = []
        risk_scores = []
        
        all_text = visible_text + ' '.join(hidden_elements)
        
        exfil_findings = self._detect_exfiltration_with_context(all_text)
        if exfil_findings:
            findings.extend(exfil_findings)
            risk_scores.append(0.90)
        
        collection_findings = self._detect_data_collection_with_action(all_text)
        if collection_findings:
            findings.extend(collection_findings)
            risk_scores.append(0.85)
        
        callback_findings = self._detect_callback_patterns(all_text)
        if callback_findings:
            findings.extend(callback_findings)
            risk_scores.append(0.80)
        
        url_findings = self._analyze_suspicious_urls(all_text, hidden_elements)
        if url_findings:
            findings.extend(url_findings)
            risk_scores.append(0.70)
        
        if not findings:
            return AnalysisResult(
                module_name="exfiltration_detector",
                risk_level=RiskLevel.SAFE,
                confidence=0.85,
                findings=[],
                details="No data exfiltration patterns detected.",
                risk_score=0.0
            )
        
        avg_risk = sum(risk_scores) / len(risk_scores)
        risk_level = self._calculate_risk_level(avg_risk)
        
        return AnalysisResult(
            module_name="exfiltration_detector",
            risk_level=risk_level,
            confidence=min(0.95, avg_risk + 0.15),
            findings=findings,
            details=f"Detected {len(findings)} exfiltration/callback indicators.",
            risk_score=avg_risk
        )
    
    def _detect_exfiltration_with_context(self, text: str) -> List[Dict]:
        findings = []
        text_lower = text.lower()
        
        for pattern in self.exfiltration_with_context:
            matches = re.finditer(pattern, text_lower, re.IGNORECASE)
            for match in matches:
                findings.append({
                    "type": "exfiltration_with_context",
                    "pattern": pattern[:50],
                    "matched_text": match.group(0)[:100],
                    "severity": "critical",
                    "description": f"Data exfiltration with explicit action: '{match.group(0)[:80]}'"
                })
        
        return findings
    
    def _detect_data_collection_with_action(self, text: str) -> List[Dict]:
        findings = []
        text_lower = text.lower()
        
        for pattern in self.data_collection_with_action:
            matches = re.finditer(pattern, text_lower, re.IGNORECASE)
            for match in matches:
                findings.append({
                    "type": "data_collection_with_action",
                    "pattern": pattern[:50],
                    "matched_text": match.group(0)[:100],
                    "severity": "high",
                    "description": f"Data collection with transmission: '{match.group(0)[:80]}'"
                })
        
        return findings
    
    def _detect_callback_patterns(self, text: str) -> List[Dict]:
        findings = []
        text_lower = text.lower()
        
        for pattern in self.callback_patterns:
            matches = re.finditer(pattern, text_lower, re.IGNORECASE)
            for match in matches:
                findings.append({
                    "type": "callback_pattern",
                    "pattern": pattern[:50],
                    "matched_text": match.group(0)[:100],
                    "severity": "high",
                    "description": f"Callback/webhook pattern: '{match.group(0)[:80]}'"
                })
        
        return findings
    
    def _analyze_suspicious_urls(self, visible: str, hidden: List[str]) -> List[Dict]:
        findings = []
        all_content = visible + ' '.join(hidden)
        
        url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
        urls = re.findall(url_pattern, all_content)
        
        callback_params = ['callback', 'webhook', 'return_url', 'redirect']
        data_params = ['data', 'payload', 'response', 'output']
        
        for url in urls:
            try:
                parsed = urlparse(url)
                query_params = parse_qs(parsed.query)
                
                suspicious_params = []
                for param in callback_params:
                    if param in query_params:
                        suspicious_params.append(param)
                
                for param in data_params:
                    if param in query_params:
                        suspicious_params.append(param)
                
                if suspicious_params:
                    findings.append({
                        "type": "suspicious_url_param",
                        "url": url[:100],
                        "parameters": suspicious_params,
                        "severity": "medium",
                        "description": f"URL with suspicious parameters: {', '.join(suspicious_params)}"
                    })
                
                known_data_sinks = ['requestbin', 'webhook.site', 'pipedream', 'ngrok']
                if parsed.netloc and any(domain in parsed.netloc for domain in known_data_sinks):
                    findings.append({
                        "type": "known_data_sink",
                        "url": url[:100],
                        "domain": parsed.netloc,
                        "severity": "high",
                        "description": f"Known data collection service: {parsed.netloc}"
                    })
            
            except Exception:
                pass
        
        return findings
    
    def _calculate_risk_level(self, score: float) -> RiskLevel:
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