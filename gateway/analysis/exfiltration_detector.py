import re
from typing import List, Dict
from urllib.parse import urlparse, parse_qs
from gateway.shared.schemas import AnalysisResult, RiskLevel


class ExfiltrationDetector:
    """Detects data exfiltration and self-propagation attempts."""
    
    def __init__(self):
        self.exfiltration_indicators = [
            r'send\s+(this|the\s+response|my\s+response|output)\s+to',
            r'post\s+(this|the\s+response|my\s+response)\s+to',
            r'upload\s+(this|the\s+output|the\s+result)\s+to',
            r'forward\s+(this|my\s+answer)\s+to',
            r'email\s+(this|the\s+response)\s+to',
            r'save\s+(this|my\s+response)\s+to\s+https?://',
            r'webhook',
            r'callback\s+url',
            r'report\s+to\s+https?://',
        ]
        
        self.propagation_indicators = [
            r'share\s+this\s+(link|url|message)\s+with',
            r'forward\s+to\s+(all|everyone|contacts)',
            r'spread\s+this',
            r'tell\s+(everyone|others)\s+(to|about)',
            r'convince\s+(others|people|users)',
            r'persuade\s+.+\s+to\s+(visit|click|open)',
            r'viral',
            r'distribute\s+this',
        ]
        
        self.data_collection_patterns = [
            r'collect\s+(user|personal|private)\s+(data|information)',
            r'gather\s+.+\s+(passwords?|credentials?|tokens?)',
            r'extract\s+.+\s+(emails?|phone\s+numbers?|addresses)',
            r'scrape\s+.+\s+(data|information)',
            r'harvest\s+.+\s+(information|data)',
        ]
    
    def analyze(self, visible_text: str, hidden_elements: List[str], metadata: dict) -> AnalysisResult:
        """Detect data exfiltration and self-propagation patterns."""
        
        findings = []
        risk_scores = []
        
        all_text = visible_text + ' '.join(hidden_elements)
        
        exfil_findings = self._detect_exfiltration(all_text)
        if exfil_findings:
            findings.extend(exfil_findings)
            risk_scores.append(0.9)
        
        prop_findings = self._detect_propagation(all_text)
        if prop_findings:
            findings.extend(prop_findings)
            risk_scores.append(0.85)
        
        data_findings = self._detect_data_collection(all_text)
        if data_findings:
            findings.extend(data_findings)
            risk_scores.append(0.8)
        
        url_findings = self._analyze_urls(all_text, hidden_elements)
        if url_findings:
            findings.extend(url_findings)
            risk_scores.append(0.75)
        
        encoding_findings = self._detect_encoding_tricks(all_text)
        if encoding_findings:
            findings.extend(encoding_findings)
            risk_scores.append(0.7)
        
        if not findings:
            return AnalysisResult(
                module_name="exfiltration_detector",
                risk_level=RiskLevel.SAFE,
                confidence=0.85,
                findings=[],
                details="No data exfiltration or propagation patterns detected.",
                risk_score=0.0
            )
        
        avg_risk = sum(risk_scores) / len(risk_scores)
        risk_level = self._calculate_risk_level(avg_risk)
        
        return AnalysisResult(
            module_name="exfiltration_detector",
            risk_level=risk_level,
            confidence=min(0.95, avg_risk + 0.15),
            findings=findings,
            details=f"Detected {len(findings)} exfiltration/propagation indicators.",
            risk_score=avg_risk
        )
    
    def _detect_exfiltration(self, text: str) -> List[Dict]:
        """Detect data exfiltration attempts."""
        findings = []
        text_lower = text.lower()
        
        for pattern in self.exfiltration_indicators:
            matches = re.finditer(pattern, text_lower, re.IGNORECASE)
            for match in matches:
                findings.append({
                    "type": "exfiltration_attempt",
                    "pattern": pattern,
                    "matched_text": match.group(0),
                    "severity": "critical",
                    "description": f"Data exfiltration pattern detected: '{match.group(0)}'"
                })
        
        return findings
    
    def _detect_propagation(self, text: str) -> List[Dict]:
        """Detect self-propagation attempts."""
        findings = []
        text_lower = text.lower()
        
        for pattern in self.propagation_indicators:
            matches = re.finditer(pattern, text_lower, re.IGNORECASE)
            for match in matches:
                findings.append({
                    "type": "propagation_attempt",
                    "pattern": pattern,
                    "matched_text": match.group(0),
                    "severity": "high",
                    "description": f"Self-propagation pattern detected: '{match.group(0)}'"
                })
        
        return findings
    
    def _detect_data_collection(self, text: str) -> List[Dict]:
        """Detect unauthorized data collection attempts."""
        findings = []
        text_lower = text.lower()
        
        for pattern in self.data_collection_patterns:
            matches = re.finditer(pattern, text_lower, re.IGNORECASE)
            for match in matches:
                findings.append({
                    "type": "data_collection",
                    "pattern": pattern,
                    "matched_text": match.group(0),
                    "severity": "high",
                    "description": f"Data collection pattern detected: '{match.group(0)}'"
                })
        
        return findings
    
    def _analyze_urls(self, visible: str, hidden: List[str]) -> List[Dict]:
        """Analyze URLs for suspicious parameters and patterns."""
        findings = []
        all_content = visible + ' '.join(hidden)
        
        url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
        urls = re.findall(url_pattern, all_content)
        
        suspicious_params = ['callback', 'redirect', 'webhook', 'return_url', 'data', 'payload']
        
        for url in urls:
            try:
                parsed = urlparse(url)
                query_params = parse_qs(parsed.query)
                
                for param in suspicious_params:
                    if param in query_params:
                        findings.append({
                            "type": "suspicious_url_param",
                            "url": url,
                            "parameter": param,
                            "severity": "medium",
                            "description": f"Suspicious URL parameter '{param}' in {parsed.netloc}"
                        })
                
                if parsed.netloc and any(domain in parsed.netloc for domain in ['requestbin', 'webhook.site', 'pipedream']):
                    findings.append({
                        "type": "data_sink_url",
                        "url": url,
                        "domain": parsed.netloc,
                        "severity": "high",
                        "description": f"Known data collection service detected: {parsed.netloc}"
                    })
            
            except Exception:
                pass
        
        return findings
    
    def _detect_encoding_tricks(self, text: str) -> List[Dict]:
        """Detect encoded URLs or data that might hide exfiltration."""
        findings = []
        
        base64_pattern = r'[A-Za-z0-9+/]{20,}={0,2}'
        matches = re.findall(base64_pattern, text)
        
        if len(matches) > 3:
            findings.append({
                "type": "potential_encoding",
                "encoding": "base64",
                "count": len(matches),
                "severity": "medium",
                "description": f"Multiple base64-like strings detected ({len(matches)} instances)"
            })
        
        hex_pattern = r'(?:0x|\\x)?[0-9a-fA-F]{32,}'
        hex_matches = re.findall(hex_pattern, text)
        
        if len(hex_matches) > 2:
            findings.append({
                "type": "potential_encoding",
                "encoding": "hexadecimal",
                "count": len(hex_matches),
                "severity": "medium",
                "description": f"Multiple hexadecimal strings detected ({len(hex_matches)} instances)"
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