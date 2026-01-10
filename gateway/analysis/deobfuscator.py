"""
Active de-obfuscation module for encoded content detection and decoding.
Handles base64, hex, URL encoding with safe recursion limits.
"""

import re
import base64
import binascii
from urllib.parse import unquote, unquote_plus
from typing import List, Dict, Tuple, Set
from gateway.shared.schemas import AnalysisResult, RiskLevel


class ContentDeobfuscator:
    """Detects and safely decodes obfuscated content."""
    
    MAX_RECURSION_DEPTH = 3
    MAX_DECODE_SIZE = 1_000_000  # 1MB limit to prevent decode bombs
    
    def __init__(self):
        self.encoding_patterns = {
            'base64': r'(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?',
            'hex': r'(?:0x|\\x)?[0-9a-fA-F]{16,}',
            'url_encoded': r'%[0-9a-fA-F]{2}(?:%[0-9a-fA-F]{2})+',
        }
    
    def analyze(self, visible_text: str, hidden_elements: List[str]) -> AnalysisResult:
        """Detect and decode obfuscated content."""
        
        all_content = visible_text + ' ' + ' '.join(hidden_elements)
        
        findings = []
        decoded_contents = []
        max_risk = 0.0
        
        # Detect encoding patterns
        encoding_detected = {}
        for enc_type, pattern in self.encoding_patterns.items():
            matches = re.findall(pattern, all_content)
            if matches:
                # Filter out short matches that are likely false positives
                valid_matches = [m for m in matches if len(m) >= 20]
                if valid_matches:
                    encoding_detected[enc_type] = valid_matches
        
        if not encoding_detected:
            return AnalysisResult(
                module_name="content_deobfuscator",
                risk_level=RiskLevel.SAFE,
                confidence=0.9,
                findings=[],
                details="No encoded content detected.",
                risk_score=0.0
            )
        
        # Attempt to decode detected patterns
        for enc_type, matches in encoding_detected.items():
            for match_str in matches[:5]:  # Limit to first 5 matches per type
                decoded, recursion_depth = self._safe_decode(match_str, enc_type)
                
                if decoded:
                    decoded_contents.append(decoded)
                    
                    # Check if decoded content contains suspicious patterns
                    is_suspicious, suspicious_patterns = self._check_decoded_content(decoded)
                    
                    risk_score = self._calculate_encoding_risk(
                        enc_type, 
                        recursion_depth, 
                        is_suspicious,
                        len(suspicious_patterns)
                    )
                    
                    max_risk = max(max_risk, risk_score)
                    
                    findings.append({
                        "type": "decoded_content",
                        "encoding": enc_type,
                        "recursion_depth": recursion_depth,
                        "original_sample": match_str[:50] + "...",
                        "decoded_sample": decoded[:100] + ("..." if len(decoded) > 100 else ""),
                        "suspicious_patterns": suspicious_patterns,
                        "severity": self._risk_to_severity(risk_score),
                        "risk_score": risk_score,
                        "description": f"Decoded {enc_type} content (depth: {recursion_depth})"
                    })
        
        # Additional risk for multiple encoding types
        if len(encoding_detected) > 1:
            max_risk = min(1.0, max_risk + 0.15)
            findings.append({
                "type": "multiple_encodings",
                "encodings": list(encoding_detected.keys()),
                "severity": "high",
                "description": f"Multiple encoding types detected: {', '.join(encoding_detected.keys())}"
            })
        
        risk_level = self._calculate_risk_level(max_risk)
        details = self._generate_details(findings, encoding_detected, max_risk)
        
        # Store decoded content for downstream analysis
        decoded_text = '\n'.join(decoded_contents)
        
        return AnalysisResult(
            module_name="content_deobfuscator",
            risk_level=risk_level,
            confidence=min(0.95, 0.75 + (len(findings) * 0.05)),
            findings=findings,
            details=details,
            risk_score=max_risk
        )
    
    def get_decoded_content(self, visible_text: str, hidden_elements: List[str]) -> str:
        """Return all decoded content for downstream analysis."""
        all_content = visible_text + ' ' + ' '.join(hidden_elements)
        decoded_parts = []
        
        for enc_type, pattern in self.encoding_patterns.items():
            matches = re.findall(pattern, all_content)
            for match_str in matches:
                if len(match_str) >= 20:
                    decoded, _ = self._safe_decode(match_str, enc_type)
                    if decoded:
                        decoded_parts.append(decoded)
        
        return '\n'.join(decoded_parts)
    
    def _safe_decode(
        self, 
        encoded_str: str, 
        encoding_type: str,
        depth: int = 0
    ) -> Tuple[str, int]:
        """Safely decode string with recursion limit."""
        
        if depth >= self.MAX_RECURSION_DEPTH:
            return "", depth
        
        if len(encoded_str) > self.MAX_DECODE_SIZE:
            return "", depth
        
        decoded = None
        
        try:
            if encoding_type == 'base64':
                decoded = self._decode_base64(encoded_str)
            elif encoding_type == 'hex':
                decoded = self._decode_hex(encoded_str)
            elif encoding_type == 'url_encoded':
                decoded = self._decode_url(encoded_str)
        except Exception:
            return "", depth
        
        if not decoded:
            return "", depth
        
        # Check if decoded content is itself encoded
        for enc_type, pattern in self.encoding_patterns.items():
            if re.search(pattern, decoded):
                # Recursive decode
                further_decoded, further_depth = self._safe_decode(
                    decoded, enc_type, depth + 1
                )
                if further_decoded:
                    return further_decoded, further_depth + 1
        
        return decoded, depth
    
    def _decode_base64(self, encoded: str) -> str:
        """Decode base64 string."""
        try:
            # Remove whitespace
            cleaned = re.sub(r'\s', '', encoded)
            
            # Add padding if needed
            missing_padding = len(cleaned) % 4
            if missing_padding:
                cleaned += '=' * (4 - missing_padding)
            
            decoded_bytes = base64.b64decode(cleaned, validate=True)
            
            # Try to decode as UTF-8
            return decoded_bytes.decode('utf-8', errors='ignore')
        except Exception:
            return ""
    
    def _decode_hex(self, encoded: str) -> str:
        """Decode hexadecimal string."""
        try:
            # Remove common prefixes
            cleaned = encoded.replace('0x', '').replace('\\x', '')
            
            # Ensure even length
            if len(cleaned) % 2 != 0:
                return ""
            
            decoded_bytes = bytes.fromhex(cleaned)
            return decoded_bytes.decode('utf-8', errors='ignore')
        except Exception:
            return ""
    
    def _decode_url(self, encoded: str) -> str:
        """Decode URL-encoded string."""
        try:
            decoded = unquote_plus(encoded)
            # URL decoding might need multiple passes
            if '%' in decoded:
                decoded = unquote_plus(decoded)
            return decoded
        except Exception:
            return ""
    
    def _check_decoded_content(self, content: str) -> Tuple[bool, List[str]]:
        """Check if decoded content contains suspicious patterns."""
        
        suspicious_patterns = [
            (r'ignore\s+(previous|prior|above)\s+(instructions|commands)', 'instruction_override'),
            (r'system\s*:\s*', 'system_prompt'),
            (r'execute\s+(code|command|script)', 'code_execution'),
            (r'send\s+to\s+https?://', 'data_exfiltration'),
            (r'bypass\s+(security|filter|check)', 'security_bypass'),
            (r'<script[^>]*>', 'script_injection'),
            (r'eval\s*\(', 'eval_usage'),
            (r'subprocess|os\.system|exec\(', 'dangerous_code'),
        ]
        
        found_patterns = []
        content_lower = content.lower()
        
        for pattern, label in suspicious_patterns:
            if re.search(pattern, content_lower):
                found_patterns.append(label)
        
        return len(found_patterns) > 0, found_patterns
    
    def _calculate_encoding_risk(
        self,
        enc_type: str,
        recursion_depth: int,
        is_suspicious: bool,
        num_suspicious: int
    ) -> float:
        """Calculate risk score for encoded content."""
        
        # Base risk by encoding type
        base_risks = {
            'base64': 0.4,
            'hex': 0.5,
            'url_encoded': 0.3,
        }
        
        risk = base_risks.get(enc_type, 0.3)
        
        # Increase risk for nested encoding
        risk += recursion_depth * 0.2
        
        # Significant increase for suspicious content
        if is_suspicious:
            risk += 0.4 + (num_suspicious * 0.1)
        
        return min(1.0, risk)
    
    def _risk_to_severity(self, risk: float) -> str:
        """Convert risk score to severity."""
        if risk >= 0.8:
            return "critical"
        elif risk >= 0.6:
            return "high"
        elif risk >= 0.4:
            return "medium"
        else:
            return "low"
    
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
    
    def _generate_details(
        self,
        findings: List[Dict],
        encoding_detected: Dict[str, List[str]],
        max_risk: float
    ) -> str:
        """Generate human-readable summary."""
        
        parts = [
            f"Detected {len(encoding_detected)} encoding type(s): {', '.join(encoding_detected.keys())}",
            f"Decoded {len(findings)} encoded segment(s)",
            f"Maximum risk score: {max_risk:.2f}"
        ]
        
        suspicious_count = sum(
            1 for f in findings 
            if f.get('type') == 'decoded_content' and f.get('suspicious_patterns')
        )
        
        if suspicious_count > 0:
            parts.append(f"{suspicious_count} decoded segment(s) contain suspicious patterns")
        
        return ". ".join(parts) + "."