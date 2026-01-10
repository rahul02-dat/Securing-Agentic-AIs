"""
OCR-based content analyzer for extracting text from images.
Multimodal safety layer to detect hidden instructions in images.
"""

import re
from typing import List, Dict, Optional
from pathlib import Path
from gateway.shared.schemas import AnalysisResult, RiskLevel

# Try to import OCR library
try:
    from PIL import Image
    import pytesseract
    HAS_OCR = True
except ImportError:
    HAS_OCR = False


class OCRContentAnalyzer:
    """Extracts and analyzes text from images using OCR."""
    
    SUPPORTED_IMAGE_FORMATS = {'.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff', '.webp'}
    BASELINE_OCR_RISK = 0.25  # Images get non-zero baseline risk
    
    def __init__(self):
        self.ocr_available = HAS_OCR
        
        if HAS_OCR:
            # Test if tesseract is installed
            try:
                pytesseract.get_tesseract_version()
            except Exception:
                self.ocr_available = False
    
    def can_process(self, file_path: str) -> bool:
        """Check if file can be processed by OCR."""
        suffix = Path(file_path).suffix.lower()
        return suffix in self.SUPPORTED_IMAGE_FORMATS
    
    def extract_text_from_image(self, image_path: str) -> Optional[str]:
        """Extract text from image file using OCR."""
        
        if not self.ocr_available:
            return None
        
        try:
            image = Image.open(image_path)
            
            # Perform OCR
            text = pytesseract.image_to_string(image, lang='eng')
            
            return text.strip() if text else None
            
        except Exception as e:
            print(f"OCR extraction failed for {image_path}: {e}")
            return None
    
    def analyze(self, extracted_text: str, image_source: str = "unknown") -> AnalysisResult:
        """Analyze OCR-extracted text for threats."""
        
        if not extracted_text:
            return AnalysisResult(
                module_name="ocr_content_analyzer",
                risk_level=RiskLevel.LOW,
                confidence=0.8,
                findings=[{
                    "type": "empty_ocr",
                    "severity": "low",
                    "description": "No text extracted from image"
                }],
                details="Image processed but no text extracted.",
                risk_score=self.BASELINE_OCR_RISK
            )
        
        findings = []
        risk_scores = []
        
        # Always assign baseline risk to OCR content
        risk_scores.append(self.BASELINE_OCR_RISK)
        
        findings.append({
            "type": "ocr_extraction",
            "source": image_source,
            "text_length": len(extracted_text),
            "severity": "medium",
            "description": f"Text extracted from image (length: {len(extracted_text)})"
        })
        
        # Check for instruction patterns
        instruction_findings = self._detect_instructions(extracted_text)
        if instruction_findings:
            findings.extend(instruction_findings)
            risk_scores.append(0.7)
        
        # Check for encoding patterns
        encoding_findings = self._detect_encoding(extracted_text)
        if encoding_findings:
            findings.extend(encoding_findings)
            risk_scores.append(0.6)
        
        # Check for URLs
        url_findings = self._detect_urls(extracted_text)
        if url_findings:
            findings.extend(url_findings)
            risk_scores.append(0.5)
        
        # Check for suspicious keywords
        keyword_findings = self._detect_suspicious_keywords(extracted_text)
        if keyword_findings:
            findings.extend(keyword_findings)
            risk_scores.append(0.65)
        
        max_risk = max(risk_scores) if risk_scores else self.BASELINE_OCR_RISK
        risk_level = self._calculate_risk_level(max_risk)
        
        details = self._generate_details(findings, extracted_text, max_risk)
        
        return AnalysisResult(
            module_name="ocr_content_analyzer",
            risk_level=risk_level,
            confidence=0.85,
            findings=findings,
            details=details,
            risk_score=max_risk
        )
    
    def _detect_instructions(self, text: str) -> List[Dict]:
        """Detect instructional patterns in OCR text."""
        findings = []
        text_lower = text.lower()
        
        instruction_patterns = [
            (r'\bignore\s+(previous|prior|above)', 'instruction_override'),
            (r'\bexecute\s+(this|the|code|command)', 'code_execution'),
            (r'\bsend\s+(to|this)\s+\w+', 'data_transmission'),
            (r'\byou\s+(are|must|should|will)\s+now', 'role_change'),
            (r'\bsystem\s*:\s*', 'system_injection'),
        ]
        
        for pattern, label in instruction_patterns:
            matches = re.findall(pattern, text_lower)
            if matches:
                findings.append({
                    "type": "ocr_instruction",
                    "pattern": label,
                    "matches": len(matches),
                    "severity": "high",
                    "description": f"Instructional pattern '{label}' found in image text"
                })
        
        return findings
    
    def _detect_encoding(self, text: str) -> List[Dict]:
        """Detect encoded content in OCR text."""
        findings = []
        
        # Base64-like patterns
        base64_pattern = r'[A-Za-z0-9+/]{20,}={0,2}'
        base64_matches = re.findall(base64_pattern, text)
        
        if len(base64_matches) > 2:
            findings.append({
                "type": "ocr_encoding",
                "encoding": "base64",
                "count": len(base64_matches),
                "severity": "medium",
                "description": f"Potential base64 encoding detected in image ({len(base64_matches)} instances)"
            })
        
        # Hex patterns
        hex_pattern = r'(?:0x|\\x)?[0-9a-fA-F]{16,}'
        hex_matches = re.findall(hex_pattern, text)
        
        if len(hex_matches) > 1:
            findings.append({
                "type": "ocr_encoding",
                "encoding": "hexadecimal",
                "count": len(hex_matches),
                "severity": "medium",
                "description": f"Hexadecimal encoding detected in image ({len(hex_matches)} instances)"
            })
        
        return findings
    
    def _detect_urls(self, text: str) -> List[Dict]:
        """Detect URLs in OCR text."""
        findings = []
        
        url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
        urls = re.findall(url_pattern, text)
        
        if urls:
            findings.append({
                "type": "ocr_url",
                "count": len(urls),
                "urls": urls[:3],  # Store first 3
                "severity": "medium",
                "description": f"{len(urls)} URL(s) found in image text"
            })
        
        return findings
    
    def _detect_suspicious_keywords(self, text: str) -> List[Dict]:
        """Detect suspicious keywords in OCR text."""
        findings = []
        text_lower = text.lower()
        
        suspicious_keywords = [
            'bypass', 'override', 'jailbreak', 'admin mode', 
            'developer mode', 'unrestricted', 'webhook', 
            'exfiltrate', 'leak data', 'backdoor'
        ]
        
        found_keywords = []
        for keyword in suspicious_keywords:
            if keyword in text_lower:
                found_keywords.append(keyword)
        
        if found_keywords:
            findings.append({
                "type": "ocr_suspicious_keywords",
                "keywords": found_keywords,
                "count": len(found_keywords),
                "severity": "high",
                "description": f"Suspicious keywords in image: {', '.join(found_keywords[:5])}"
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
    
    def _generate_details(
        self,
        findings: List[Dict],
        extracted_text: str,
        max_risk: float
    ) -> str:
        """Generate human-readable summary."""
        
        parts = [
            f"OCR extracted {len(extracted_text)} characters from image",
            f"Risk score: {max_risk:.2f} (baseline: {self.BASELINE_OCR_RISK})"
        ]
        
        threat_findings = [
            f for f in findings 
            if f.get('type') in ['ocr_instruction', 'ocr_suspicious_keywords']
        ]
        
        if threat_findings:
            parts.append(f"{len(threat_findings)} threat indicator(s) detected in image text")
        
        encoding_findings = [f for f in findings if f.get('type') == 'ocr_encoding']
        if encoding_findings:
            parts.append("Encoded content detected in image")
        
        return ". ".join(parts) + "."