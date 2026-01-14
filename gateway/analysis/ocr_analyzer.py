"""
OCR-based content analyzer for extracting text from images with location tracking.
Multimodal safety layer to detect hidden instructions in images with precise bounding boxes.
"""

import re
from typing import List, Dict, Optional, Tuple
from pathlib import Path
from gateway.shared.schemas import (
    AnalysisResult, RiskLevel, ContentChannel, InjectionFinding, LocationReference
)
from gateway.shared.location_tracker import LocationTracker

# Try to import OCR library
try:
    from PIL import Image
    import pytesseract
    HAS_OCR = True
except ImportError:
    HAS_OCR = False


class OCRContentAnalyzer:
    """Extracts and analyzes text from images using OCR with location tracking."""
    
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
    
    def extract_text_with_boxes(self, image_path: str) -> Optional[Dict]:
        """
        Extract text and bounding boxes from image using OCR.
        
        Returns:
            Dict with text, boxes, and confidence scores
        """
        if not self.ocr_available:
            return None
        
        try:
            image = Image.open(image_path)
            
            # Get detailed OCR results with bounding boxes
            data = pytesseract.image_to_data(image, output_type=pytesseract.Output.DICT)
            
            return {
                "text": data.get('text', []),
                "left": data.get('left', []),
                "top": data.get('top', []),
                "width": data.get('width', []),
                "height": data.get('height', []),
                "conf": data.get('conf', []),
            }
            
        except Exception as e:
            print(f"OCR extraction with boxes failed for {image_path}: {e}")
            return None
    
    def analyze(self, extracted_text: str, image_source: str = "unknown",
                ocr_data: Optional[Dict] = None) -> AnalysisResult:
        """
        Analyze OCR-extracted text for threats with location tracking.
        
        Args:
            extracted_text: Text extracted from image
            image_source: Source image file path
            ocr_data: Optional OCR data with bounding boxes
            
        Returns:
            AnalysisResult with localized findings
        """
        
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
        
        # Detect instruction patterns with locations
        instruction_findings, instruction_risks = self._detect_instructions_with_location(
            extracted_text, ocr_data
        )
        findings.extend(instruction_findings)
        risk_scores.extend(instruction_risks)
        
        # Detect encoding patterns with locations
        encoding_findings, encoding_risks = self._detect_encoding_with_location(
            extracted_text, ocr_data
        )
        findings.extend(encoding_findings)
        risk_scores.extend(encoding_risks)
        
        # Detect URLs with locations
        url_findings, url_risks = self._detect_urls_with_location(
            extracted_text, ocr_data
        )
        findings.extend(url_findings)
        risk_scores.extend(url_risks)
        
        # Detect suspicious keywords with locations
        keyword_findings, keyword_risks = self._detect_suspicious_keywords_with_location(
            extracted_text, ocr_data
        )
        findings.extend(keyword_findings)
        risk_scores.extend(keyword_risks)
        
        max_risk = max(risk_scores) if risk_scores else self.BASELINE_OCR_RISK
        risk_level = self._calculate_risk_level(max_risk)
        
        # Convert to dicts for serialization
        findings_dicts = [f.to_dict() if isinstance(f, InjectionFinding) else f for f in findings]
        
        details = self._generate_details(findings, extracted_text, max_risk)
        
        return AnalysisResult(
            module_name="ocr_content_analyzer",
            risk_level=risk_level,
            confidence=0.85,
            findings=findings_dicts,
            details=details,
            risk_score=max_risk
        )
    
    def _detect_instructions_with_location(
        self, text: str, ocr_data: Optional[Dict] = None
    ) -> Tuple[List[InjectionFinding], List[float]]:
        """Detect instructional patterns in OCR text with bounding box locations."""
        findings = []
        risks = []
        text_lower = text.lower()
        
        instruction_patterns = [
            (r'\bignore\s+(previous|prior|above)', 'instruction_override', 0.8),
            (r'\bexecute\s+(this|the|code|command)', 'code_execution', 0.85),
            (r'\bsend\s+(to|this)\s+\w+', 'data_transmission', 0.7),
            (r'\byou\s+(are|must|should|will)\s+now', 'role_change', 0.75),
            (r'\bsystem\s*:\s*', 'system_injection', 0.65),
        ]
        
        for pattern, label, risk_score in instruction_patterns:
            matches = list(re.finditer(pattern, text_lower, re.IGNORECASE))
            for match in matches:
                matched_text = text[match.start():match.end()]
                
                # Create location with bbox if available
                location = self._get_location_from_ocr(
                    text, match.start(), match.end(), ocr_data, ContentChannel.OCR
                )
                
                finding = InjectionFinding(
                    type="ocr_instruction",
                    detector="ocr_instruction_detector",
                    severity="high",
                    risk_score=risk_score,
                    pattern=pattern,
                    matched_text=matched_text,
                    description=f"OCR: Instructional pattern '{label}' in image text",
                    locations=[location],
                    reasoning="Image contains text attempting to override instructions"
                )
                findings.append(finding)
                risks.append(risk_score)
        
        return findings, risks
    
    def _detect_encoding_with_location(
        self, text: str, ocr_data: Optional[Dict] = None
    ) -> Tuple[List[InjectionFinding], List[float]]:
        """Detect encoded content in OCR text with locations."""
        findings = []
        risks = []
        
        # Base64-like patterns
        base64_pattern = r'[A-Za-z0-9+/]{20,}={0,2}'
        base64_matches = list(re.finditer(base64_pattern, text))
        
        if len(base64_matches) > 2:
            # Create location for first match
            match = base64_matches[0]
            location = self._get_location_from_ocr(
                text, match.start(), match.end(), ocr_data, ContentChannel.OCR
            )
            
            finding = InjectionFinding(
                type="ocr_encoding",
                detector="encoding_detector",
                severity="medium",
                risk_score=0.6,
                pattern=base64_pattern,
                matched_text=match.group(0),
                description=f"Base64 encoding detected in image ({len(base64_matches)} instances)",
                locations=[location],
                reasoning="Encoded content may hide malicious payload",
                encoding_trace=["base64"]
            )
            findings.append(finding)
            risks.append(0.6)
        
        # Hex patterns
        hex_pattern = r'(?:0x|\\x)?[0-9a-fA-F]{16,}'
        hex_matches = list(re.finditer(hex_pattern, text))
        
        if len(hex_matches) > 1:
            match = hex_matches[0]
            location = self._get_location_from_ocr(
                text, match.start(), match.end(), ocr_data, ContentChannel.OCR
            )
            
            finding = InjectionFinding(
                type="ocr_encoding",
                detector="encoding_detector",
                severity="medium",
                risk_score=0.55,
                pattern=hex_pattern,
                matched_text=match.group(0),
                description=f"Hexadecimal encoding detected in image ({len(hex_matches)} instances)",
                locations=[location],
                reasoning="Hex encoding may hide binary or ASCII payloads",
                encoding_trace=["hexadecimal"]
            )
            findings.append(finding)
            risks.append(0.55)
        
        return findings, risks
    
    def _detect_urls_with_location(
        self, text: str, ocr_data: Optional[Dict] = None
    ) -> Tuple[List[InjectionFinding], List[float]]:
        """Detect URLs in OCR text with locations."""
        findings = []
        risks = []
        
        url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
        url_matches = list(re.finditer(url_pattern, text))
        
        if url_matches:
            for match in url_matches[:3]:  # Track first 3
                location = self._get_location_from_ocr(
                    text, match.start(), match.end(), ocr_data, ContentChannel.OCR
                )
                
                finding = InjectionFinding(
                    type="ocr_url",
                    detector="url_detector",
                    severity="medium",
                    risk_score=0.5,
                    matched_text=match.group(0),
                    description=f"URL found in image text",
                    locations=[location],
                    reasoning="URL in image may lead to malicious payload"
                )
                findings.append(finding)
                risks.append(0.5)
        
        return findings, risks
    
    def _detect_suspicious_keywords_with_location(
        self, text: str, ocr_data: Optional[Dict] = None
    ) -> Tuple[List[InjectionFinding], List[float]]:
        """Detect suspicious keywords in OCR text with locations."""
        findings = []
        risks = []
        text_lower = text.lower()
        
        suspicious_keywords = [
            'bypass', 'override', 'jailbreak', 'admin mode',
            'developer mode', 'unrestricted', 'webhook',
            'exfiltrate', 'leak data', 'backdoor'
        ]
        
        for keyword in suspicious_keywords:
            matches = list(re.finditer(re.escape(keyword), text_lower, re.IGNORECASE))
            for match in matches:
                matched_text = text[match.start():match.end()]
                location = self._get_location_from_ocr(
                    text, match.start(), match.end(), ocr_data, ContentChannel.OCR
                )
                
                finding = InjectionFinding(
                    type="ocr_suspicious_keyword",
                    detector="keyword_detector",
                    severity="high",
                    risk_score=0.65,
                    matched_text=matched_text,
                    description=f"Suspicious keyword in image: '{keyword}'",
                    locations=[location],
                    reasoning="Keywords indicate malicious intent in image content"
                )
                findings.append(finding)
                risks.append(0.65)
        
        return findings, risks
    
    def _get_location_from_ocr(
        self,
        text: str,
        start: int,
        end: int,
        ocr_data: Optional[Dict],
        channel: ContentChannel
    ) -> LocationReference:
        """
        Create location reference from OCR data or text position.
        Includes bounding box if available.
        """
        
        # Get basic text location
        location = LocationTracker.track_text_location(
            text, start, end, channel, context_chars=40
        )
        
        # Try to match bounding box from OCR data
        if ocr_data and "text" in ocr_data:
            ocr_texts = ocr_data.get("text", [])
            char_count = 0
            
            for i, ocr_text in enumerate(ocr_texts):
                text_len = len(ocr_text)
                if char_count <= start < char_count + text_len:
                    # Found the bounding box for this text
                    bbox = {
                        "x": ocr_data["left"][i],
                        "y": ocr_data["top"][i],
                        "width": ocr_data["width"][i],
                        "height": ocr_data["height"][i],
                        "confidence": float(ocr_data["conf"][i]) / 100.0
                    }
                    location.bbox = bbox
                    break
                char_count += text_len + 1  # +1 for space separator
        
        location.channel = channel
        return location
    
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
        findings: List,
        extracted_text: str,
        max_risk: float
    ) -> str:
        """Generate human-readable summary."""
        
        parts = [
            f"OCR extracted {len(extracted_text)} characters from image",
            f"Risk score: {max_risk:.2f} (baseline: {self.BASELINE_OCR_RISK})"
        ]
        
        threat_types = set()
        for finding in findings:
            if isinstance(finding, dict):
                threat_type = finding.get("type")
            else:
                threat_type = finding.type
            
            if threat_type in ['ocr_instruction', 'ocr_suspicious_keyword', 'ocr_encoding']:
                threat_types.add(threat_type)
        
        if threat_types:
            parts.append(f"{len(threat_types)} threat indicator(s) detected in image text")
        
        return ". ".join(parts) + "."
