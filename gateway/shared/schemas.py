from dataclasses import dataclass, field
from typing import List, Dict, Optional, Union
from datetime import datetime
from enum import Enum
from abc import ABC


class RiskLevel(Enum):
    SAFE = "safe"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ContentChannel(Enum):
    """Channel through which content was detected."""
    VISIBLE = "visible"
    HIDDEN = "hidden"
    METADATA = "metadata"
    ENCODED = "encoded"
    OCR = "ocr"
    CSS_HIDDEN = "css_hidden"
    HTML_COMMENT = "html_comment"
    SCRIPT = "script"
    IFRAME = "iframe"
    ATTRIBUTE = "attribute"


class SecurityDecision(Enum):
    ALLOW = "allow"
    SANITIZE = "sanitize"
    BLOCK = "block"
    REQUIRE_APPROVAL = "require_approval"


class ContentIntent(Enum):
    DESCRIPTIVE = "descriptive"
    INSTRUCTIONAL = "instructional"
    CONDITIONAL_INSTRUCTIONAL = "conditional_instructional"
    AMBIGUOUS = "ambiguous"
    MALICIOUS = "malicious"


@dataclass
class LocationReference:
    """Precise location information for detected content."""
    channel: ContentChannel
    line_number: Optional[int] = None
    offset: Optional[int] = None
    tag_name: Optional[str] = None
    tag_id: Optional[str] = None
    tag_class: Optional[str] = None
    attribute_name: Optional[str] = None
    page_number: Optional[int] = None
    bbox: Optional[Dict[str, float]] = None  # {x, y, w, h} for OCR
    css_style: Optional[str] = None
    parent_tag: Optional[str] = None
    context_before: Optional[str] = None
    context_after: Optional[str] = None
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization."""
        result = {
            "channel": self.channel.value,
        }
        if self.line_number is not None:
            result["line_number"] = self.line_number
        if self.offset is not None:
            result["offset"] = self.offset
        if self.tag_name is not None:
            result["tag_name"] = self.tag_name
        if self.tag_id is not None:
            result["tag_id"] = self.tag_id
        if self.tag_class is not None:
            result["tag_class"] = self.tag_class
        if self.attribute_name is not None:
            result["attribute_name"] = self.attribute_name
        if self.page_number is not None:
            result["page_number"] = self.page_number
        if self.bbox is not None:
            result["bbox"] = self.bbox
        if self.css_style is not None:
            result["css_style"] = self.css_style
        if self.parent_tag is not None:
            result["parent_tag"] = self.parent_tag
        if self.context_before is not None:
            result["context_before"] = self.context_before
        if self.context_after is not None:
            result["context_after"] = self.context_after
        return result


@dataclass
class InjectionFinding:
    """Detailed finding about a prompt injection."""
    type: str
    detector: str
    severity: str
    risk_score: float
    description: str
    pattern: Optional[str] = None
    matched_text: Optional[str] = None
    locations: List[LocationReference] = field(default_factory=list)
    reasoning: Optional[str] = None
    encoding_trace: Optional[List[str]] = None  # trace of encoding layers
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "type": self.type,
            "detector": self.detector,
            "severity": self.severity,
            "risk_score": self.risk_score,
            "description": self.description,
            "pattern": self.pattern,
            "matched_text": self.matched_text,
            "locations": [loc.to_dict() for loc in self.locations],
            "reasoning": self.reasoning,
            "encoding_trace": self.encoding_trace,
        }


@dataclass
class ContentBlock:
    """Represents extracted content with metadata."""
    content: str
    content_type: str
    visibility: str
    source_location: Optional[str] = None


@dataclass
class AnalysisResult:
    """Results from security analysis modules."""
    module_name: str
    risk_level: RiskLevel
    confidence: float
    findings: List[Dict]
    details: str
    risk_score: float = 0.0
    detected_intent: Optional[ContentIntent] = None


@dataclass
class SecurityAssessment:
    """Complete security assessment of input."""
    input_id: str
    timestamp: datetime
    input_type: str
    source: str
    content_blocks: List[ContentBlock]
    analysis_results: List[AnalysisResult]
    overall_risk: RiskLevel
    risk_score: float
    decision: SecurityDecision
    restricted_capabilities: List[str]
    sanitized_content: Optional[str]
    reasoning: str
    agentic_intent_detected: bool = False
    requested_actions: List[str] = field(default_factory=list)
    primary_intent: ContentIntent = ContentIntent.DESCRIPTIVE
    intent_confidence: float = 0.0


@dataclass
class AgentRestrictions:
    """Defines what capabilities an agent can use."""
    mode: str = "NORMAL"
    allow_web_access: bool = True
    allow_file_write: bool = True
    allow_code_execution: bool = True
    allow_tool_use: bool = True
    max_output_length: Optional[int] = None
    allowed_domains: List[str] = field(default_factory=list)
    blocked_patterns: List[str] = field(default_factory=list)
    requires_approval: bool = False
    approval_reason: str = ""


@dataclass
class SecurityEvent:
    """Structured log entry for security events."""
    event_id: str
    timestamp: str
    event_type: str
    severity: str
    input_source: str
    risk_level: str
    decision: str
    findings: List[Dict]
    metadata: Dict