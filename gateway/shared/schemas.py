from dataclasses import dataclass, field
from typing import List, Dict, Optional
from datetime import datetime
from enum import Enum


class RiskLevel(Enum):
    SAFE = "safe"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class SecurityDecision(Enum):
    ALLOW = "allow"
    SANITIZE = "sanitize"
    BLOCK = "block"
    REQUIRE_APPROVAL = "require_approval"


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