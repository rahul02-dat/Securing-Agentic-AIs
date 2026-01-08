import re
from typing import List, Dict, Tuple
from gateway.shared.schemas import AnalysisResult, RiskLevel


class AgenticIntentDetector:
    """Detects requests for autonomous actions and agentic behavior."""
    
    def __init__(self):
        self.action_patterns = [
            (r'\bsend\s+(an?\s+)?(email|message|notification|alert)', 'send_email', 0.9),
            (r'\bwrite\s+(to\s+)?(file|disk|storage)', 'write_file', 0.85),
            (r'\bexecute\s+(this\s+)?(code|command|script|program)', 'execute_code', 0.95),
            (r'\bcall\s+(the\s+|an?\s+)?(api|endpoint|service|function)', 'call_api', 0.85),
            (r'\bmake\s+(an?\s+)?(http|web|api)\s+(request|call)', 'http_request', 0.85),
            (r'\bdelete\s+(the\s+)?(file|data|record)', 'delete_data', 0.9),
            (r'\bmodify\s+(the\s+)?(file|database|system)', 'modify_system', 0.85),
            (r'\brun\s+(this\s+)?(command|script|program|code)', 'execute_code', 0.9),
            (r'\binstall\s+(package|library|software|dependency)', 'install_package', 0.85),
            (r'\bpost\s+to\s+(slack|discord|webhook|api)', 'post_to_service', 0.9),
            (r'\bupload\s+(file|data|content)', 'upload_data', 0.85),
            (r'\bdownload\s+(from|file|content)', 'download_data', 0.75),
            (r'\bcreate\s+(new\s+)?(file|folder|directory|database)', 'create_file', 0.8),
            (r'\bconnect\s+to\s+(database|server|api|service)', 'connect_service', 0.8),
            (r'\bquery\s+(the\s+)?(database|db|sql)', 'query_database', 0.75),
            (r'\bschedule\s+(task|job|cron)', 'schedule_task', 0.85),
            (r'\btrigger\s+(webhook|event|notification)', 'trigger_event', 0.85),
        ]
        
        self.tool_access_patterns = [
            r'\btool\s+access\b',
            r'\buse\s+(the\s+)?(tool|function|plugin)',
            r'\bwith\s+tool\s+(access|capability|permission)',
            r'\bif\s+you\s+(have|can\s+use)\s+tool',
            r'\benable\s+tool\s+(mode|access)',
            r'\bactivate\s+(tool|plugin|function)',
        ]
        
        self.autonomy_patterns = [
            r'\bwithout\s+(asking|permission|confirmation|approval)',
            r'\bdon\'?t\s+(ask|confirm|wait)',
            r'\bno\s+need\s+to\s+(ask|confirm)',
            r'\bautomatic(ally)?',
            r'\bautonomous(ly)?',
            r'\bon\s+your\s+own',
            r'\bindependent(ly)?',
            r'\bjust\s+do\s+it',
            r'\bsilently',
            r'\bin\s+the\s+background',
            r'\bwithout\s+telling',
        ]
        
        self.permission_bypass_patterns = [
            r'\bskip\s+(the\s+)?(confirmation|approval|permission)',
            r'\bbypass\s+(the\s+)?(check|confirmation|approval)',
            r'\bignore\s+(the\s+)?(warning|prompt|confirmation)',
            r'\bsuppress\s+(the\s+)?(prompt|confirmation|dialog)',
            r'\bno\s+(user\s+)?(confirmation|approval|permission)\s+needed',
        ]
    
    def analyze(self, visible_text: str, hidden_elements: List[str]) -> AnalysisResult:
        """Detect agentic intent and autonomous action requests."""
        
        findings = []
        detected_actions = []
        max_risk = 0.0
        
        all_content = visible_text + ' ' + ' '.join(hidden_elements)
        all_content_lower = all_content.lower()
        
        action_findings, action_list, action_risk = self._detect_action_requests(all_content_lower)
        if action_findings:
            findings.extend(action_findings)
            detected_actions.extend(action_list)
            max_risk = max(max_risk, action_risk)
        
        tool_findings = self._detect_tool_access(all_content_lower)
        if tool_findings:
            findings.extend(tool_findings)
            max_risk = max(max_risk, 0.7)
        
        autonomy_findings = self._detect_autonomy_requests(all_content_lower)
        if autonomy_findings:
            findings.extend(autonomy_findings)
            max_risk = max(max_risk, 0.85)
        
        bypass_findings = self._detect_permission_bypass(all_content_lower)
        if bypass_findings:
            findings.extend(bypass_findings)
            max_risk = max(max_risk, 0.95)
        
        combined_risk = self._calculate_combined_risk(
            has_actions=bool(action_findings),
            has_tool_access=bool(tool_findings),
            has_autonomy=bool(autonomy_findings),
            has_bypass=bool(bypass_findings),
            base_risk=max_risk
        )
        
        agentic_intent = bool(findings)
        risk_level = self._calculate_risk_level(combined_risk)
        
        if not findings:
            return AnalysisResult(
                module_name="agentic_intent_detector",
                risk_level=RiskLevel.SAFE,
                confidence=0.9,
                findings=[],
                details="No agentic intent detected.",
                risk_score=0.0
            )
        
        details = self._generate_details(agentic_intent, detected_actions, findings)
        
        return AnalysisResult(
            module_name="agentic_intent_detector",
            risk_level=risk_level,
            confidence=min(0.95, combined_risk + 0.1),
            findings=findings,
            details=details,
            risk_score=combined_risk
        )
    
    def _detect_action_requests(self, text: str) -> Tuple[List[Dict], List[str], float]:
        """Detect explicit action requests."""
        findings = []
        actions = []
        max_risk = 0.0
        
        for pattern, action_type, risk_score in self.action_patterns:
            matches = list(re.finditer(pattern, text, re.IGNORECASE))
            if matches:
                actions.append(action_type)
                max_risk = max(max_risk, risk_score)
                
                for match in matches:
                    findings.append({
                        "type": "action_request",
                        "action": action_type,
                        "pattern": pattern,
                        "matched_text": match.group(0),
                        "severity": "critical" if risk_score >= 0.9 else "high",
                        "risk_score": risk_score,
                        "description": f"Request to perform action: {action_type}"
                    })
        
        return findings, list(set(actions)), max_risk
    
    def _detect_tool_access(self, text: str) -> List[Dict]:
        """Detect mentions of tool access or capabilities."""
        findings = []
        
        for pattern in self.tool_access_patterns:
            matches = list(re.finditer(pattern, text, re.IGNORECASE))
            if matches:
                for match in matches:
                    findings.append({
                        "type": "tool_access_mention",
                        "matched_text": match.group(0),
                        "severity": "medium",
                        "description": "Mentions tool access or capabilities"
                    })
        
        return findings
    
    def _detect_autonomy_requests(self, text: str) -> List[Dict]:
        """Detect requests for autonomous behavior."""
        findings = []
        
        for pattern in self.autonomy_patterns:
            matches = list(re.finditer(pattern, text, re.IGNORECASE))
            if matches:
                for match in matches:
                    findings.append({
                        "type": "autonomy_request",
                        "matched_text": match.group(0),
                        "severity": "high",
                        "description": "Requests autonomous behavior without user interaction"
                    })
        
        return findings
    
    def _detect_permission_bypass(self, text: str) -> List[Dict]:
        """Detect attempts to bypass user permission checks."""
        findings = []
        
        for pattern in self.permission_bypass_patterns:
            matches = list(re.finditer(pattern, text, re.IGNORECASE))
            if matches:
                for match in matches:
                    findings.append({
                        "type": "permission_bypass",
                        "matched_text": match.group(0),
                        "severity": "critical",
                        "description": "Attempts to bypass user permission or confirmation"
                    })
        
        return findings
    
    def _calculate_combined_risk(
        self,
        has_actions: bool,
        has_tool_access: bool,
        has_autonomy: bool,
        has_bypass: bool,
        base_risk: float
    ) -> float:
        """Calculate cumulative risk score based on detected patterns."""
        
        risk = base_risk
        
        if has_actions:
            risk += 0.3
        
        if has_tool_access:
            risk += 0.2
        
        if has_autonomy:
            risk += 0.25
        
        if has_bypass:
            risk += 0.35
        
        if has_actions and has_autonomy:
            risk += 0.15
        
        if has_actions and has_bypass:
            risk += 0.2
        
        if has_tool_access and has_autonomy:
            risk += 0.1
        
        return min(1.0, risk)
    
    def _calculate_risk_level(self, score: float) -> RiskLevel:
        """Convert numeric risk score to RiskLevel enum."""
        if score >= 0.85:
            return RiskLevel.CRITICAL
        elif score >= 0.65:
            return RiskLevel.HIGH
        elif score >= 0.4:
            return RiskLevel.MEDIUM
        elif score >= 0.15:
            return RiskLevel.LOW
        else:
            return RiskLevel.SAFE
    
    def _generate_details(
        self,
        agentic_intent: bool,
        actions: List[str],
        findings: List[Dict]
    ) -> str:
        """Generate human-readable summary of findings."""
        
        if not agentic_intent:
            return "No agentic intent detected."
        
        parts = [
            f"Agentic intent detected with {len(findings)} indicators.",
        ]
        
        if actions:
            parts.append(f"Requested actions: {', '.join(actions)}")
        
        critical_count = sum(1 for f in findings if f.get('severity') == 'critical')
        high_count = sum(1 for f in findings if f.get('severity') == 'high')
        
        if critical_count > 0:
            parts.append(f"{critical_count} critical threat(s)")
        if high_count > 0:
            parts.append(f"{high_count} high-risk indicator(s)")
        
        return ". ".join(parts) + "."