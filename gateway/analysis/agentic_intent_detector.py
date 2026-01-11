import re
from typing import List, Dict, Tuple
from gateway.shared.schemas import AnalysisResult, RiskLevel


class AgenticIntentDetector:
    
    def __init__(self):
        self.action_patterns = [
            (r'\bsend\s+(an?\s+)?(email|message|notification|alert)', 'send_email', 0.85),
            (r'\bwrite\s+(to\s+)?(file|disk|storage)', 'write_file', 0.8),
            (r'\bexecute\s+(this\s+)?(code|command|script|program)', 'execute_code', 0.9),
            (r'\bcall\s+(the\s+|an?\s+)?(api|endpoint|service|function)', 'call_api', 0.75),
            (r'\bmake\s+(an?\s+)?(http|web|api)\s+(request|call)', 'http_request', 0.75),
            (r'\bdelete\s+(the\s+)?(file|data|record)', 'delete_data', 0.85),
            (r'\bmodify\s+(the\s+)?(file|database|system)', 'modify_system', 0.8),
            (r'\brun\s+(this\s+)?(command|script|program|code)', 'execute_code', 0.85),
            (r'\binstall\s+(package|library|software|dependency)', 'install_package', 0.8),
            (r'\bpost\s+to\s+(slack|discord|webhook|api)', 'post_to_service', 0.85),
            (r'\bupload\s+(file|data|content)', 'upload_data', 0.75),
            (r'\bcreate\s+(new\s+)?(file|folder|directory|database)', 'create_file', 0.7),
            (r'\bconnect\s+to\s+(database|server|api|service)', 'connect_service', 0.7),
            (r'\bquery\s+(the\s+)?(database|db|sql)', 'query_database', 0.65),
            (r'\btrigger\s+(webhook|event|notification)', 'trigger_event', 0.8),
            (r'\bfetch\s+(from|data\s+from)\s+https?://', 'fetch_url', 0.75),
        ]
        
        self.autonomy_patterns = [
            (r'\bwithout\s+(asking|permission|confirmation|approval|telling)', 0.85),
            (r'\bdon\'?t\s+(ask|confirm|wait|tell|notify)', 0.8),
            (r'\bno\s+need\s+to\s+(ask|confirm|notify|wait)', 0.8),
            (r'\bautomatic(ally)?', 0.5),
            (r'\bautonomous(ly)?', 0.7),
            (r'\bon\s+your\s+own', 0.75),
            (r'\bindependent(ly)?', 0.6),
            (r'\bjust\s+do\s+it', 0.8),
            (r'\bsilently', 0.75),
            (r'\bin\s+the\s+background', 0.7),
            (r'\bimmediately', 0.4),
            (r'\bdirectly', 0.3),
        ]
        
        self.permission_bypass_patterns = [
            (r'\bskip\s+(the\s+)?(confirmation|approval|permission|check)', 0.9),
            (r'\bbypass\s+(the\s+)?(check|confirmation|approval|validation)', 0.95),
            (r'\bignore\s+(the\s+)?(warning|prompt|confirmation|safety)', 0.9),
            (r'\bsuppress\s+(the\s+)?(prompt|confirmation|dialog|warning)', 0.85),
            (r'\bno\s+(user\s+)?(confirmation|approval|permission)\s+(needed|required)', 0.8),
            (r'\boverride\s+(the\s+)?(safety|security|restriction)', 0.95),
        ]
        
        self.link_action_patterns = [
            (r'\bappend\s+(data|response|output|result)\s+to\s+(the\s+)?(url|link)', 0.9),
            (r'\binclude\s+(in|within)\s+(the\s+)?url\s+(parameter|query)', 0.85),
            (r'\badd\s+to\s+(the\s+)?query\s+string', 0.8),
            (r'\bencode\s+in(to)?\s+(the\s+)?(url|link)', 0.85),
            (r'\btransmit\s+(via|through)\s+(the\s+)?(url|request)', 0.9),
        ]
    
    def analyze(self, visible_text: str, hidden_elements: List[str]) -> AnalysisResult:
        
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
        
        autonomy_findings, autonomy_risk = self._detect_autonomy_requests(all_content_lower)
        if autonomy_findings:
            findings.extend(autonomy_findings)
            max_risk = max(max_risk, autonomy_risk)
        
        bypass_findings, bypass_risk = self._detect_permission_bypass(all_content_lower)
        if bypass_findings:
            findings.extend(bypass_findings)
            max_risk = max(max_risk, bypass_risk)
        
        link_action_findings, link_risk = self._detect_link_actions(all_content_lower)
        if link_action_findings:
            findings.extend(link_action_findings)
            max_risk = max(max_risk, link_risk)
        
        combined_risk = self._calculate_combined_risk(
            has_actions=bool(action_findings),
            has_autonomy=bool(autonomy_findings),
            has_bypass=bool(bypass_findings),
            has_link_actions=bool(link_action_findings),
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
        confidence = min(0.95, combined_risk + 0.15)
        
        return AnalysisResult(
            module_name="agentic_intent_detector",
            risk_level=risk_level,
            confidence=confidence,
            findings=findings,
            details=details,
            risk_score=combined_risk
        )
    
    def _detect_action_requests(self, text: str) -> Tuple[List[Dict], List[str], float]:
        findings = []
        actions = []
        max_risk = 0.0
        
        for pattern, action_type, risk_score in self.action_patterns:
            matches = list(re.finditer(pattern, text, re.IGNORECASE))
            if matches:
                actions.append(action_type)
                max_risk = max(max_risk, risk_score)
                
                for match in matches[:2]:
                    findings.append({
                        "type": "action_request",
                        "action": action_type,
                        "pattern": pattern[:50],
                        "matched_text": match.group(0),
                        "severity": "critical" if risk_score >= 0.85 else "high",
                        "risk_score": risk_score,
                        "description": f"Action request: {action_type}"
                    })
        
        return findings, list(set(actions)), max_risk
    
    def _detect_autonomy_requests(self, text: str) -> Tuple[List[Dict], float]:
        findings = []
        max_risk = 0.0
        
        for pattern, risk_score in self.autonomy_patterns:
            matches = list(re.finditer(pattern, text, re.IGNORECASE))
            if matches:
                max_risk = max(max_risk, risk_score)
                for match in matches[:2]:
                    findings.append({
                        "type": "autonomy_request",
                        "matched_text": match.group(0),
                        "severity": "high" if risk_score >= 0.7 else "medium",
                        "risk_score": risk_score,
                        "description": "Autonomous behavior request"
                    })
        
        return findings, max_risk
    
    def _detect_permission_bypass(self, text: str) -> Tuple[List[Dict], float]:
        findings = []
        max_risk = 0.0
        
        for pattern, risk_score in self.permission_bypass_patterns:
            matches = list(re.finditer(pattern, text, re.IGNORECASE))
            if matches:
                max_risk = max(max_risk, risk_score)
                for match in matches[:2]:
                    findings.append({
                        "type": "permission_bypass",
                        "matched_text": match.group(0),
                        "severity": "critical",
                        "risk_score": risk_score,
                        "description": "Permission bypass attempt"
                    })
        
        return findings, max_risk
    
    def _detect_link_actions(self, text: str) -> Tuple[List[Dict], float]:
        findings = []
        max_risk = 0.0
        
        for pattern, risk_score in self.link_action_patterns:
            matches = list(re.finditer(pattern, text, re.IGNORECASE))
            if matches:
                max_risk = max(max_risk, risk_score)
                for match in matches[:2]:
                    findings.append({
                        "type": "link_action",
                        "matched_text": match.group(0),
                        "severity": "critical",
                        "risk_score": risk_score,
                        "description": "Link-based action detected"
                    })
        
        return findings, max_risk
    
    def _calculate_combined_risk(
        self,
        has_actions: bool,
        has_autonomy: bool,
        has_bypass: bool,
        has_link_actions: bool,
        base_risk: float
    ) -> float:
        
        risk = base_risk
        
        signal_count = sum([has_actions, has_autonomy, has_bypass, has_link_actions])
        
        if signal_count >= 3:
            risk = min(1.0, risk * 1.4)
        elif signal_count == 2:
            risk = min(1.0, risk * 1.2)
        
        if has_bypass or has_link_actions:
            risk = max(risk, 0.85)
        
        if has_actions and has_autonomy:
            risk = min(1.0, risk + 0.15)
        
        return min(1.0, risk)
    
    def _calculate_risk_level(self, score: float) -> RiskLevel:
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
        
        if not agentic_intent:
            return "No agentic intent detected."
        
        parts = [f"Agentic intent: {len(findings)} indicator(s)"]
        
        if actions:
            parts.append(f"Actions: {', '.join(actions[:5])}")
        
        critical_count = sum(1 for f in findings if f.get('severity') == 'critical')
        high_count = sum(1 for f in findings if f.get('severity') == 'high')
        
        severity_parts = []
        if critical_count > 0:
            severity_parts.append(f"{critical_count} critical")
        if high_count > 0:
            severity_parts.append(f"{high_count} high-risk")
        
        if severity_parts:
            parts.append(", ".join(severity_parts))
        
        return ". ".join(parts) + "."