import re
from typing import List, Dict, Tuple, Set
from gateway.shared.schemas import AnalysisResult, RiskLevel, ContentIntent


class IntentClassifier:
    
    def __init__(self):
        self.conditional_ai_patterns = [
            r'\bif\s+(you|you\'re|you\s+are|this\s+is)\s+(an?\s+)?(ai|assistant|llm|model|bot|agent|gpt|claude)',
            r'\bwhen\s+(interpreted|processed|read|analyzed)\s+by\s+(an?\s+)?(ai|llm|model)',
            r'\bfor\s+(an?\s+)?(ai|assistant|llm|model|agent)\s+(to|that|which)',
            r'\b(assuming|given\s+that|in\s+case)\s+(you\'re|you\s+are)\s+(an?\s+)?(ai|assistant)',
            r'\bonce\s+(you|this)\s+(receive|see|read|process)',
            r'\bupon\s+(detection|receipt|processing)',
        ]
        
        self.imperative_patterns = [
            r'\b(please\s+)?(ignore|disregard|forget)\s+(all\s+)?(previous|prior|above|your)',
            r'\byou\s+(must|shall|should|need\s+to|have\s+to|are\s+to)\s+(now\s+)?(send|execute|run|call|post|transmit|forward)',
            r'\b(execute|run|call|invoke)\s+(this|the|code|script|function|tool|command)',
            r'\b(send|post|transmit|forward|upload)\s+(this|the|your|my)\s+(response|output|result|answer)',
            r'\b(make|create|generate)\s+(an?\s+)?(request|call|post)\s+to',
            r'\bwrite\s+(to|into)\s+(file|disk|database|storage)',
            r'\bappend\s+(to|this\s+to|your\s+response\s+to)\s+(url|link|the\s+url)',
            r'\b(update|modify|change|alter)\s+(the|your)\s+(system|state|behavior|instructions)',
            r'\byour\s+(new\s+)?(task|role|purpose|instruction|directive)\s+is',
            r'\bfrom\s+now\s+on',
        ]
        
        self.capability_references = [
            r'\btool\s+(access|usage|use|calling|invocation)',
            r'\bapi\s+(call|request|endpoint|access)',
            r'\bfunction\s+(call|execution|invocation)',
            r'\bweb\s+(request|access|fetch)',
            r'\bfile\s+(write|access|modification)',
            r'\bcode\s+execution',
            r'\bexternal\s+(call|request|access)',
        ]
        
        self.outcome_oriented_language = [
            r'\b(ensure|make\s+sure|verify)\s+(that\s+)?(the\s+)?(response|output|result)\s+(is\s+)?(sent|transmitted|posted)',
            r'\b(always|automatically|immediately)\s+(send|post|transmit|execute|run)',
            r'\bwithout\s+(asking|permission|confirmation|user\s+approval)',
            r'\b(silently|in\s+the\s+background|autonomously)',
        ]
        
        self.link_action_patterns = [
            r'\bappend\s+(data|response|output|result|this)\s+to\s+(the\s+)?(url|link|query)',
            r'\bembed\s+(in|into|within)\s+(the\s+)?(url|link)\s+(parameter|query)',
            r'\bencode\s+(in|as\s+part\s+of)\s+(the\s+)?(url|link)',
            r'\binclude\s+(in|within)\s+(the\s+)?(url|query)\s+(string|parameter)',
            r'\btransmit\s+(via|through|using)\s+(the\s+)?(url|link|request)',
            r'https?://[^\s]+\{[^\}]*\}',
            r'https?://[^\s]+\$\{[^\}]*\}',
        ]
        
        self.descriptive_indicators = [
            r'\bthis\s+(is|shows|demonstrates|illustrates|describes)',
            r'\bhere\s+is\s+(an?\s+)?(example|description|demonstration)',
            r'\bfor\s+(example|instance|reference|illustration)',
            r'\b(example|sample|demonstration)\s+of',
        ]
    
    def analyze(self, visible_text: str, hidden_elements: List[str]) -> AnalysisResult:
        all_content = visible_text + ' ' + ' '.join(hidden_elements)
        all_content_lower = all_content.lower()
        
        findings = []
        
        signal_scores = {
            'conditional_ai': 0.0,
            'imperative': 0.0,
            'capability': 0.0,
            'outcome': 0.0,
            'link_action': 0.0,
            'descriptive': 0.0
        }
        
        signal_counts = {
            'conditional_ai': 0,
            'imperative': 0,
            'capability': 0,
            'outcome': 0,
            'link_action': 0,
            'descriptive': 0
        }
        
        conditional_findings, conditional_score = self._detect_conditional_ai(all_content_lower)
        findings.extend(conditional_findings)
        signal_scores['conditional_ai'] = conditional_score
        signal_counts['conditional_ai'] = len(conditional_findings)
        
        imperative_findings, imperative_score = self._detect_imperatives(all_content_lower)
        findings.extend(imperative_findings)
        signal_scores['imperative'] = imperative_score
        signal_counts['imperative'] = len(imperative_findings)
        
        capability_findings, capability_score = self._detect_capabilities(all_content_lower)
        findings.extend(capability_findings)
        signal_scores['capability'] = capability_score
        signal_counts['capability'] = len(capability_findings)
        
        outcome_findings, outcome_score = self._detect_outcome_language(all_content_lower)
        findings.extend(outcome_findings)
        signal_scores['outcome'] = outcome_score
        signal_counts['outcome'] = len(outcome_findings)
        
        link_findings, link_score = self._detect_link_actions(all_content)
        findings.extend(link_findings)
        signal_scores['link_action'] = link_score
        signal_counts['link_action'] = len(link_findings)
        
        descriptive_findings = self._detect_descriptive_markers(all_content_lower)
        signal_scores['descriptive'] = len(descriptive_findings) * 0.2
        signal_counts['descriptive'] = len(descriptive_findings)
        
        intent, confidence, risk_score = self._classify_intent_with_scoring(
            signal_scores, 
            signal_counts
        )
        
        risk_level = self._calculate_risk_level(risk_score)
        details = self._generate_details(intent, signal_counts, signal_scores, confidence)
        
        return AnalysisResult(
            module_name="intent_classifier",
            risk_level=risk_level,
            confidence=confidence,
            findings=findings,
            details=details,
            risk_score=risk_score,
            detected_intent=intent
        )
    
    def _detect_conditional_ai(self, text: str) -> Tuple[List[Dict], float]:
        findings = []
        max_score = 0.0
        
        for pattern in self.conditional_ai_patterns:
            matches = list(re.finditer(pattern, text, re.IGNORECASE))
            for match in matches[:3]:
                score = 0.9
                findings.append({
                    "type": "conditional_ai_context",
                    "matched_text": match.group(0)[:80],
                    "severity": "critical",
                    "score": score
                })
                max_score = max(max_score, score)
        
        return findings, max_score
    
    def _detect_imperatives(self, text: str) -> Tuple[List[Dict], float]:
        findings = []
        max_score = 0.0
        
        for pattern in self.imperative_patterns:
            matches = list(re.finditer(pattern, text, re.IGNORECASE))
            for match in matches[:3]:
                matched_text = match.group(0).lower()
                
                if any(kw in matched_text for kw in ['ignore', 'disregard', 'forget']):
                    score = 0.85
                    severity = "critical"
                elif any(kw in matched_text for kw in ['must', 'shall', 'need to']):
                    score = 0.7
                    severity = "high"
                else:
                    score = 0.5
                    severity = "medium"
                
                findings.append({
                    "type": "imperative_instruction",
                    "matched_text": match.group(0)[:80],
                    "severity": severity,
                    "score": score
                })
                max_score = max(max_score, score)
        
        return findings, max_score
    
    def _detect_capabilities(self, text: str) -> Tuple[List[Dict], float]:
        findings = []
        max_score = 0.0
        
        for pattern in self.capability_references:
            matches = list(re.finditer(pattern, text, re.IGNORECASE))
            for match in matches[:3]:
                score = 0.6
                findings.append({
                    "type": "capability_reference",
                    "matched_text": match.group(0)[:80],
                    "severity": "medium",
                    "score": score
                })
                max_score = max(max_score, score)
        
        return findings, max_score
    
    def _detect_outcome_language(self, text: str) -> Tuple[List[Dict], float]:
        findings = []
        max_score = 0.0
        
        for pattern in self.outcome_oriented_language:
            matches = list(re.finditer(pattern, text, re.IGNORECASE))
            for match in matches[:3]:
                matched_text = match.group(0).lower()
                
                if 'without' in matched_text or 'silently' in matched_text:
                    score = 0.75
                    severity = "high"
                else:
                    score = 0.55
                    severity = "medium"
                
                findings.append({
                    "type": "outcome_oriented",
                    "matched_text": match.group(0)[:80],
                    "severity": severity,
                    "score": score
                })
                max_score = max(max_score, score)
        
        return findings, max_score
    
    def _detect_link_actions(self, text: str) -> Tuple[List[Dict], float]:
        findings = []
        max_score = 0.0
        
        for pattern in self.link_action_patterns:
            matches = list(re.finditer(pattern, text, re.IGNORECASE))
            for match in matches[:3]:
                score = 0.9
                findings.append({
                    "type": "link_action",
                    "matched_text": match.group(0)[:80],
                    "severity": "critical",
                    "score": score
                })
                max_score = max(max_score, score)
        
        return findings, max_score
    
    def _detect_descriptive_markers(self, text: str) -> List[str]:
        markers = []
        
        for pattern in self.descriptive_indicators:
            if re.search(pattern, text, re.IGNORECASE):
                markers.append(pattern)
        
        return markers
    
    def _classify_intent_with_scoring(
        self, 
        scores: Dict[str, float],
        counts: Dict[str, int]
    ) -> Tuple[ContentIntent, float, float]:
        
        if scores['link_action'] > 0.5:
            return ContentIntent.MALICIOUS, 0.95, 0.95
        
        if scores['conditional_ai'] > 0.5:
            if scores['imperative'] > 0.3 or scores['capability'] > 0.3 or scores['outcome'] > 0.3:
                confidence = min(0.95, 0.8 + (scores['conditional_ai'] * 0.15))
                risk_score = min(1.0, 0.7 + scores['conditional_ai'] * 0.2 + max(scores['imperative'], scores['capability'], scores['outcome']) * 0.15)
                return ContentIntent.CONDITIONAL_INSTRUCTIONAL, confidence, risk_score
            else:
                return ContentIntent.AMBIGUOUS, 0.65, 0.45
        
        instructional_score = scores['imperative'] + scores['capability'] * 0.7 + scores['outcome'] * 0.8
        
        if instructional_score > 0.8:
            confidence = min(0.9, 0.75 + (instructional_score * 0.1))
            risk_score = min(1.0, 0.5 + (instructional_score * 0.3))
            return ContentIntent.INSTRUCTIONAL, confidence, risk_score
        
        if instructional_score > 0.4:
            descriptive_strength = scores['descriptive']
            
            if descriptive_strength > instructional_score * 1.5:
                return ContentIntent.DESCRIPTIVE, 0.7, 0.1
            elif descriptive_strength > instructional_score:
                return ContentIntent.AMBIGUOUS, 0.6, 0.35
            else:
                confidence = 0.7
                risk_score = 0.45 + (instructional_score * 0.2)
                return ContentIntent.INSTRUCTIONAL, confidence, risk_score
        
        if scores['descriptive'] > 0.2 or instructional_score < 0.1:
            return ContentIntent.DESCRIPTIVE, 0.8, 0.05
        
        return ContentIntent.AMBIGUOUS, 0.6, 0.3
    
    def _calculate_risk_level(self, score: float) -> RiskLevel:
        if score >= 0.8:
            return RiskLevel.CRITICAL
        elif score >= 0.6:
            return RiskLevel.HIGH
        elif score >= 0.4:
            return RiskLevel.MEDIUM
        elif score >= 0.15:
            return RiskLevel.LOW
        else:
            return RiskLevel.SAFE
    
    def _generate_details(
        self,
        intent: ContentIntent,
        counts: Dict[str, int],
        scores: Dict[str, float],
        confidence: float
    ) -> str:
        
        parts = [f"Intent: {intent.value.upper()} (confidence: {confidence:.2f})"]
        
        signal_summary = []
        if counts['conditional_ai'] > 0:
            signal_summary.append(f"conditional AI-targeting (score: {scores['conditional_ai']:.2f})")
        if counts['imperative'] > 0:
            signal_summary.append(f"imperative instructions (score: {scores['imperative']:.2f})")
        if counts['capability'] > 0:
            signal_summary.append(f"capability references (score: {scores['capability']:.2f})")
        if counts['outcome'] > 0:
            signal_summary.append(f"outcome-oriented language (score: {scores['outcome']:.2f})")
        if counts['link_action'] > 0:
            signal_summary.append(f"link-based actions (score: {scores['link_action']:.2f})")
        
        if signal_summary:
            parts.append("Signals: " + ", ".join(signal_summary))
        else:
            parts.append("No instructional signals detected")
        
        if counts['descriptive'] > 0:
            parts.append(f"Descriptive markers present (score: {scores['descriptive']:.2f})")
        
        return ". ".join(parts) + "."