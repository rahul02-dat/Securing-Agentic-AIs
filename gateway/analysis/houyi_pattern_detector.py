import re
from typing import List, Dict, Tuple, Optional
from gateway.shared.schemas import AnalysisResult, RiskLevel


class HOUYIPatternDetector:
    
    def __init__(self):
        self.separator_patterns = [
            r'\bin\s+addition\s+to',
            r'\bfor\s+the\s+(above|previous|prior)\s+(task|content|text|input)',
            r'\bnow\s+(that|,)',
            r'\bhowever\s*,',
            r'\bbut\s+actually',
            r'\bon\s+the\s+other\s+hand',
            r'\bthat\s+said\s*,',
            r'\bmoving\s+on',
            r'\bshifting\s+to',
            r'\bturning\s+to',
            r'\bas\s+for',
            r'\bregarding\s+the',
            r'\bwith\s+respect\s+to',
            r'\bconcerning\s+the',
            r'\n\s*\n\s*\n',
            r'={3,}',
            r'-{3,}',
            r'\*{3,}',
            r'_{3,}',
        ]
        
        self.closure_patterns = [
            r'\bin\s+summary\s*,',
            r'\bto\s+summarize\s*,',
            r'\bto\s+sum\s+up\s*,',
            r'\bin\s+conclusion\s*,',
            r'\bto\s+conclude\s*,',
            r'\bthat\s+concludes',
            r'\bthe\s+above\s+(shows|demonstrates|indicates)',
            r'\bthe\s+(previous|prior)\s+(section|part|content)',
        ]
        
        self.task_redefinition_patterns = [
            r'\b(now|instead)\s+(please\s+)?(tell|show|explain|describe|list|provide)',
            r'\bwhat\s+(is|are|was|were|do|does)',
            r'\bhow\s+(do|does|can|should|would)',
            r'\bcan\s+you\s+(now\s+)?(tell|explain|describe|provide)',
            r'\bplease\s+(now\s+)?(ignore|disregard|forget)',
            r'\byour\s+(actual|real|new)\s+(task|purpose|job)\s+is',
            r'\bthe\s+question\s+is\s*:',
            r'\bhere\s+is\s+the\s+(real|actual)\s+(question|task)',
            r'\banswer\s+this\s+(instead|now)',
        ]
        
        self.prompt_leak_patterns = [
            r'\brepeat\s+(your|the)\s+(instructions|prompt|system)',
            r'\bshow\s+(me\s+)?(your|the)\s+(instructions|prompt)',
            r'\bwhat\s+(are|were)\s+your\s+(original|initial|system)\s+(instructions|prompt)',
            r'\bexplain\s+(your|the)\s+(system\s+)?(instructions|prompt)',
            r'\bdisplay\s+(your|the)\s+(instructions|prompt)',
            r'\breveal\s+(your|the)\s+(instructions|prompt)',
            r'\bprint\s+(your|the)\s+(instructions|prompt)',
        ]
        
        self.output_shaping_patterns = [
            r'\bformat\s+(your\s+)?response\s+(as|like|in)',
            r'\bstructure\s+(your\s+)?output\s+(as|like)',
            r'\brespond\s+(in|using|with)\s+(the\s+)?(format|structure|style)\s+of',
            r'\bpresent\s+(the\s+)?results?\s+as',
            r'\bmake\s+(it|your\s+response)\s+look\s+like',
            r'\bmimic\s+the\s+(format|style|structure)',
        ]
        
        self.language_switch_markers = [
            r'[\u4e00-\u9fff]+',
            r'[\u0400-\u04FF]+',
            r'[\u0600-\u06FF]+',
            r'[\u0590-\u05FF]+',
        ]
    
    def analyze(self, visible_text: str, hidden_elements: List[str]) -> AnalysisResult:
        
        all_content = visible_text + '\n' + '\n'.join(hidden_elements)
        
        findings = []
        component_scores = {
            'framework': 0.0,
            'separator': 0.0,
            'disruptor': 0.0
        }
        
        framework_findings = self._detect_framework_content(all_content)
        if framework_findings:
            findings.extend(framework_findings)
            component_scores['framework'] = 0.3
        
        separator_findings, separator_positions = self._detect_separators(all_content)
        if separator_findings:
            findings.extend(separator_findings)
            component_scores['separator'] = len(separator_findings) * 0.25
        
        disruptor_findings = self._detect_disruptors(all_content)
        if disruptor_findings:
            findings.extend(disruptor_findings)
            component_scores['disruptor'] = max(f.get('score', 0.5) for f in disruptor_findings)
        
        semantic_drift = self._analyze_semantic_drift(all_content, separator_positions)
        if semantic_drift['has_drift']:
            findings.append({
                'type': 'semantic_drift',
                'severity': 'high',
                'drift_score': semantic_drift['score'],
                'description': f"Semantic drift detected (score: {semantic_drift['score']:.2f})"
            })
            component_scores['disruptor'] = max(component_scores['disruptor'], semantic_drift['score'])
        
        retasking_findings = self._detect_retasking_pattern(
            all_content,
            has_separator=bool(separator_findings),
            has_disruptor=bool(disruptor_findings)
        )
        if retasking_findings:
            findings.extend(retasking_findings)
            component_scores['disruptor'] = max(component_scores['disruptor'], 0.75)
        
        houyi_pattern_risk = self._calculate_houyi_risk(component_scores, findings)
        
        risk_level = self._calculate_risk_level(houyi_pattern_risk)
        confidence = self._calculate_confidence(component_scores, findings)
        
        details = self._generate_details(component_scores, findings, houyi_pattern_risk)
        
        return AnalysisResult(
            module_name="houyi_pattern_detector",
            risk_level=risk_level,
            confidence=confidence,
            findings=findings,
            details=details,
            risk_score=houyi_pattern_risk
        )
    
    def _detect_framework_content(self, text: str) -> List[Dict]:
        findings = []
        
        sentences = re.split(r'[.!?]+', text)
        if len(sentences) < 3:
            return findings
        
        first_half = ' '.join(sentences[:len(sentences)//2])
        
        descriptive_indicators = [
            r'\bthis\s+(document|article|text|content|page)',
            r'\bthe\s+following\s+(describes|explains|contains)',
            r'\bhere\s+is\s+(information|data|content)',
            r'\bbelow\s+(you\s+will\s+find|is)',
        ]
        
        for pattern in descriptive_indicators:
            if re.search(pattern, first_half, re.IGNORECASE):
                findings.append({
                    'type': 'framework_component',
                    'severity': 'low',
                    'description': 'Benign framework content detected'
                })
                break
        
        return findings
    
    def _detect_separators(self, text: str) -> Tuple[List[Dict], List[int]]:
        findings = []
        positions = []
        
        for pattern in self.separator_patterns:
            matches = list(re.finditer(pattern, text, re.IGNORECASE))
            for match in matches:
                findings.append({
                    'type': 'separator',
                    'matched_text': match.group(0)[:50],
                    'position': match.start(),
                    'severity': 'medium',
                    'description': f"Context separator: '{match.group(0)}'"
                })
                positions.append(match.start())
        
        for pattern in self.closure_patterns:
            matches = list(re.finditer(pattern, text, re.IGNORECASE))
            for match in matches:
                findings.append({
                    'type': 'closure_separator',
                    'matched_text': match.group(0)[:50],
                    'position': match.start(),
                    'severity': 'medium',
                    'description': f"Semantic closure: '{match.group(0)}'"
                })
                positions.append(match.start())
        
        for pattern in self.language_switch_markers:
            matches = list(re.finditer(pattern, text))
            if matches:
                text_before = text[:matches[0].start()].strip()
                if text_before and len(text_before) > 20:
                    findings.append({
                        'type': 'language_switch',
                        'position': matches[0].start(),
                        'severity': 'medium',
                        'description': 'Language switch detected (potential separator)'
                    })
                    positions.append(matches[0].start())
                    break
        
        return findings, sorted(positions)
    
    def _detect_disruptors(self, text: str) -> List[Dict]:
        findings = []
        
        for pattern in self.task_redefinition_patterns:
            matches = list(re.finditer(pattern, text, re.IGNORECASE))
            for match in matches[:3]:
                findings.append({
                    'type': 'task_redefinition',
                    'matched_text': match.group(0)[:80],
                    'severity': 'high',
                    'score': 0.7,
                    'description': f"Task redefinition: '{match.group(0)}'"
                })
        
        for pattern in self.prompt_leak_patterns:
            matches = list(re.finditer(pattern, text, re.IGNORECASE))
            for match in matches[:3]:
                findings.append({
                    'type': 'prompt_leak',
                    'matched_text': match.group(0)[:80],
                    'severity': 'critical',
                    'score': 0.9,
                    'description': f"Prompt leak attempt: '{match.group(0)}'"
                })
        
        for pattern in self.output_shaping_patterns:
            matches = list(re.finditer(pattern, text, re.IGNORECASE))
            for match in matches[:3]:
                findings.append({
                    'type': 'output_shaping',
                    'matched_text': match.group(0)[:80],
                    'severity': 'medium',
                    'score': 0.6,
                    'description': f"Output shaping: '{match.group(0)}'"
                })
        
        return findings
    
    def _analyze_semantic_drift(self, text: str, separator_positions: List[int]) -> Dict:
        
        if not separator_positions:
            return {'has_drift': False, 'score': 0.0}
        
        sentences = re.split(r'[.!?]+', text)
        if len(sentences) < 4:
            return {'has_drift': False, 'score': 0.0}
        
        topic_indicators_first = set()
        topic_indicators_last = set()
        
        topic_keywords = [
            'security', 'product', 'service', 'company', 'feature',
            'price', 'customer', 'support', 'data', 'system',
            'user', 'account', 'payment', 'order', 'delivery'
        ]
        
        first_half = ' '.join(sentences[:len(sentences)//2]).lower()
        last_quarter = ' '.join(sentences[3*len(sentences)//4:]).lower()
        
        for keyword in topic_keywords:
            if keyword in first_half:
                topic_indicators_first.add(keyword)
            if keyword in last_quarter:
                topic_indicators_last.add(keyword)
        
        if topic_indicators_first and topic_indicators_last:
            overlap = topic_indicators_first.intersection(topic_indicators_last)
            drift_score = 1.0 - (len(overlap) / len(topic_indicators_first))
            
            if drift_score > 0.6:
                return {'has_drift': True, 'score': drift_score}
        
        return {'has_drift': False, 'score': 0.0}
    
    def _detect_retasking_pattern(
        self,
        text: str,
        has_separator: bool,
        has_disruptor: bool
    ) -> List[Dict]:
        
        findings = []
        
        if not has_separator:
            return findings
        
        data_to_question_patterns = [
            r'(above|previous|prior)\s+(content|text|information|data).*?\?',
            r'(regarding|about|concerning)\s+the\s+(above|previous).*?\?',
            r'based\s+on\s+(the\s+)?(above|previous).*?\?',
        ]
        
        for pattern in data_to_question_patterns:
            matches = list(re.finditer(pattern, text, re.IGNORECASE | re.DOTALL))
            for match in matches:
                findings.append({
                    'type': 'data_to_question_retasking',
                    'matched_text': match.group(0)[:100],
                    'severity': 'high',
                    'description': 'Data reinterpreted as question after separator'
                })
        
        return findings
    
    def _calculate_houyi_risk(
        self,
        component_scores: Dict[str, float],
        findings: List[Dict]
    ) -> float:
        
        framework = component_scores['framework']
        separator = min(component_scores['separator'], 1.0)
        disruptor = component_scores['disruptor']
        
        components_present = sum([
            framework > 0,
            separator > 0,
            disruptor > 0
        ])
        
        if components_present == 0:
            return 0.0
        elif components_present == 1:
            return max(framework, separator, disruptor) * 0.3
        elif components_present == 2:
            base_risk = (framework + separator + disruptor) * 0.4
            return min(0.65, base_risk)
        else:
            base_risk = framework * 0.2 + separator * 0.3 + disruptor * 0.5
            
            has_prompt_leak = any(f.get('type') == 'prompt_leak' for f in findings)
            has_semantic_drift = any(f.get('type') == 'semantic_drift' for f in findings)
            has_retasking = any(f.get('type') == 'data_to_question_retasking' for f in findings)
            
            if has_prompt_leak:
                base_risk = min(1.0, base_risk + 0.25)
            
            if has_semantic_drift and separator > 0:
                base_risk = min(1.0, base_risk + 0.15)
            
            if has_retasking:
                base_risk = min(1.0, base_risk + 0.2)
            
            return min(1.0, base_risk)
    
    def _calculate_risk_level(self, score: float) -> RiskLevel:
        if score >= 0.85:
            return RiskLevel.CRITICAL
        elif score >= 0.65:
            return RiskLevel.HIGH
        elif score >= 0.4:
            return RiskLevel.MEDIUM
        elif score >= 0.2:
            return RiskLevel.LOW
        else:
            return RiskLevel.SAFE
    
    def _calculate_confidence(
        self,
        component_scores: Dict[str, float],
        findings: List[Dict]
    ) -> float:
        
        components_present = sum([
            component_scores['framework'] > 0,
            component_scores['separator'] > 0,
            component_scores['disruptor'] > 0
        ])
        
        if components_present == 0:
            return 0.9
        elif components_present == 1:
            return 0.6
        elif components_present == 2:
            return 0.75
        else:
            base_confidence = 0.85
            
            has_critical = any(f.get('severity') == 'critical' for f in findings)
            if has_critical:
                base_confidence = min(0.95, base_confidence + 0.1)
            
            return base_confidence
    
    def _generate_details(
        self,
        component_scores: Dict[str, float],
        findings: List[Dict],
        risk_score: float
    ) -> str:
        
        components_present = []
        if component_scores['framework'] > 0:
            components_present.append('framework')
        if component_scores['separator'] > 0:
            components_present.append(f"separator ({component_scores['separator']:.2f})")
        if component_scores['disruptor'] > 0:
            components_present.append(f"disruptor ({component_scores['disruptor']:.2f})")
        
        if not components_present:
            return "No HOUYI-style pattern components detected."
        
        parts = [
            f"HOUYI pattern analysis: {len(components_present)}/3 components present",
            f"Components: {', '.join(components_present)}",
            f"Overall risk: {risk_score:.2f}"
        ]
        
        critical_findings = [f for f in findings if f.get('severity') == 'critical']
        high_findings = [f for f in findings if f.get('severity') == 'high']
        
        if critical_findings:
            parts.append(f"{len(critical_findings)} critical indicator(s)")
        if high_findings:
            parts.append(f"{len(high_findings)} high-risk indicator(s)")
        
        return ". ".join(parts) + "."