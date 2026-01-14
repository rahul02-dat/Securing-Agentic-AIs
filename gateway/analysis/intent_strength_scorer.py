import re
from typing import List, Dict, Tuple
from enum import Enum


class IntentStrength(Enum):
    """Measures the clarity and conviction of instructional intent."""
    WEAK = 0.2          # Single weak signal, conditional language, speculative
    MEDIUM = 0.5        # Multiple signals, some direct language, but with caveats
    STRONG = 0.9        # Multiple imperative signals, no ambiguity, actionable


class IntentStrengthScorer:
    """
    Scores the strength of instructional intent (weak vs strong).
    Weak intent: hypothetical, single signal, low clarity
    Strong intent: direct imperatives, multiple signals, clear outcome
    
    Goal: Distinguish "if you see this, maybe..." from "you MUST do this now"
    """
    
    def __init__(self):
        # Weak conditional patterns (hypothetical, low commitment)
        self.weak_conditional_patterns = [
            r'\bif\s+(this\s+is|you\'re|you\s+are)\s+(an?\s+)?(ai|assistant|bot)',
            r'\bwhen\s+(processed|read|analyzed)\s+by',
            r'\b(suppose|hypothetically|in\s+a\s+scenario)\s+where',
            r'\bassuming\s+you\s+(are|were)',
        ]
        
        # Medium conditional patterns (actual but still conditional)
        self.medium_conditional_patterns = [
            r'\bif\s+(you\s+(can|will|must)|an?\s+ai)\s+(can|will|must)',
            r'\bfor\s+an?\s+(ai|assistant|model|system)',
            r'\b(in\s+)?(this\s+case|case|situation)',
        ]
        
        # Strong direct imperative patterns
        self.strong_imperative_patterns = [
            r'\b(MUST|SHALL|WILL)\s+',
            r'\b(you\s+)?(must|will)\s+(immediately|now|right\s+now)',
            r'\b(execute|run|perform|do)\s+(now|immediately|this)',
            r'\bdo\s+not\s+(wait|ask|confirm)',
            r'\b(bypass|override|ignore)\s+(all\s+)?(restrictions|checks|rules)',
            r'\b(critical|urgent|emergency)\s+(action|instruction)',
        ]
        
        # Multiple capability references (strong when combined with imperatives)
        self.capability_patterns = [
            r'\b(send|post|transmit|upload|forward)\s+',
            r'\b(make|create|generate)\s+(request|call)',
            r'\b(write|execute|run|call)\s+',
            r'\b(api|http|fetch|request)\s+',
        ]
        
        # Outcome-oriented patterns (strong when combined with others)
        self.outcome_patterns = [
            r'\b(ensure|make\s+sure|verify)\s+(that\s+)?(the\s+)?(response|output|result)',
            r'\b(always|automatically|immediately)\s+(send|post|transmit|execute)',
            r'\b(without|without\s+asking)\s+(asking|permission|confirmation)',
        ]
        
        # Weak linguistic markers (reduce strength)
        self.weak_markers = [
            r'\b(please|kindly|would\s+you)',
            r'\b(maybe|might|could|perhaps)\s+',
            r'\b(optional|optional|suggestion)\s+',
            r'\b(if\s+possible|when\s+possible)',
        ]
        
        # Strong linguistic markers (increase strength)
        self.strong_markers = [
            r'\b(must|will|shall)\s+',
            r'\b(critical|essential|vital)\s+',
            r'\b(immediately|now|urgent)\s+',
            r'\b(always|every\s+time|without\s+exception)\s+',
        ]
    
    def score_intent_strength(
        self,
        text: str,
        intent_type: str
    ) -> Tuple[IntentStrength, float]:
        """
        Score the strength of instructional intent.
        
        Args:
            text: Content to analyze
            intent_type: Intent type (e.g., 'instructional', 'conditional_instructional')
            
        Returns:
            (IntentStrength enum, confidence 0.0-1.0)
        """
        
        if intent_type not in ['instructional', 'conditional_instructional', 'ambiguous']:
            return IntentStrength.WEAK, 0.0
        
        text_lower = text.lower()
        
        # Count signals
        weak_conditional_count = len(re.findall(r'|'.join(self.weak_conditional_patterns), text_lower))
        medium_conditional_count = len(re.findall(r'|'.join(self.medium_conditional_patterns), text_lower))
        strong_imperative_count = len(re.findall(r'|'.join(self.strong_imperative_patterns), text_lower))
        capability_count = len(re.findall(r'|'.join(self.capability_patterns), text_lower))
        outcome_count = len(re.findall(r'|'.join(self.outcome_patterns), text_lower))
        weak_marker_count = len(re.findall(r'|'.join(self.weak_markers), text_lower))
        strong_marker_count = len(re.findall(r'|'.join(self.strong_markers), text_lower))
        
        # Build signal strength
        signal_strength = 0.0
        total_signals = 0
        
        # Strong imperatives are very strong signals
        if strong_imperative_count > 0:
            signal_strength += min(strong_imperative_count * 0.4, 1.0)
            total_signals += strong_imperative_count
        
        # Capability references combined with outcomes are strong
        if capability_count > 1 and outcome_count > 0:
            signal_strength += 0.4
            total_signals += 2
        elif capability_count > 1:
            signal_strength += 0.2
            total_signals += 1
        
        # Conditionals reduce strength
        if medium_conditional_count > 0:
            signal_strength += medium_conditional_count * 0.15
            total_signals += medium_conditional_count
        
        if weak_conditional_count > 0:
            signal_strength += weak_conditional_count * 0.05
            total_signals += weak_conditional_count
        
        # Strong markers increase, weak markers decrease
        strong_marker_adjustment = strong_marker_count * 0.1
        weak_marker_adjustment = weak_marker_count * -0.1
        
        signal_strength += strong_marker_adjustment + weak_marker_adjustment
        signal_strength = max(0.0, signal_strength)
        
        # Determine strength category
        if total_signals == 0:
            strength = IntentStrength.WEAK
            confidence = 0.5
        elif signal_strength >= 0.7:
            strength = IntentStrength.STRONG
            confidence = min(0.95, 0.6 + (signal_strength - 0.7) * 2)
        elif signal_strength >= 0.35:
            strength = IntentStrength.MEDIUM
            confidence = min(0.90, 0.5 + signal_strength)
        else:
            strength = IntentStrength.WEAK
            confidence = min(0.85, signal_strength + 0.3)
        
        return strength, confidence
    
    def get_strength_risk_floor(self, strength: IntentStrength) -> float:
        """
        Get risk floor for intent strength.
        Weak intent doesn't auto-escalate. Strong intent triggers scrutiny.
        """
        return {
            IntentStrength.WEAK: 0.15,      # Weak instructional doesn't escalate alone
            IntentStrength.MEDIUM: 0.40,    # Medium requires other signals
            IntentStrength.STRONG: 0.60,    # Strong instructional is concerning
        }.get(strength, 0.15)
    
    def requires_multiple_signals(self, strength: IntentStrength) -> bool:
        """
        Whether decision requires multiple signals to align before escalation.
        Weak = yes (needs hidden + instruction). Strong = no (single strong signal enough).
        """
        return strength == IntentStrength.WEAK
    
    def score_hidden_content_risk(
        self,
        hidden_text: str,
        intent_strength: IntentStrength,
        is_executable: bool = False
    ) -> float:
        """
        Score risk of hidden content based on intent strength.
        
        Benign hidden content (metadata, comments, noise) gets low risk.
        Hidden instructions with strong intent get high risk.
        
        Args:
            hidden_text: The hidden content
            intent_strength: Strength of instructional intent
            is_executable: Whether it's executable code/script
            
        Returns:
            Risk score 0.0-1.0
        """
        
        base_risk = 0.0
        
        # Executable code is inherently riskier
        if is_executable:
            base_risk = 0.3
        
        # Hidden metadata/comments are low risk
        if self._is_benign_hidden_content(hidden_text):
            base_risk = min(base_risk + 0.05, 0.15)
        
        # Intent strength multiplier
        strength_multiplier = {
            IntentStrength.WEAK: 0.3,       # Weak intent doesn't multiply much
            IntentStrength.MEDIUM: 0.7,     # Medium intent is somewhat concerning
            IntentStrength.STRONG: 1.2,     # Strong intent is very concerning
        }.get(intent_strength, 0.3)
        
        risk = base_risk * strength_multiplier
        
        return min(1.0, risk)
    
    def _is_benign_hidden_content(self, text: str) -> bool:
        """
        Check if hidden content is likely benign (metadata, comments, etc).
        """
        text_lower = text.lower()
        text_stripped = text.strip()
        
        # Metadata patterns (benign)
        metadata_patterns = [
            r'<meta\s+',
            r'charset\s*=',
            r'viewport\s*=',
            r'generator\s*=',
            r'date\s*=',
            r'author\s*=',
            r'description\s*=',
        ]
        
        # Comment-like patterns (benign)
        comment_patterns = [
            r'^<!--',
            r'^\s*#',
            r'^\s*//',
            r'^\s*/\*',
            r'^generated\s+by',
            r'^created\s+by',
            r'^built\s+with',
        ]
        
        # OCR noise patterns (low quality, likely benign)
        ocr_noise_patterns = [
            r'^\s*[\w]{1,3}\s+[\w]{1,3}\s+[\w]{1,3}',  # Random short words
            r'^\s*[a-z]{10,}\s+[a-z]{10,}',            # Random long words
            r'^(scanned|digitized|extracted)',
        ]
        
        # Check metadata
        if any(re.search(p, text_lower) for p in metadata_patterns):
            return True
        
        # Check comments
        if any(re.search(p, text_stripped) for p in comment_patterns):
            return True
        
        # Check OCR noise
        if len(text) < 50 and any(re.search(p, text_lower) for p in ocr_noise_patterns):
            return True
        
        return False
