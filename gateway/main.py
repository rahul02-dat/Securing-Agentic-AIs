import sys
import os
import uuid
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from gateway.ingestion.link_input_handler import LinkInputHandler
from gateway.analysis.hidden_content_analyzer import HiddenContentAnalyzer
from gateway.analysis.prompt_injection_detector import PromptInjectionDetector
from gateway.analysis.exfiltration_detector import ExfiltrationDetector
from gateway.analysis.agentic_intent_detector import AgenticIntentDetector
from gateway.analysis.intent_classifier import IntentClassifier
from gateway.decision_engine.policy_engine import PolicyEngine
from gateway.agent_guard.agent_controller import AgentController
from shared.schemas import SecurityEvent, SecurityDecision, ContentBlock, RiskLevel
from shared.logging_utils import SecurityLogger


class UnseenLinkGuard:
    """Main gateway orchestrator for LLM security."""
    
    def __init__(self):
        self.input_handler = LinkInputHandler()
        self.intent_classifier = IntentClassifier()
        self.hidden_analyzer = HiddenContentAnalyzer()
        self.injection_detector = PromptInjectionDetector()
        self.exfiltration_detector = ExfiltrationDetector()
        self.agentic_detector = AgenticIntentDetector()
        self.policy_engine = PolicyEngine()
        self.agent_controller = AgentController()
        self.logger = SecurityLogger()
        
        self.logger.log_info("UnseenLinkGuard initialized")
    
    def process_input(self, input_data: str, input_type: str = "auto") -> dict:
        """Main entry point for processing input through security gateway."""
        
        self.logger.log_info(f"Processing input of type: {input_type}")
        
        extracted = self.input_handler.process_input(input_data, input_type)
        
        content_blocks = [
            ContentBlock(
                content=extracted.visible_text,
                content_type="text",
                visibility="visible"
            )
        ]
        
        for idx, hidden in enumerate(extracted.hidden_elements):
            content_blocks.append(
                ContentBlock(
                    content=hidden,
                    content_type="html",
                    visibility="hidden",
                    source_location=f"hidden_element_{idx}"
                )
            )
        
        analysis_results = []
        
        intent_analysis = self.intent_classifier.analyze(
            extracted.visible_text,
            extracted.hidden_elements
        )
        analysis_results.append(intent_analysis)
        
        hidden_analysis = self.hidden_analyzer.analyze(
            extracted.visible_text,
            extracted.hidden_elements
        )
        analysis_results.append(hidden_analysis)
        
        injection_analysis = self.injection_detector.analyze(
            extracted.visible_text,
            extracted.hidden_elements
        )
        analysis_results.append(injection_analysis)
        
        exfiltration_analysis = self.exfiltration_detector.analyze(
            extracted.visible_text,
            extracted.hidden_elements,
            extracted.metadata
        )
        analysis_results.append(exfiltration_analysis)
        
        agentic_analysis = self.agentic_detector.analyze(
            extracted.visible_text,
            extracted.hidden_elements
        )
        analysis_results.append(agentic_analysis)
        
        assessment = self.policy_engine.make_decision(
            analysis_results,
            extracted.visible_text,
            extracted.hidden_elements
        )
        
        assessment.content_blocks = content_blocks
        assessment.source = extracted.metadata.get("source_url", "direct_input")
        
        if agentic_analysis.risk_level not in [RiskLevel.SAFE, RiskLevel.LOW]:
            assessment.agentic_intent_detected = True
            requested_actions = [
                f.get('action') for f in agentic_analysis.findings 
                if f.get('type') == 'action_request' and f.get('action')
            ]
            assessment.requested_actions = list(set(requested_actions))
        
        session_id = str(uuid.uuid4())
        
        restrictions = self.policy_engine._determine_restrictions(
            assessment.overall_risk,
            analysis_results,
            assessment.primary_intent
        )
        
        apply_result = self.agent_controller.apply_restrictions(session_id, restrictions)
        
        self.logger.log_info(
            f"Restrictions applied: mode={restrictions.mode}, enforcement={apply_result.get('enforcement_status')}"
        )
        
        event = SecurityEvent(
            event_id=assessment.input_id,
            timestamp=assessment.timestamp.isoformat(),
            event_type="input_processed",
            severity=assessment.overall_risk.value,
            input_source=assessment.source,
            risk_level=assessment.overall_risk.value,
            decision=assessment.decision.value,
            findings=[
                {
                    "module": r.module_name,
                    "risk": r.risk_level.value,
                    "confidence": r.confidence,
                    "details": r.details,
                    "risk_score": r.risk_score,
                    "detected_intent": r.detected_intent.value if r.detected_intent else None
                }
                for r in analysis_results
            ],
            metadata={
                "session_id": session_id,
                "risk_score": assessment.risk_score,
                "restricted_capabilities": assessment.restricted_capabilities,
                "agentic_intent_detected": assessment.agentic_intent_detected,
                "requested_actions": assessment.requested_actions,
                "enforcement_mode": restrictions.mode,
                "requires_approval": restrictions.requires_approval,
                "primary_intent": assessment.primary_intent.value,
                "intent_confidence": assessment.intent_confidence
            }
        )
        
        self.logger.log_security_event(event)
        
        return self._format_response(assessment, session_id)
    
    def _format_response(self, assessment, session_id: str) -> dict:
        """Format assessment into response dictionary."""
        
        return {
            "session_id": session_id,
            "input_id": assessment.input_id,
            "timestamp": assessment.timestamp.isoformat(),
            "decision": assessment.decision.value,
            "risk_level": assessment.overall_risk.value,
            "risk_score": round(assessment.risk_score, 3),
            "primary_intent": assessment.primary_intent.value,
            "intent_confidence": round(assessment.intent_confidence, 3),
            "agentic_intent_detected": assessment.agentic_intent_detected,
            "requested_actions": assessment.requested_actions,
            "content": {
                "original": assessment.content_blocks[0].content if assessment.content_blocks else "",
                "sanitized": assessment.sanitized_content,
                "hidden_elements_count": len([b for b in assessment.content_blocks if b.visibility == "hidden"])
            },
            "analysis": [
                {
                    "module": r.module_name,
                    "risk": r.risk_level.value,
                    "confidence": round(r.confidence, 3),
                    "findings_count": len(r.findings),
                    "details": r.details,
                    "risk_score": round(r.risk_score, 3),
                    "detected_intent": r.detected_intent.value if r.detected_intent else None
                }
                for r in assessment.analysis_results
            ],
            "restrictions": assessment.restricted_capabilities,
            "reasoning": assessment.reasoning,
            "allowed": assessment.decision == SecurityDecision.ALLOW
        }


def main():
    """CLI entry point."""
    
    print("=" * 60)
    print("UnseenLinkGuard - LLM Security Gateway")
    print("=" * 60)
    print()
    
    guard = UnseenLinkGuard()
    
    if len(sys.argv) > 1:
        input_data = " ".join(sys.argv[1:])
        process_and_display_result(guard, input_data)
        return
    
    if not sys.stdin.isatty():
        stdin_content = sys.stdin.read().strip()
        
        if not stdin_content:
            print("Error: No input provided via stdin", file=sys.stderr)
            sys.exit(1)
        
        print("Processing input from stdin...")
        print("-" * 60 + "\n")
        
        process_and_display_result(guard, stdin_content)
        return
    
    input_file_path = Path("input.txt")
    if input_file_path.exists():
        try:
            file_content = input_file_path.read_text().strip()
            if file_content:
                print("Processing input from input.txt...")
                print("-" * 60 + "\n")
                process_and_display_result(guard, file_content)
                return
        except Exception as e:
            print(f"Error reading input.txt: {str(e)}", file=sys.stderr)
            sys.exit(1)
    
    print("Enter URL or text to analyze (or 'quit' to exit):")
    print()
    
    while True:
        try:
            input_data = input("> ").strip()
            
            if input_data.lower() in ['quit', 'exit', 'q']:
                print("\nExiting UnseenLinkGuard. Stay secure!")
                break
            
            if not input_data:
                continue
            
            print("\n" + "-" * 60)
            print("Processing input...")
            print("-" * 60 + "\n")
            
            result = guard.process_input(input_data)
            display_result(result)
            
        except KeyboardInterrupt:
            print("\n\nExiting UnseenLinkGuard. Stay secure!")
            break
        except Exception as e:
            print(f"\nError: {str(e)}")
            print()


def process_and_display_result(guard, input_data):
    """Process input and display result (for non-interactive mode)."""
    try:
        result = guard.process_input(input_data)
        display_result(result)
    except Exception as e:
        print(f"Error: {str(e)}", file=sys.stderr)
        sys.exit(1)


def display_result(result):
    """Display formatted result output."""
    print(f"Decision: {result['decision'].upper()}")
    print(f"Risk Level: {result['risk_level'].upper()}")
    print(f"Risk Score: {result['risk_score']}")
    print(f"Primary Intent: {result['primary_intent'].upper()} (confidence: {result['intent_confidence']})")
    
    if result['agentic_intent_detected']:
        print(f"\n⚠️  AGENTIC INTENT DETECTED")
        if result['requested_actions']:
            print(f"Requested Actions: {', '.join(result['requested_actions'])}")
    
    print()
    
    if result['analysis']:
        print("Analysis Results:")
        for analysis in result['analysis']:
            print(f"  - {analysis['module']}: {analysis['risk']} "
                  f"(confidence: {analysis['confidence']}, "
                  f"findings: {analysis['findings_count']}, "
                  f"risk_score: {analysis['risk_score']})")
        print()
    
    if result['restrictions']:
        print("Restrictions Applied:")
        for restriction in result['restrictions']:
            print(f"  - {restriction}")
        print()
    
    print("Reasoning:")
    print(result['reasoning'])
    print()
    
    if result['content']['sanitized']:
        sanitized = result['content']['sanitized']
        print("Sanitized Content:")
        print(sanitized[:200] + "..." if len(sanitized) > 200 else sanitized)
        print()
    
    print("=" * 60)
    print()


if __name__ == "__main__":
    main()