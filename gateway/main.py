import sys
import os
import uuid
import csv
from datetime import datetime
from pathlib import Path
from io import StringIO

sys.path.insert(0, str(Path(__file__).parent.parent))

# Try to import PDF extraction library
try:
    import pypdf
    HAS_PYPDF = True
except ImportError:
    HAS_PYPDF = False

# Try to import Excel handling libraries
try:
    import openpyxl
    HAS_OPENPYXL = True
except ImportError:
    HAS_OPENPYXL = False

# Try to import Word document handling library
try:
    from docx import Document as DocxDocument
    HAS_PYTHON_DOCX = True
except ImportError:
    HAS_PYTHON_DOCX = False

# Try to import PowerPoint handling library
try:
    from pptx import Presentation
    HAS_PYTHON_PPTX = True
except ImportError:
    HAS_PYTHON_PPTX = False

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


def read_file_content(file_path: Path) -> str:
    """
    Read file content, handling different file types.
    
    Args:
        file_path: Path to the file
        
    Returns:
        File content as string
        
    Raises:
        ValueError: If file type is not supported or cannot be read
    """
    suffix = file_path.suffix.lower()
    
    # Text files
    text_extensions = {'.txt', '.md', '.html', '.xml', '.csv', '.json', '.py', '.js', '.yaml', '.yml', '.log'}
    if suffix in text_extensions:
        try:
            return file_path.read_text(encoding='utf-8').strip()
        except UnicodeDecodeError:
            # Try with latin-1 as fallback
            try:
                return file_path.read_text(encoding='latin-1').strip()
            except Exception as e:
                raise ValueError(f"Cannot read text file {file_path}: {str(e)}")
    
    # CSV files
    elif suffix == '.csv':
        try:
            content = []
            with open(file_path, 'r', encoding='utf-8') as f:
                reader = csv.reader(f)
                for row_num, row in enumerate(reader, 1):
                    content.append(f"Row {row_num}: {' | '.join(row)}")
            result = '\n'.join(content).strip()
            if not result:
                raise ValueError("CSV file is empty")
            return result
        except Exception as e:
            raise ValueError(f"Error reading CSV file {file_path}: {str(e)}")
    
    # Excel files (.xlsx, .xls)
    elif suffix in {'.xlsx', '.xls'}:
        if not HAS_OPENPYXL:
            raise ValueError(
                f"Excel file detected ({file_path}) but openpyxl is not installed. "
                "Install it with: pip install openpyxl"
            )
        try:
            content = []
            workbook = openpyxl.load_workbook(file_path)
            for sheet_name in workbook.sheetnames:
                sheet = workbook[sheet_name]
                content.append(f"Sheet: {sheet_name}")
                for row_num, row in enumerate(sheet.iter_rows(values_only=True), 1):
                    row_values = [str(cell) if cell is not None else "" for cell in row]
                    content.append(f"Row {row_num}: {' | '.join(row_values)}")
            result = '\n'.join(content).strip()
            if not result:
                raise ValueError("Excel file is empty or contains no readable data")
            return result
        except Exception as e:
            raise ValueError(f"Error reading Excel file {file_path}: {str(e)}")
    
    # Word documents (.docx)
    elif suffix == '.docx':
        if not HAS_PYTHON_DOCX:
            raise ValueError(
                f"Word document detected ({file_path}) but python-docx is not installed. "
                "Install it with: pip install python-docx"
            )
        try:
            doc = DocxDocument(file_path)
            content = []
            for para in doc.paragraphs:
                if para.text.strip():
                    content.append(para.text)
            # Also extract text from tables
            for table in doc.tables:
                for row in table.rows:
                    row_values = [cell.text for cell in row.cells]
                    content.append(' | '.join(row_values))
            result = '\n'.join(content).strip()
            if not result:
                raise ValueError("Word document contains no readable text")
            return result
        except Exception as e:
            raise ValueError(f"Error reading Word document {file_path}: {str(e)}")
    
    # PowerPoint presentations (.pptx)
    elif suffix == '.pptx':
        if not HAS_PYTHON_PPTX:
            raise ValueError(
                f"PowerPoint file detected ({file_path}) but python-pptx is not installed. "
                "Install it with: pip install python-pptx"
            )
        try:
            prs = Presentation(file_path)
            content = []
            for slide_num, slide in enumerate(prs.slides, 1):
                content.append(f"Slide {slide_num}:")
                for shape in slide.shapes:
                    if hasattr(shape, "text") and shape.text.strip():
                        content.append(f"  {shape.text}")
            result = '\n'.join(content).strip()
            if not result:
                raise ValueError("PowerPoint presentation contains no readable text")
            return result
        except Exception as e:
            raise ValueError(f"Error reading PowerPoint file {file_path}: {str(e)}")
    
    # PDF files
    elif suffix == '.pdf':
        if not HAS_PYPDF:
            raise ValueError(
                f"PDF file detected ({file_path}) but pypdf is not installed. "
                "Install it with: pip install pypdf"
            )
        try:
            text_content = []
            with open(file_path, 'rb') as f:
                pdf_reader = pypdf.PdfReader(f)
                for page_num in range(len(pdf_reader.pages)):
                    page = pdf_reader.pages[page_num]
                    text_content.append(page.extract_text())
            result = '\n'.join(text_content).strip()
            if not result:
                raise ValueError("No text could be extracted from the PDF")
            return result
        except Exception as e:
            raise ValueError(f"Error reading PDF file {file_path}: {str(e)}")
    
    # Other common file types
    elif suffix in {'.jpg', '.jpeg', '.png', '.gif', '.img', '.bin', '.zip', '.tar', '.gz'}:
        raise ValueError(
            f"Binary file format '{suffix}' is not supported. "
            "Please provide a text, CSV, Excel, Word, PowerPoint, or PDF file."
        )
    
    # Unknown extension - try as text
    else:
        try:
            return file_path.read_text(encoding='utf-8').strip()
        except (UnicodeDecodeError, OSError):
            raise ValueError(
                f"Unable to read file {file_path}. "
                "Supported formats: .txt, .md, .html, .csv, .xlsx, .xls, .docx, .pptx, .pdf, and other text files"
            )


def main():
    """CLI entry point."""
    
    print("=" * 60)
    print("UnseenLinkGuard - LLM Security Gateway")
    print("=" * 60)
    print()
    
    guard = UnseenLinkGuard()
    
    if len(sys.argv) > 1:
        input_arg = " ".join(sys.argv[1:])
        
        # Check if argument is a file path
        file_path = Path(input_arg)
        if file_path.exists() and file_path.is_file():
            try:
                file_content = read_file_content(file_path)
                if file_content:
                    print(f"Processing input from file: {file_path}")
                    print("-" * 60 + "\n")
                    process_and_display_result(guard, file_content, str(file_path))
                    return
            except ValueError as e:
                print(f"Error: {str(e)}", file=sys.stderr)
                sys.exit(1)
        else:
            # Treat as direct input
            process_and_display_result(guard, input_arg)
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
            file_content = read_file_content(input_file_path)
            if file_content:
                print("Processing input from input.txt...")
                print("-" * 60 + "\n")
                process_and_display_result(guard, file_content, "input.txt")
                return
        except ValueError as e:
            print(f"Error: {str(e)}", file=sys.stderr)
            sys.exit(1)
    
    print("Enter URL, text to analyze, or file path (or 'quit' to exit):")
    print("Supported file types: .txt, .md, .html, .csv, .xlsx, .xls, .docx, .pptx, .pdf")
    print()
    
    while True:
        try:
            user_input = input("> ").strip()
            
            if user_input.lower() in ['quit', 'exit', 'q']:
                print("\nExiting UnseenLinkGuard. Stay secure!")
                break
            
            if not user_input:
                continue
            
            # Check if input is a file path
            file_path = Path(user_input)
            if file_path.exists() and file_path.is_file():
                try:
                    file_content = read_file_content(file_path)
                    if file_content:
                        print("\n" + "-" * 60)
                        print(f"Processing input from file: {file_path}")
                        print("-" * 60 + "\n")
                        result = guard.process_input(file_content)
                        display_result(result)
                    else:
                        print(f"File {file_path} is empty.")
                except ValueError as e:
                    print(f"Error: {str(e)}")
                continue
            
            print("\n" + "-" * 60)
            print("Processing input...")
            print("-" * 60 + "\n")
            
            result = guard.process_input(user_input)
            display_result(result)
            
        except KeyboardInterrupt:
            print("\n\nExiting UnseenLinkGuard. Stay secure!")
            break
        except Exception as e:
            print(f"\nError: {str(e)}")
            print()


def process_and_display_result(guard, input_data, source=None):
    """Process input and display result (for non-interactive mode)."""
    try:
        if source:
            print(f"File: {source}")
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