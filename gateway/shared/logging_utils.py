import json
import logging
from pathlib import Path
from datetime import datetime
from typing import Dict, Any
from .schemas import SecurityEvent


class SecurityLogger:
    """Handles structured logging of security events to JSON."""
    
    def __init__(self, log_dir: str = "logs"):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(exist_ok=True)
        self.log_file = self.log_dir / "security_events.jsonl"
        
        self.logger = logging.getLogger("PromptWall")
        self.logger.setLevel(logging.INFO)
        
        handler = logging.StreamHandler()
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)
    
    def log_security_event(self, event: SecurityEvent):
        """Write security event to JSONL file."""
        event_dict = {
            "event_id": event.event_id,
            "timestamp": event.timestamp,
            "event_type": event.event_type,
            "severity": event.severity,
            "input_source": event.input_source,
            "risk_level": event.risk_level,
            "decision": event.decision,
            "findings": event.findings,
            "metadata": event.metadata
        }
        
        with open(self.log_file, "a") as f:
            f.write(json.dumps(event_dict) + "\n")
        
        self.logger.info(f"Security event logged: {event.event_type} - {event.severity}")
    
    def log_info(self, message: str, **kwargs):
        """Log informational message."""
        self.logger.info(message, extra=kwargs)
    
    def log_warning(self, message: str, **kwargs):
        """Log warning message."""
        self.logger.warning(message, extra=kwargs)
    
    def log_error(self, message: str, **kwargs):
        """Log error message."""
        self.logger.error(message, extra=kwargs)