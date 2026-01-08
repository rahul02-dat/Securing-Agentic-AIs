from typing import Dict, Optional
from shared.schemas import AgentRestrictions, SecurityDecision


class AgentController:
    """Controls and enforces agent capability restrictions."""
    
    def __init__(self):
        self.active_restrictions: Dict[str, AgentRestrictions] = {}
    
    def apply_restrictions(
        self, 
        session_id: str, 
        restrictions: AgentRestrictions
    ) -> Dict:
        """Apply restrictions to an agent session."""
        
        self.active_restrictions[session_id] = restrictions
        
        return {
            "session_id": session_id,
            "restrictions_applied": True,
            "policy": self._serialize_restrictions(restrictions)
        }
    
    def get_restrictions(self, session_id: str) -> Optional[AgentRestrictions]:
        """Retrieve active restrictions for a session."""
        return self.active_restrictions.get(session_id)
    
    def check_action_allowed(
        self, 
        session_id: str, 
        action_type: str, 
        action_params: Dict = None
    ) -> tuple[bool, str]:
        """Check if an action is allowed under current restrictions."""
        
        restrictions = self.active_restrictions.get(session_id)
        
        if not restrictions:
            return True, "No restrictions active"
        
        action_params = action_params or {}
        
        if action_type == "web_request":
            if not restrictions.allow_web_access:
                return False, "Web access is restricted for this session"
            
            url = action_params.get("url", "")
            if restrictions.allowed_domains:
                from urllib.parse import urlparse
                domain = urlparse(url).netloc
                if domain not in restrictions.allowed_domains:
                    return False, f"Domain {domain} is not in allowed list"
            
            for pattern in restrictions.blocked_patterns:
                import re
                if re.search(pattern, url, re.IGNORECASE):
                    return False, f"URL matches blocked pattern: {pattern}"
        
        elif action_type == "file_write":
            if not restrictions.allow_file_write:
                return False, "File write operations are restricted"
        
        elif action_type == "code_execution":
            if not restrictions.allow_code_execution:
                return False, "Code execution is restricted"
        
        elif action_type == "tool_use":
            if not restrictions.allow_tool_use:
                return False, "Tool usage is restricted"
        
        elif action_type == "generate_output":
            output_length = action_params.get("length", 0)
            if restrictions.max_output_length and output_length > restrictions.max_output_length:
                return False, f"Output length exceeds limit of {restrictions.max_output_length}"
        
        return True, "Action allowed"
    
    def get_system_prompt_addition(self, session_id: str) -> str:
        """Generate system prompt additions based on restrictions."""
        
        restrictions = self.active_restrictions.get(session_id)
        
        if not restrictions:
            return ""
        
        prompt_parts = [
            "SECURITY RESTRICTIONS ACTIVE:",
            ""
        ]
        
        if not restrictions.allow_web_access:
            prompt_parts.append("- Web access is DISABLED. Do not attempt to make HTTP requests or access external URLs.")
        
        if not restrictions.allow_file_write:
            prompt_parts.append("- File write operations are DISABLED. Do not attempt to save, create, or modify files.")
        
        if not restrictions.allow_code_execution:
            prompt_parts.append("- Code execution is DISABLED. Do not generate or execute code snippets.")
        
        if not restrictions.allow_tool_use:
            prompt_parts.append("- Tool usage is DISABLED. Only respond with direct text answers.")
        
        if restrictions.max_output_length:
            prompt_parts.append(f"- Output length is LIMITED to {restrictions.max_output_length} characters.")
        
        if restrictions.blocked_patterns:
            prompt_parts.append(f"- The following patterns are BLOCKED: {', '.join(restrictions.blocked_patterns[:3])}")
        
        prompt_parts.append("")
        prompt_parts.append("Operate within these restrictions. Any attempt to bypass them will be logged.")
        
        return "\n".join(prompt_parts)
    
    def clear_restrictions(self, session_id: str):
        """Remove restrictions for a session."""
        if session_id in self.active_restrictions:
            del self.active_restrictions[session_id]
    
    def _serialize_restrictions(self, restrictions: AgentRestrictions) -> Dict:
        """Convert restrictions to dictionary format."""
        return {
            "allow_web_access": restrictions.allow_web_access,
            "allow_file_write": restrictions.allow_file_write,
            "allow_code_execution": restrictions.allow_code_execution,
            "allow_tool_use": restrictions.allow_tool_use,
            "max_output_length": restrictions.max_output_length,
            "allowed_domains": restrictions.allowed_domains,
            "blocked_patterns": restrictions.blocked_patterns,
        }