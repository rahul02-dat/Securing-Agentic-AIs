"""
Configuration loader with safe defaults.
Loads settings from YAML file with fallback to defaults.
"""

import yaml
from pathlib import Path
from typing import Dict, Any


class ConfigLoader:
    """Loads and provides access to configuration settings."""
    
    DEFAULT_CONFIG = {
        'risk_weights': {
            'intent_classifier': 0.30,
            'semantic_threat_detector': 0.15,
            'hidden_content_analyzer': 0.10,
            'prompt_injection_detector': 0.15,
            'exfiltration_detector': 0.10,
            'agentic_intent_detector': 0.15,
            'content_deobfuscator': 0.05,
        },
        'decision_thresholds': {
            'block': 0.75,
            'require_approval': 0.40,
            'sanitize': 0.20,
            'allow': 0.15,
        },
        'intent_risk_floors': {
            'malicious': 0.95,
            'conditional_instructional': 0.70,
            'instructional': 0.50,
            'ambiguous': 0.30,
            'descriptive': 0.00,
        },
        'baseline_risks': {
            'ocr_extracted': 0.25,
            'decoded_content': 0.20,
            'hidden_elements': 0.15,
            'conditional_language': 0.35,
        },
        'semantic_analysis': {
            'enabled': True,
            'similarity_threshold': 0.65,
            'model_name': 'all-MiniLM-L6-v2',
        },
        'deobfuscation': {
            'max_recursion_depth': 3,
            'max_decode_size': 1000000,
            'min_pattern_length': 20,
        },
        'ocr_analysis': {
            'enabled': True,
            'supported_formats': ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff', '.webp'],
            'baseline_risk': 0.25,
        },
        'enforcement': {
            'fail_closed': True,
            'strict_intent_enforcement': True,
            'require_approval_for_agentic': True,
        },
        'performance': {
            'parallel_execution': True,
            'max_workers': 5,
            'analysis_timeout': 30,
        },
        'logging': {
            'level': 'INFO',
            'log_dir': 'logs',
            'log_file': 'security_events.jsonl',
        },
        'features': {
            'semantic_detection': True,
            'active_deobfuscation': True,
            'ocr_analysis': True,
            'parallel_analysis': True,
        }
    }
    
    def __init__(self, config_path: str = "config.yaml"):
        self.config_path = Path(config_path)
        self.config = self._load_config()
    
    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from file or use defaults."""
        
        if self.config_path.exists():
            try:
                with open(self.config_path, 'r') as f:
                    loaded_config = yaml.safe_load(f)
                
                # Merge with defaults (loaded config overrides defaults)
                config = self._deep_merge(self.DEFAULT_CONFIG.copy(), loaded_config or {})
                
                print(f"Configuration loaded from {self.config_path}")
                return config
                
            except Exception as e:
                print(f"Warning: Could not load config from {self.config_path}: {e}")
                print("Using default configuration")
                return self.DEFAULT_CONFIG.copy()
        else:
            print(f"Config file {self.config_path} not found. Using defaults.")
            return self.DEFAULT_CONFIG.copy()
    
    def _deep_merge(self, base: Dict, override: Dict) -> Dict:
        """Recursively merge override dict into base dict."""
        result = base.copy()
        
        for key, value in override.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = self._deep_merge(result[key], value)
            else:
                result[key] = value
        
        return result
    
    def get(self, *keys, default=None):
        """Get nested configuration value."""
        value = self.config
        
        for key in keys:
            if isinstance(value, dict) and key in value:
                value = value[key]
            else:
                return default
        
        return value
    
    def get_risk_weights(self) -> Dict[str, float]:
        """Get module risk weights."""
        return self.config['risk_weights']
    
    def get_decision_thresholds(self) -> Dict[str, float]:
        """Get decision thresholds."""
        return self.config['decision_thresholds']
    
    def get_intent_risk_floors(self) -> Dict[str, float]:
        """Get intent-based minimum risk scores."""
        return self.config['intent_risk_floors']
    
    def get_baseline_risks(self) -> Dict[str, float]:
        """Get baseline risks for content types."""
        return self.config['baseline_risks']
    
    def is_feature_enabled(self, feature: str) -> bool:
        """Check if a feature is enabled."""
        return self.config.get('features', {}).get(feature, False)
    
    def get_parallel_execution_enabled(self) -> bool:
        """Check if parallel execution is enabled."""
        return self.config.get('performance', {}).get('parallel_execution', True)
    
    def get_max_workers(self) -> int:
        """Get max workers for parallel execution."""
        return self.config.get('performance', {}).get('max_workers', 5)


# Global config instance
_config_instance = None


def get_config() -> ConfigLoader:
    """Get global configuration instance."""
    global _config_instance
    
    if _config_instance is None:
        _config_instance = ConfigLoader()
    
    return _config_instance


def reload_config(config_path: str = "config.yaml"):
    """Reload configuration from file."""
    global _config_instance
    _config_instance = ConfigLoader(config_path)
    return _config_instance