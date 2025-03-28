import os
from typing import Dict, List

class Config:
    """Configuration management with validation"""
    
    DEFAULTS: Dict = {
        "API_URL": "https://openrouter.ai/api/v1/chat/completions",
        "API_KEY": os.getenv("OPENROUTER_API_KEY", ""),
        "MODEL": "deepseek/deepseek-chat",
        "SUPPORTED_FILES": [".eml", ".msg"],
        "DATE_FORMAT": "%Y-%m-%d %H:%M:%S",
        "MAX_FILE_SIZE": 10 * 1024 * 1024,  # 10MB
        "USER_AGENT": "EmailPhishingDetector/1.0",
        "TIMEOUT": (10, 30),  # Connect timeout, read timeout
        "MAX_TOKENS": 2000,
        "TEMPERATURE": 0.2,
        "VIRUSTOTAL_API_KEY": os.getenv("VIRUSTOTAL_API_KEY", "")
    }

    def __init__(self, overrides: Dict = None):
        self.config = self.DEFAULTS.copy()
        if overrides:
            self.config.update(overrides)
        self.validate()

    def validate(self) -> None:
        """Validate configuration parameters"""
        if not isinstance(self.config["SUPPORTED_FILES"], list):
            raise ValueError("SUPPORTED_FILES must be a list")
        if not all(isinstance(ext, str) for ext in self.config["SUPPORTED_FILES"]):
            raise ValueError("SUPPORTED_FILES must contain strings")
        if not isinstance(self.config["MAX_FILE_SIZE"], int) or self.config["MAX_FILE_SIZE"] <= 0:
            raise ValueError("MAX_FILE_SIZE must be a positive integer")
        if not isinstance(self.config["TIMEOUT"], tuple) or len(self.config["TIMEOUT"]) != 2:
            raise ValueError("TIMEOUT must be a tuple of two numbers")
        if not isinstance(self.config["VIRUSTOTAL_API_KEY"], str):
            raise ValueError("VIRUSTOTAL_API_KEY must be a string")

    def get(self, key: str, default=None):
        """Get configuration value"""
        return self.config.get(key, default)

CONFIG = Config()