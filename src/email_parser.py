import os
import re
from email import message_from_string, policy
from typing import Dict
import logging

from config.config import CONFIG

logger = logging.getLogger(__name__)

class EmailAnalysisError(Exception):
    pass

def validate_email_file(file_path: str) -> None:
    """Validate the input email file"""
    if not os.path.exists(file_path):
        raise EmailAnalysisError(f"File not found: {file_path}")
    if not os.path.isfile(file_path):
        raise EmailAnalysisError(f"Path is not a file: {file_path}")
    if os.path.getsize(file_path) > CONFIG.get("MAX_FILE_SIZE"):
        raise EmailAnalysisError(f"File too large (>{CONFIG.get('MAX_FILE_SIZE')//(1024*1024)}MB)")
    if not any(file_path.lower().endswith(ext) for ext in CONFIG.get("SUPPORTED_FILES")):
        raise EmailAnalysisError(f"Unsupported file type. Supported: {CONFIG.get('SUPPORTED_FILES')}")

def parse_email(file_path: str) -> Dict:
    """Parse email file and return structured data"""
    validate_email_file(file_path)
    
    try:
        with open(file_path, 'rb') as f:
            raw_content = f.read().decode('utf-8', errors='replace')
            msg = message_from_string(raw_content, policy=policy.default)
            
        return {
            "message": msg,
            "filename": os.path.basename(file_path),
            "raw_content": raw_content
        }
    except Exception as e:
        logger.error(f"Failed to parse email: {e}")
        raise EmailAnalysisError(f"Email parsing failed: {e}")