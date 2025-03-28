import json
import requests
from typing import Dict
import logging

from config.config import CONFIG

logger = logging.getLogger(__name__)

def analyze_with_ai(analysis_data: Dict) -> Dict:
    """Send analysis data to AI for evaluation, including VirusTotal results"""
    if not CONFIG.get("API_KEY"):
        logger.error("API key not configured")
        return {"error": "API key not configured"}
    
    prompt = {
        "role": "user",
        "content": f"""Analyze this email for security threats. Provide JSON with:
        - verdict: "malicious", "suspicious", or "clean"
        - confidence: float between 0-1
        - explanation: detailed analysis
        - indicators: list of suspicious elements
        - recommendations: suggested actions
        
        Incorporate VirusTotal results (under "VirusTotal" keys) in your analysis, 
        considering malicious and suspicious counts from IP, URL, and attachment scans.
        
        Email data: {json.dumps(analysis_data, indent=2)}"""
    }

    headers = {
        "Authorization": f"Bearer {CONFIG.get('API_KEY')}",
        "Content-Type": "application/json",
        "User-Agent": CONFIG.get("USER_AGENT")
    }

    payload = {
        "model": CONFIG.get("MODEL"),
        "messages": [prompt],
        "temperature": CONFIG.get("TEMPERATURE"),
        "max_tokens": CONFIG.get("MAX_TOKENS"),
        "response_format": {"type": "json_object"}
    }

    try:
        response = requests.post(
            CONFIG.get("API_URL"),
            headers=headers,
            json=payload,
            timeout=CONFIG.get("TIMEOUT")
        )
        response.raise_for_status()
        
        result = response.json()
        if not result.get("choices"):
            raise ValueError("Invalid API response - no choices")
            
        message_content = result["choices"][0]["message"]["content"]
        if message_content.startswith("```json"):
            message_content = message_content[7:-3]
            
        ai_response = json.loads(message_content)
        required_fields = ["verdict", "confidence", "explanation"]
        if not all(field in ai_response for field in required_fields):
            raise ValueError("Missing required fields in AI response")
            
        return ai_response
        
    except Exception as e:
        logger.error(f"AI analysis failed: {e}")
        return {"error": str(e)}