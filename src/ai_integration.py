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
        "content": f"""You are a web programmer and security expert tasked with examining an email to determine if it is a phishing attempt or a legitimate communication. To complete this task, follow these sub-tasks:

1. Analyze the HTML (in 'Body.html'), URLs (in 'Body.links.Data'), and text content (in 'Body.text') for any social engineering techniques often used in phishing attacks. Point out any suspicious elements found in the HTML, URLs, or text.
2. Identify the brand name from the email (in 'Headers' or 'Body'). If the HTML or text appears to resemble a legitimate brand's communication, verify if the URLs (in 'Body.links.Data') match the legitimate domain name associated with the brand, if known.
3. Evaluate VirusTotal results (under 'VirusTotal' keys in 'Headers', 'Body.links', and 'Attachments'). Use these weights: high malicious counts (>3) strongly indicate phishing (weight: 0.8), moderate counts (1-3) suggest suspicion (weight: 0.5), zero counts indicate clean (weight: 0.1), and errors or missing data are neutral (weight: 0.0). Combine this with your analysis from steps 1 and 2, include security check results from 'Headers.SecurityChecks' (SPF, DKIM, DMARC, reply_to_spoofing) in your reasoning to state your conclusion on whether the email is a phishing attempt, legitimate, or unknown, and explain your reasoning.
4. Submit your findings as JSON-formatted output with the following keys:
   - phishing_score: int (indicates phishing risk on a scale of 0 to 10)
   - brands: str (identified brand name or None if not applicable)
   - phishing: boolean (True if phishing, False if legitimate, None if unknown)
   - suspicious_domain: boolean (True if domain is suspect, False if not, None if unknown)
   - verdict: str (malicious, suspicious, or clean)
   - confidence: float (between 0-1)
   - explanation: str (detailed analysis including VirusTotal impact. write this as if speaking directly to the user in a friendly, educated tone—e.g., 'Hey there! Here’s what we found...'. Explain the findings clearly, including why VirusTotal might not flag something malicious if counts are zero, such as new threats or evasion tactics. Tailor it to the email’s specific context.))
   - indicators: list (list all suspicious elements, including failed SPF, DKIM, DMARC, domain mismatches, and social engineering tactics identified)
   - recommendations: list (suggested actions)
   - VirusTotal: dict (malicious_count: int, suspicious_count: int, IP_scan: int, URL_scan: int, attachment_scan: int)

Limitations:
- The HTML may be shortened and simplified.
- The text content may contain encoding errors.
- VirusTotal results may have errors or incomplete data due to rate limits.

Examples of social engineering techniques:
- Alerting the user to a problem with their account
- Offering unexpected rewards
- Informing the user of a missing package or additional payment required
- Displaying fake security warnings

Email data:
{json.dumps(analysis_data, indent=2)}
"""
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
        required_fields = ["phishing_score", "brands", "phishing", "suspicious_domain", "verdict", "confidence", "explanation"]
        if not all(field in ai_response for field in required_fields):
            raise ValueError("Missing required fields in AI response")
            
        return ai_response
        
    except Exception as e:
        logger.error(f"AI analysis failed: {e}")
        return {"error": str(e)}