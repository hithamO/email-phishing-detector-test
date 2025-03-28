import re
import hashlib
import urllib.parse
from typing import Dict
import logging
from email.message import EmailMessage
import virustotal_python
from config.config import CONFIG
import time

logger = logging.getLogger(__name__)

def check_virustotal_ip(ip: str) -> Dict:
    """Check IP address with VirusTotal API"""
    if not CONFIG.get("VIRUSTOTAL_API_KEY"):
        logger.warning("VirusTotal API key not configured")
        return {"error": "API key not configured"}
    
    with virustotal_python.Virustotal(CONFIG.get("VIRUSTOTAL_API_KEY")) as vtotal:
        try:
            resp = vtotal.request(f"ip_addresses/{ip}")
            return resp.data
        except Exception as e:
            logger.error(f"VirusTotal IP check failed for {ip}: {e}")
            return {"error": str(e)}

def check_virustotal_url(url: str) -> Dict:
    """Check URL with VirusTotal API, polling until analysis is complete"""
    if not CONFIG.get("VIRUSTOTAL_API_KEY"):
        logger.warning("VirusTotal API key not configured")
        return {"error": "API key not configured"}
    
    with virustotal_python.Virustotal(CONFIG.get("VIRUSTOTAL_API_KEY")) as vtotal:
        try:
            # Submit URL for analysis
            resp = vtotal.request("urls", data={"url": url}, method="POST")
            analysis_id = resp.data["id"]
            
            # Poll for analysis results (max 5 attempts, 5 seconds apart)
            for _ in range(5):
                analysis_resp = vtotal.request(f"analyses/{analysis_id}")
                status = analysis_resp.data.get("attributes", {}).get("status", "queued")
                if status == "completed":
                    return analysis_resp.data
                time.sleep(5)  # Wait before next check
            logger.warning(f"VirusTotal URL analysis for {url} timed out")
            return {"error": "Analysis timeout"}
        except Exception as e:
            logger.error(f"VirusTotal URL check failed for {url}: {e}")
            return {"error": str(e)}

def check_virustotal_file_hash(hash: str) -> Dict:
    """Check file hash with VirusTotal API"""
    if not CONFIG.get("VIRUSTOTAL_API_KEY"):
        logger.warning("VirusTotal API key not configured")
        return {"error": "API key not configured"}
    
    with virustotal_python.Virustotal(CONFIG.get("VIRUSTOTAL_API_KEY")) as vtotal:
        try:
            resp = vtotal.request(f"files/{hash}")
            return resp.data
        except Exception as e:
            logger.error(f"VirusTotal file check failed for {hash}: {e}")
            return {"error": str(e)}

def analyze_headers(msg: EmailMessage) -> Dict:
    """Analyze email headers with security checks and VirusTotal"""
    headers = {"Data": {}, "SecurityChecks": {}, "Investigation": {}, "VirusTotal": {}}
    
    for header, value in msg.items():
        headers["Data"][header.lower()] = value.strip()
    
    auth_results = headers["Data"].get("authentication-results", "").lower()
    headers["SecurityChecks"] = {
        "spf": "spf=pass" in auth_results,
        "dkim": "dkim=pass" in auth_results,
        "dmarc": "dmarc=pass" in auth_results,
        "reply_to_spoofing": check_reply_to_spoofing(headers["Data"])
    }
    
    if "received" in headers["Data"]:
        ip_addresses = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', headers["Data"]["received"])
        if ip_addresses:
            headers["Investigation"]["ip_lookup"] = [
                f"https://www.virustotal.com/gui/ip-address/{ip}" 
                for ip in ip_addresses
            ]
            headers["VirusTotal"]["ip_results"] = {}
            for ip in ip_addresses:
                headers["VirusTotal"]["ip_results"][ip] = check_virustotal_ip(ip)
                time.sleep(15)  # Basic rate limiting: 4 requests/minute = 15s delay
    
    return headers

def check_reply_to_spoofing(headers: Dict) -> bool:
    """Check if From and Reply-To addresses mismatch"""
    from_addr = headers.get("from", "")
    reply_to = headers.get("reply-to", "")
    if not from_addr or not reply_to:
        return False
    from_email = extract_email(from_addr)
    reply_email = extract_email(reply_to)
    return from_email != reply_email if (from_email and reply_email) else False

def extract_email(header: str) -> str:
    """Extract email address from header"""
    match = re.search(r'<([^>]+)>', header)
    return match.group(1).lower() if match else header.lower()

def analyze_body(msg: EmailMessage) -> Dict:
    """Extract and analyze email body content with VirusTotal"""
    body = {"text": "", "html": "", "links": {"Data": {}, "Investigation": {}, "VirusTotal": {}}, "security_flags": []}
    
    if msg.is_multipart():
        for part in msg.walk():
            if "attachment" not in str(part.get_content_disposition()):
                process_part(part, body)
    else:
        process_part(msg, body)
    
    body["security_flags"] = detect_suspicious_content(body["text"] or body["html"])
    body["links"] = extract_links(body["text"] + body["html"])
    
    return body

def process_part(part, body: Dict) -> None:
    """Process individual email part"""
    try:
        content_type = part.get_content_type()
        payload = part.get_payload(decode=True)
        if payload:
            charset = part.get_content_charset() or 'utf-8'
            decoded = payload.decode(charset, errors='replace')
            if content_type == "text/plain":
                body["text"] += decoded
            elif content_type == "text/html":
                body["html"] += decoded
    except Exception as e:
        logger.warning(f"Failed to decode part: {e}")

def detect_suspicious_content(content: str) -> list:
    """Detect potential phishing indicators"""
    flags = []
    urgency_phrases = ["urgent", "immediate action", "required", "account suspended",
                      "verify now", "limited time", "click below"]
    
    if any(phrase.lower() in content.lower() for phrase in urgency_phrases):
        flags.append("urgency_language")
    if re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', content):
        flags.append("ip_address_in_content")
    if "@http" in content.lower() or "@https" in content.lower():
        flags.append("obfuscated_link")
    return flags

def extract_links(content: str) -> Dict:
    """Extract and analyze links from content with VirusTotal"""
    links = {"Data": {}, "Investigation": {}, "VirusTotal": {}}
    
    url_pattern = r'(https?://[^\s<>"\']+|www\.[^\s<>"\']+|\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b|href\s*=\s*["\'][^"\']+["\'])'
    found_links = re.findall(url_pattern, content)
    
    for i, raw_link in enumerate(set(found_links), 1):
        link = re.sub(r'^href\s*=\s*["\']|["\']$', '', raw_link) if raw_link.startswith('href=') else raw_link
        links["Data"][str(i)] = link
        if link.startswith(('http', 'www')):
            clean_link = urllib.parse.quote(link.split('://')[-1] if '://' in link else link)
            links["Investigation"][str(i)] = {
                "virustotal": f"https://www.virustotal.com/gui/search/{clean_link}",
                "urlscan": f"https://urlscan.io/search/#{clean_link}"
            }
            links["VirusTotal"][str(i)] = check_virustotal_url(link)
            time.sleep(15)  # Basic rate limiting: 4 requests/minute = 15s delay
    
    return links

def analyze_attachments(msg: EmailMessage) -> Dict:
    """Analyze email attachments with VirusTotal"""
    attachments = {"Data": {}, "Investigation": {}, "VirusTotal": {}}
    
    for part in msg.walk():
        if part.get_content_disposition() == 'attachment':
            filename = part.get_filename()
            if filename:
                try:
                    payload = part.get_payload(decode=True)
                    if payload:
                        file_info = {
                            "size": len(payload),
                            "content_type": part.get_content_type(),
                            "hashes": generate_hashes(payload)
                        }
                        attachments["Data"][filename] = file_info
                        attachments["Investigation"][filename] = {
                            "virustotal": f"https://www.virustotal.com/gui/search/{file_info['hashes']['sha256']}",
                            "file_analysis": f"https://www.hybrid-analysis.com/search?query={file_info['hashes']['sha256']}"
                        }
                        attachments["VirusTotal"][filename] = check_virustotal_file_hash(file_info['hashes']['sha256'])
                        time.sleep(15)  # Basic rate limiting: 4 requests/minute = 15s delay
                except Exception as e:
                    logger.warning(f"Failed to process attachment {filename}: {e}")
                    attachments["Data"][filename] = {"error": str(e)}
    
    return attachments

def generate_hashes(data: bytes) -> Dict:
    """Generate cryptographic hashes"""
    return {
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest()
    }