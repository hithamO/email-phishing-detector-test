import json
from typing import Dict
import textwrap
import logging

logger = logging.getLogger(__name__)

def print_ai_analysis(ai_data: Dict) -> None:
    """Print AI analysis results with updated fields"""
    if not ai_data:
        print("❌ No AI analysis available")
        return
    
    verdict = ai_data.get('verdict', 'UNKNOWN').upper()
    confidence = float(ai_data.get('confidence', 0)) * 100
    phishing_score = ai_data.get('phishing_score', 0)
    brands = ai_data.get('brands', 'None')
    phishing = ai_data.get('phishing', None)
    suspicious_domain = ai_data.get('suspicious_domain', None)
    verdict_color = '\033[91m' if verdict in ['SUSPICIOUS', 'MALICIOUS'] else '\033[92m' if verdict == 'CLEAN' else '\033[93m'
    
    print(f"\n{verdict_color}┌{'─'*78}┐")
    print(f"│{' FINAL VERDICT (Including VirusTotal Data) ':^78}│")
    print(f"│{verdict_color}{verdict:^78}\033[0m│")
    print(f"│{' Confidence: ':<39}{confidence:.1f}%{' ':>38}│")
    print(f"│{' Phishing Score (0-10): ':<39}{phishing_score}{' ':>38}│")
    print(f"└{'─'*78}┘\033[0m")
    
    print(f"\n\033[1mDETAILS:\033[0m")
    print(f"  Identified Brand: {brands}")
    print(f"  Phishing: {'Yes' if phishing is True else 'No' if phishing is False else 'Unknown'}")
    print(f"  Suspicious Domain: {'Yes' if suspicious_domain is True else 'No' if suspicious_domain is False else 'Unknown'}")
    
    if ai_data.get('VirusTotal'):
        vt = ai_data['VirusTotal']
        print(f"\n\033[1mVIRUSTOTAL SUMMARY:\033[0m")
        print(f"  Total Malicious Detections: {vt.get('malicious_count', 0)}")
        print(f"  Total Suspicious Detections: {vt.get('suspicious_count', 0)}")
        print(f"  Malicious IPs: {vt.get('IP_scan', 0)}")
        print(f"  Malicious URLs: {vt.get('URL_scan', 0)}")
        print(f"  Malicious Attachments: {vt.get('attachment_scan', 0)}")
    
    explanation = ai_data.get('explanation', 'No explanation provided')
    print(f"\n\033[1mANALYSIS FINDINGS:\033[0m")
    print(textwrap.fill(explanation, width=80, initial_indent='  ', subsequent_indent='  '))
    
    if ai_data.get('indicators'):
        print(f"\n\033[91m\033[1m🚩 RED FLAGS DETECTED:\033[0m")
        for i, indicator in enumerate(ai_data['indicators'], 1):
            print(f"  {i}. {indicator}")
    
    if ai_data.get('recommendations'):
        print(f"\n\033[92m\033[1m🛡️ RECOMMENDED ACTIONS:\033[0m")
        for i, recommendation in enumerate(ai_data['recommendations'], 1):
            print(f"  {i}. {recommendation}")

def generate_report(results: Dict, verbose: bool = False) -> None:
    """Generate complete analysis report including VirusTotal results"""
    print(f"\n{' Email Analysis Report ':=^60}")
    print(f"📄 File: {results['Information'].get('Filename', 'Unknown')}")
    print(f"📅 Date: {results['Information'].get('AnalysisDate', 'Unknown')}")
    print(f"🔍 Status: {results['Information'].get('Status', 'Unknown')}")
    print(f"{'':=^60}")

    headers = results["Analysis"].get("Headers", {})
    if headers:
        print(f"\n{' Headers ':-^60}")
        print(f"From: {headers.get('Data', {}).get('from', 'N/A')}")
        print(f"To: {headers.get('Data', {}).get('to', 'N/A')}")
        print(f"Subject: {headers.get('Data', {}).get('subject', 'N/A')}")
        print(f"Date: {headers.get('Data', {}).get('date', 'N/A')}")
        
        if headers.get("SecurityChecks"):
            print(f"\n🔒 Security Checks:")
            checks = headers["SecurityChecks"]
            print(f"  SPF: {'✅ Pass' if checks.get('spf') else '❌ Fail'}")
            print(f"  DKIM: {'✅ Pass' if checks.get('dkim') else '❌ Fail'}")
            print(f"  DMARC: {'✅ Pass' if checks.get('dmarc') else '❌ Fail'}")
            print(f"  Reply-To Spoofing: {'⚠️ Detected' if checks.get('reply_to_spoofing') else '✅ Clean'}")
        
        if headers.get("VirusTotal", {}).get("ip_results"):
            print(f"\n🔍 VirusTotal IP Results:")
            for ip, result in headers["VirusTotal"]["ip_results"].items():
                if "error" in result:
                    print(f"  {ip}: Error - {result['error']}")
                else:
                    stats = result.get("attributes", {}).get("last_analysis_stats", {})
                    print(f"  {ip}: Malicious: {stats.get('malicious', 0)}, Suspicious: {stats.get('suspicious', 0)}")

    body = results["Analysis"].get("Body", {})
    if body:
        print(f"\n{' Content ':-^60}")
        print(f"Text Length: {len(body.get('text', ''))} characters")
        print(f"HTML Content: {'✅ Present' if body.get('html') else '❌ Absent'}")
        if body.get("security_flags"):
            print(f"\n🚩 Security Flags Detected:")
            for flag in body["security_flags"]:
                print(f"  - {flag.replace('_', ' ').title()}")

    links = body.get("links", {}).get("Data", {})
    if links:
        print(f"\n{' Links ':-^60}")
        for i, link in links.items():
            print(f"{i}. {link[:80]}{'...' if len(link) > 80 else ''}")
        if body["links"].get("VirusTotal"):
            print(f"\n🔍 VirusTotal URL Results:")
            for i, result in body["links"]["VirusTotal"].items():
                if "error" in result:
                    print(f"  Link {i}: Error - {result['error']}")
                else:
                    stats = result.get("attributes", {}).get("last_analysis_stats", {})
                    print(f"  Link {i}: Malicious: {stats.get('malicious', 0)}, Suspicious: {stats.get('suspicious', 0)}")

    attachments = results["Analysis"].get("Attachments", {}).get("Data", {})
    if attachments:
        print(f"\n{' Attachments ':-^60}")
        for name, info in attachments.items():
            if isinstance(info, dict) and "error" not in info:
                print(f"- {name} ({info.get('size', 0)} bytes, {info.get('content_type', 'unknown')})")
            else:
                print(f"- {name} (Error processing)")
        if results["Analysis"]["Attachments"].get("VirusTotal"):
            print(f"\n🔍 VirusTotal Attachment Results:")
            for name, result in results["Analysis"]["Attachments"]["VirusTotal"].items():
                if "error" in result:
                    print(f"  {name}: Error - {result['error']}")
                else:
                    stats = result.get("attributes", {}).get("last_analysis_stats", {})
                    print(f"  {name}: Malicious: {stats.get('malicious', 0)}, Suspicious: {stats.get('suspicious', 0)}")

    if "AI_Analysis" in results["Analysis"]:
        print_ai_analysis(results["Analysis"]["AI_Analysis"])