import sys
import logging
from datetime import datetime
from argparse import ArgumentParser
import json

from config.config import CONFIG
from src.email_parser import parse_email
from src.security_analyzer import analyze_headers, analyze_body, analyze_attachments, generate_hashes
from src.ai_integration import analyze_with_ai
from src.report_generator import generate_report

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def analyze_email(file_path: str, use_ai: bool = False) -> dict:
    """Main email analysis function"""
    results = {
        "Information": {
            "Filename": "",
            "AnalysisDate": datetime.now().strftime(CONFIG.get("DATE_FORMAT")),
            "Status": "Analysis started"
        },
        "Analysis": {}
    }

    try:
        email_data = parse_email(file_path)
        results["Information"]["Filename"] = email_data["filename"]
        
        results["Analysis"] = {
            "Headers": analyze_headers(email_data["message"]),
            "Body": analyze_body(email_data["message"]),
            "Attachments": analyze_attachments(email_data["message"]),
            "FileHashes": generate_hashes(email_data["raw_content"].encode('utf-8'))
        }
        
        if use_ai:
            ai_result = analyze_with_ai(results["Analysis"])
            results["Analysis"]["AI_Analysis"] = ai_result
            logger.debug(f"AI Analysis Result: {json.dumps(ai_result, indent=2)}")
        
        results["Information"]["Status"] = "Analysis completed successfully"
    except Exception as e:
        logger.error(f"Analysis failed: {e}")
        results["Information"]["Status"] = f"Analysis failed: {e}"
    
    return results

def save_results(results: dict, output_path: str) -> None:
    """Save analysis results to JSON file"""
    try:
        with open(output_path, 'w') as f:
            json.dump(results, f, indent=2)
        logger.info(f"Results saved to {output_path}")
    except Exception as e:
        logger.error(f"Failed to save results: {e}")

def main():
    parser = ArgumentParser(description="Advanced Email Phishing Detector")
    parser.add_argument("-f", "--file", required=True, help="Email file to analyze")
    parser.add_argument("--ai", action="store_true", help="Enable AI analysis")
    parser.add_argument("-o", "--output", help="Output JSON file path")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    args = parser.parse_args()

    try:
        print(f"\n🔍 Analyzing email: {args.file}")
        if args.ai:
            print("🤖 AI analysis enabled")
        if CONFIG.get("VIRUSTOTAL_API_KEY"):
            print("🛡️ VirusTotal integration enabled")
        
        results = analyze_email(args.file, args.ai)
        generate_report(results, args.verbose)
        
        if args.output:
            save_results(results, args.output)
        
        sys.exit(0 if results["Information"]["Status"] == "Analysis completed successfully" else 1)
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()