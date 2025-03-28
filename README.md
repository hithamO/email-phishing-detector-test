# Email Phishing Detector

A Python-based tool to analyze email files (`.eml`, `.msg`) for phishing threats using security checks, VirusTotal API, and AI analysis via DeepSeek.

## Features

- **Header Analysis**: Checks SPF, DKIM, DMARC, and Reply-To spoofing.
- **Body Analysis**: Detects suspicious content (e.g., urgency phrases, obfuscated links).
- **Attachment Analysis**: Generates hashes and checks them with VirusTotal.
- **VirusTotal Integration**: Real-time scanning of IPs, URLs, and file hashes.
- **AI Analysis**: Uses DeepSeek (via OpenRouter) to provide a verdict based on all analysis data, including VirusTotal results.
- **Reporting**: Detailed console output and JSON export.

## Requirements

- Python 3.8+
- Dependencies listed in `requirements.txt`
- API Keys:
  - **VirusTotal API Key** (free tier available at [VirusTotal](https://www.virustotal.com))
  - **OpenRouter API Key** (for AI analysis, available at [OpenRouter](https://openrouter.ai))

## Installation

### 1. Clone the Repository

```sh
git clone https://github.com/yourusername/email-phishing-detector.git
cd email-phishing-detector
```

### 2. Install Dependencies

```sh
pip install -r requirements.txt
```

### 3. Set Environment Variables

#### On Windows

```sh
set VIRUSTOTAL_API_KEY=your_virustotal_api_key
set OPENROUTER_API_KEY=your_openrouter_api_key
```

#### On Unix/Linux

```sh
export VIRUSTOTAL_API_KEY=your_virustotal_api_key
export OPENROUTER_API_KEY=your_openrouter_api_key
```

## Usage

Run the tool with an email file:

```sh
python main.py -f path/to/email.eml --ai -o report.json
```

### Command-line Arguments

- `-f`: Path to the email file (required).
- `--ai`: Enable AI analysis with DeepSeek (optional).
- `-o`: Output JSON file path (optional).
- `-v`: Verbose output (optional).

## Project Structure

```
email_phishing_detector/
├── config/
│   └── config.py          # Configuration settings
├── src/
│   ├── __init__.py
│   ├── email_parser.py    # Email file parsing
│   ├── security_analyzer.py # Security and VirusTotal analysis
│   ├── ai_integration.py  # DeepSeek AI integration
│   └── report_generator.py # Report generation
├── main.py                # Entry point
├── requirements.txt       # Dependencies
├── .gitignore             # Git ignore rules
└── README.md              # This file
```

## Configuration

- `VIRUSTOTAL_API_KEY`: VirusTotal API key.
- `OPENROUTER_API_KEY`: OpenRouter API key for DeepSeek.
- `MAX_FILE_SIZE`: Maximum email file size (default: 10MB).
- `TIMEOUT`: API request timeouts.

## Notes

- **Rate Limits**: VirusTotal free tier allows 4 requests per minute. The script includes a 15-second delay to comply.
- **AI Analysis**: Requires an OpenRouter API key. Without it, only basic and VirusTotal analysis will run.
- **Error Handling**: Errors are logged; check logs for debugging.

## Contributing

1. Fork the repository.
2. Create a branch:
   ```sh
   git checkout -b feature-name
   ```
3. Commit changes:
   ```sh
   git commit -m "Add feature"
   ```
4. Push to GitHub:
   ```sh
   git push origin feature-name
   ```
5. Open a pull request.

---

# Email Phishing Detector - Technical Documentation

**Version:** 1.0\
**Author:** Haitham's Team

## 1. Code Overview

This Python script is a standalone email phishing detector that analyzes `.eml` and `.msg` files for security threats. It combines header analysis, content scanning, and AI-powered detection (via DeepSeek API) to identify phishing attempts.

### Key Features

✅ **Header Analysis**: Checks SPF, DKIM, DMARC authentication, and reply-to spoofing\
✅ **Content Scanning**: Detects suspicious links, urgency language, and obfuscated URLs\
✅ **Attachment Analysis**: Extracts file metadata and generates hashes (MD5, SHA1, SHA256)\
✅ **AI Integration**: Uses DeepSeek AI to evaluate phishing risk\
✅ **Reporting**: Console output + JSON export

## 2. Relationship to EmailAnalyzer

🚫 **This tool does NOT use EmailAnalyzer (GitHub tool).** It is an independent implementation with:

- **Similarities:** Both tools analyze email headers and attachments.
- **Differences:** This version adds AI analysis and real-time threat scoring.

*(If you want to integrate EmailAnalyzer, modifications will be needed to call its functions.)*

## 3. Code Structure

### A. Core Functions

| Function                  | Purpose                                                        |
| ------------------------- | -------------------------------------------------------------- |
| `analyze_email_headers()` | Checks SPF, DKIM, DMARC + detects reply-to spoofing            |
| `analyze_email_body()`    | Extracts text/HTML content, flags urgency/IP addresses         |
| `extract_links()`         | Identifies URLs + generates VirusTotal/URLScan.io lookup links |
| `analyze_attachments()`   | Processes attachments + generates file hashes                  |
| `analyze_with_ai()`       | Sends data to DeepSeek API for phishing verdict                |

### B. Workflow

**1. Input Validation → 2. Header/Body Analysis → 3. AI Evaluation → 4. Report Generation**

## 4. Critical Security Checks

| Check                 | Method Used                       | Example Output               |
| --------------------- | --------------------------------- | ---------------------------- |
| **SPF/DKIM/DMARC**    | Parses Authentication-Results     | ✅ SPF Pass / ❌ DKIM Fail     |
| **Reply-To Spoofing** | Compares From vs. Reply-To        | ⚠️ Detected                  |
| **Suspicious Links**  | Regex + URL defanging             | goo00000gle.com → Phishing   |
| **Urgency Detection** | Keyword matching (urgent, verify) | 🚩 Urgency Language Detected |

---

This documentation provides a structured guide to the **Email Phishing Detector**, including setup, usage, and technical insights. Contributions and suggestions are welcome!

