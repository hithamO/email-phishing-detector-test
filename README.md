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
**Author:** Haitham



## Code Structure

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

## Critical Security Checks

| Check                 | Method Used                       | Example Output               |
| --------------------- | --------------------------------- | ---------------------------- |
| **SPF/DKIM/DMARC**    | Parses Authentication-Results     | ✅ SPF Pass / ❌ DKIM Fail     |
| **Reply-To Spoofing** | Compares From vs. Reply-To        | ⚠️ Detected                  |
| **Suspicious Links**  | Regex + URL defanging             | goo00000gle.com → Phishing   |
| **Urgency Detection** | Keyword matching (urgent, verify) | 🚩 Urgency Language Detected |

---

## Example output (with colors in terminal):

┌──────────────────────────────────────────────────────────────────────────────┐
│                                FINAL VERDICT                                 │
│                                SUSPICIOUS                                    │
│ Confidence: 75.0%                                                            │
└──────────────────────────────────────────────────────────────────────────────┘

ANALYSIS FINDINGS:
  The email appears to be a phishing attempt due to several suspicious elements.
  The sender's email address 'hhiitthhaamm12345666@gmail.com' is unusual and
  resembles a randomly generated address. The email content urges the recipient
  to verify their account details by clicking on a link, which is a common tactic
  used in phishing attacks. The link provided 'http://google.com/' appears to be
  a legitimate Google URL, but the display text 'goo00000gle.com' is suspicious
  and could be an attempt to deceive the recipient. The email also uses a sense
  of urgency by threatening account suspension within 24 hours, which is a common
  phishing tactic. However, the email passes SPF, DKIM, and DMARC checks, which
  adds some legitimacy to it. The absence of malicious attachments and the use of
  a legitimate URL reduce the likelihood of it being outright malicious, but the
  overall context and suspicious elements make it highly suspicious.

🚩 RED FLAGS DETECTED:
  1. Unusual sender email address: 'hhiitthhaamm12345666@gmail.com'
  2. Suspicious display text for the link: 'goo00000gle.com'
  3. Urgent call to action with a threat of account suspension
  4. Email content resembles a phishing attempt

🛡️ RECOMMENDED ACTIONS:
  1. Do not click on any links in the email.
  2. Verify the legitimacy of the email by contacting the supposed sender through
     official channels.
  3. Report the email as phishing to your email provider.
  4. Consider enabling two-factor authentication on your accounts for added
     security.

================================================================================
Note: This analysis is automated. Always use human judgment for final decisions.
================================================================================

## FAQ
Q: Can this analyze emails directly from Gmail?
→ Not currently. You’d need to download emails as .eml first.

Q: Is the AI analysis free?
→ Yes (via OpenRouter free tier), but has rate limits.

Q: How accurate is the detection?
→ ~85-90% for obvious phishing; AI improves subtle cases.

## References
EmailAnalyzer (Alternative tool)

OpenRouter API Docs
