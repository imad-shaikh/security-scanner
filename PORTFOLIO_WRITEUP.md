# AI Security Scanner

AI Security Scanner is an AI-powered Python CLI tool that scans source code for common security vulnerabilities, classifies severity, and generates structured Markdown or JSON reports with suggested fixes. I built it as a practical developer tool that is easy to run from the terminal and simple enough for other students to understand.

- Built a Gemini-powered scanner that reviews individual Python files or full directories.
- Designed structured security reports with severity, impact, vulnerable code references, and practical fixes.
- Added intentionally vulnerable examples for SQL injection, hardcoded secrets, weak hashing, command injection, and insecure file handling.

## Tech Stack

Python, argparse, pathlib, python-dotenv, google-generativeai, colorama

## What I Learned

I learned how to turn a basic script into a cleaner command line tool with argument parsing, report generation, environment-based configuration, and readable error handling. I also practiced writing prompts that produce structured output instead of long free-form responses.

## Demo Command

```bash
python3 scanner.py scan examples/ --output reports/security_report.md
```

## Resume Bullet

- Built an AI-powered Python CLI security scanner that analyzes source code with Gemini, classifies vulnerability severity, and generates structured Markdown and JSON reports with suggested fixes.
