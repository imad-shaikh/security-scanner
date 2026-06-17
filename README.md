# AI Security Scanner

AI Security Scanner is a beginner-friendly Python CLI tool that uses Gemini to review Python source files for common security vulnerabilities. It scans individual files or directories, classifies findings by severity, and can generate clean terminal, Markdown, or JSON reports.

## Features

- Scan one Python file or every `.py` file in a directory.
- Gemini-powered vulnerability analysis with structured findings.
- Color-coded terminal severity output.
- Markdown reports suitable for demos and portfolio screenshots.
- JSON reports for structured output and future automation.
- Graceful handling for missing files, missing API keys, and API errors.

## Tech Stack

- Python 3
- argparse and pathlib from the Python standard library
- Gemini via `google-generativeai`
- `python-dotenv` for local environment variables
- `colorama` for terminal colors

## Setup

Clone the project, create a virtual environment, and install dependencies:

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

Create a `.env` file in the project root:

```bash
GOOGLE_API_KEY=your_api_key_here
```

Do not commit `.env`. The project `.gitignore` excludes it.

## Usage

Show CLI help:

```bash
python3 scanner.py --help
```

Scan a single file:

```bash
python3 scanner.py scan examples/sql_injection.py
```

Scan a directory:

```bash
python3 scanner.py scan examples/
```

Write a Markdown report:

```bash
python3 scanner.py scan examples/ --output reports/security_report.md
```

Write a JSON report:

```bash
python3 scanner.py scan examples/ --format json --output reports/security_report.json
```

Print Markdown to the terminal:

```bash
python3 scanner.py scan examples/ --format markdown
```

## Example Output

```text
AI Security Scanner Results
============================

File: examples/sql_injection.py
  1. [HIGH] SQL Injection
     Description: User input is concatenated directly into a SQL query.
     Impact: An attacker could alter the query and read or modify data.
     Fix: Use parameterized queries instead of string concatenation.
     Reference: query = "SELECT * FROM users WHERE username = '" + username + "'"
```

## Project Structure

```text
security-scanner/
├── scanner.py
├── examples/
│   ├── command_injection.py
│   ├── hardcoded_secret.py
│   ├── insecure_file_handling.py
│   ├── sql_injection.py
│   └── weak_hashing.py
├── reports/
│   └── .gitkeep
├── README.md
├── PORTFOLIO_WRITEUP.md
├── requirements.txt
└── .gitignore
```

## Future Improvements

- Add optional rule-based checks before calling Gemini.
- Support more programming languages.
- Add a test suite for CLI behavior and report generation.
- Add severity filtering and baseline comparison.
- Build a lightweight web dashboard after the CLI is stable.

## Security Note

This project is an educational developer tool, not a replacement for professional security review, static analysis, or penetration testing. AI-generated findings should be reviewed carefully before being treated as confirmed vulnerabilities.
