"""AI-powered command line security scanner for Python files."""

from __future__ import annotations

import argparse
import json
import os
import sys
import warnings
from datetime import datetime
from pathlib import Path
from typing import Any

try:
    from colorama import Fore, Style, init

    init(autoreset=True)
except ImportError:  # Keep --help usable before dependencies are installed.
    class Fore:
        RED = ""
        YELLOW = ""
        BLUE = ""
        GREEN = ""

    class Style:
        BRIGHT = ""
        RESET_ALL = ""


MODEL_NAME = "gemini-2.5-flash"
API_TIMEOUT_SECONDS = 20
VALID_SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")
SKIPPED_DIRS = {".git", ".venv", "venv", "__pycache__", "node_modules"}


class ScannerSetupError(Exception):
    """Raised when the scanner cannot be configured."""


def build_parser() -> argparse.ArgumentParser:
    """Build the command line parser."""
    parser = argparse.ArgumentParser(
        description="Scan Python source files for common security issues using Gemini."
    )
    subparsers = parser.add_subparsers(dest="command")

    scan_parser = subparsers.add_parser("scan", help="Scan a Python file or directory.")
    scan_parser.add_argument("path", type=Path, help="Python file or directory to scan.")
    scan_parser.add_argument(
        "--format",
        choices=("terminal", "markdown", "json"),
        default="terminal",
        help="Output format. Defaults to terminal; inferred from --output extension when possible.",
    )
    scan_parser.add_argument(
        "--output",
        "-o",
        type=Path,
        help="Optional report path, such as reports/security_report.md or reports/security_report.json.",
    )
    scan_parser.set_defaults(func=run_scan)
    return parser


def configure_gemini():
    """Load environment variables and create a Gemini model client."""
    try:
        from dotenv import load_dotenv
    except ImportError as exc:
        raise ScannerSetupError(
            "Missing dependency: python-dotenv. Install dependencies with 'pip install -r requirements.txt'."
        ) from exc

    try:
        with warnings.catch_warnings():
            warnings.filterwarnings("ignore", category=FutureWarning)
            import google.generativeai as genai
    except ImportError as exc:
        raise ScannerSetupError(
            "Missing dependency: google-generativeai. Install dependencies with 'pip install -r requirements.txt'."
        ) from exc

    load_dotenv()
    api_key = os.getenv("GOOGLE_API_KEY")
    if not api_key:
        raise ScannerSetupError(
            "GOOGLE_API_KEY is not set. Create a .env file with GOOGLE_API_KEY=your_api_key_here."
        )

    genai.configure(api_key=api_key)
    return genai.GenerativeModel(MODEL_NAME)


def collect_python_files(target: Path) -> list[Path]:
    """Return Python files from a file or directory target."""
    if not target.exists():
        raise FileNotFoundError(f"Path not found: {target}")

    if target.is_file():
        if target.suffix != ".py":
            raise ValueError(f"Expected a .py file, got: {target}")
        return [target]

    if not target.is_dir():
        raise ValueError(f"Path is not a file or directory: {target}")

    files: list[Path] = []
    for path in target.rglob("*.py"):
        if any(part in SKIPPED_DIRS for part in path.parts):
            continue
        files.append(path)

    return sorted(files)


def build_security_prompt(file_path: Path, code: str) -> str:
    """Create the prompt sent to Gemini for one file."""
    return f"""
You are a concise application security reviewer.
Analyze this single Python file for practical security vulnerabilities.

Return only valid JSON with this exact shape:
{{
  "findings": [
    {{
      "severity": "CRITICAL/HIGH/MEDIUM/LOW",
      "type": "Short vulnerability name",
      "description": "One or two sentences explaining the issue",
      "impact": "Practical risk if exploited",
      "fix": "Clear, practical fix",
      "code_reference": "Line number, function name, or short vulnerable snippet if possible"
    }}
  ]
}}

If there are no findings, return:
{{"findings": []}}

Keep fixes practical and concise. Do not include markdown or extra commentary.

File path: {file_path}

Code:
```python
{code}
```
""".strip()


def strip_json_fence(text: str) -> str:
    """Remove common markdown code fences around JSON."""
    cleaned = text.strip()
    if not cleaned.startswith("```"):
        return cleaned

    lines = cleaned.splitlines()
    if lines and lines[0].strip().startswith("```"):
        lines = lines[1:]
    if lines and lines[-1].strip().startswith("```"):
        lines = lines[:-1]
    return "\n".join(lines).strip()


def parse_gemini_response(text: str) -> list[dict[str, str]]:
    """Parse Gemini JSON into normalized finding dictionaries."""
    cleaned = strip_json_fence(text)
    try:
        data = json.loads(cleaned)
    except json.JSONDecodeError:
        start = cleaned.find("{")
        end = cleaned.rfind("}")
        if start == -1 or end == -1 or end <= start:
            raise
        data = json.loads(cleaned[start : end + 1])

    findings = data.get("findings", []) if isinstance(data, dict) else data
    if not isinstance(findings, list):
        raise ValueError("Gemini response did not include a findings list.")

    return [normalize_finding(item) for item in findings if isinstance(item, dict)]


def normalize_finding(item: dict[str, Any]) -> dict[str, str]:
    """Normalize one finding so reports always have consistent fields."""
    severity = str(item.get("severity", "LOW")).upper()
    if severity not in VALID_SEVERITIES:
        severity = "LOW"

    return {
        "severity": severity,
        "type": clean_value(item.get("type"), "Security Finding"),
        "description": clean_value(item.get("description"), "No description provided."),
        "impact": clean_value(item.get("impact"), "Impact not specified."),
        "fix": clean_value(item.get("fix"), "No fix provided."),
        "code_reference": clean_value(
            item.get("code_reference") or item.get("vulnerable_code_reference"),
            "Not specified.",
        ),
    }


def clean_value(value: Any, fallback: str) -> str:
    """Convert report values to readable single strings."""
    if value is None:
        return fallback
    text = str(value).strip()
    return text if text else fallback


def scan_file(model: Any, file_path: Path) -> dict[str, Any]:
    """Scan one Python file and return structured results."""
    try:
        code = file_path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return {
            "path": str(file_path),
            "findings": [],
            "error": "Could not read file as UTF-8 text.",
        }

    try:
        response = model.generate_content(
            build_security_prompt(file_path, code),
            request_options={"retry": None, "timeout": API_TIMEOUT_SECONDS},
        )
        response_text = getattr(response, "text", "").strip()
        findings = parse_gemini_response(response_text)
        return {"path": str(file_path), "findings": findings, "error": None}
    except Exception as exc:  # Gemini/API/parser failures should not crash the CLI.
        return {
            "path": str(file_path),
            "findings": [],
            "error": f"Gemini analysis failed: {exc}",
        }


def color_severity(severity: str) -> str:
    """Return a colorized severity label for terminal output."""
    colors = {
        "CRITICAL": Fore.RED + Style.BRIGHT,
        "HIGH": Fore.YELLOW + Style.BRIGHT,
        "MEDIUM": Fore.BLUE,
        "LOW": Fore.GREEN,
    }
    return f"{colors.get(severity, '')}{severity}{Style.RESET_ALL}"


def print_terminal_results(results: list[dict[str, Any]]) -> None:
    """Print scan findings in a readable terminal format."""
    print("\nAI Security Scanner Results")
    print("=" * 28)

    for result in results:
        print(f"\nFile: {result['path']}")
        if result.get("error"):
            print(f"  Error: {result['error']}")
            continue

        findings = result.get("findings", [])
        if not findings:
            print("  No findings reported.")
            continue

        for index, finding in enumerate(findings, start=1):
            severity = color_severity(finding["severity"])
            print(f"  {index}. [{severity}] {finding['type']}")
            print(f"     Description: {finding['description']}")
            print(f"     Impact: {finding['impact']}")
            print(f"     Fix: {finding['fix']}")
            print(f"     Reference: {finding['code_reference']}")


def build_report(results: list[dict[str, Any]]) -> dict[str, Any]:
    """Build the shared report structure used by JSON and Markdown output."""
    severity_counts = {severity: 0 for severity in VALID_SEVERITIES}
    total_findings = 0

    for result in results:
        for finding in result.get("findings", []):
            total_findings += 1
            severity = finding.get("severity", "LOW")
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

    return {
        "title": "AI Security Scanner Report",
        "generated_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "summary": {
            "files_scanned": len(results),
            "total_findings": total_findings,
            "scan_errors": sum(1 for result in results if result.get("error")),
            "severity_counts": severity_counts,
        },
        "files_scanned": [result["path"] for result in results],
        "results": results,
    }


def render_markdown_report(report: dict[str, Any]) -> str:
    """Render a polished Markdown report."""
    summary = report["summary"]
    lines = [
        "# AI Security Scanner Report",
        "",
        f"Generated: {report['generated_at']}",
        f"Files scanned: {summary['files_scanned']}",
        f"Total findings: {summary['total_findings']}",
        f"Scan errors: {summary['scan_errors']}",
        "",
        "## Severity Summary",
        "",
        "| Severity | Count |",
        "| --- | ---: |",
    ]

    for severity in VALID_SEVERITIES:
        lines.append(f"| {severity} | {summary['severity_counts'].get(severity, 0)} |")

    lines.extend(["", "## Findings by File", ""])

    for result in report["results"]:
        lines.append(f"### {result['path']}")
        lines.append("")

        if result.get("error"):
            lines.append(f"Scan error: {result['error']}")
            lines.append("")
            continue

        findings = result.get("findings", [])
        if not findings:
            lines.append("No findings reported.")
            lines.append("")
            continue

        for finding in findings:
            lines.append(f"#### {finding['severity']} - {finding['type']}")
            lines.append("")
            lines.append(f"- Severity: {finding['severity']}")
            lines.append(f"- Type: {finding['type']}")
            lines.append(f"- Description: {finding['description']}")
            lines.append(f"- Impact: {finding['impact']}")
            lines.append(f"- Vulnerable code reference: {finding['code_reference']}")
            lines.append("- Fix:")
            lines.append("")
            lines.append("```text")
            lines.append(finding["fix"])
            lines.append("```")
            lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def resolve_format(requested_format: str, output_path: Path | None) -> str:
    """Infer report format from output extension when the default is used."""
    if requested_format != "terminal" or output_path is None:
        return requested_format

    suffix = output_path.suffix.lower()
    if suffix == ".json":
        return "json"
    if suffix in {".md", ".markdown"}:
        return "markdown"
    return requested_format


def write_report(output_path: Path, content: str) -> None:
    """Write report content and create parent directories as needed."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(content, encoding="utf-8")
    print(f"Wrote report to {output_path}", file=sys.stderr)


def run_scan(args: argparse.Namespace) -> int:
    """Run the scan command."""
    try:
        files = collect_python_files(args.path)
    except (FileNotFoundError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    if not files:
        print(f"Error: no Python files found in {args.path}", file=sys.stderr)
        return 1

    Path("reports").mkdir(exist_ok=True)

    try:
        model = configure_gemini()
    except ScannerSetupError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    print(f"Scanning {len(files)} Python file(s)...", file=sys.stderr)
    results: list[dict[str, Any]] = []
    for index, file_path in enumerate(files, start=1):
        print(f"[{index}/{len(files)}] Analyzing {file_path}", file=sys.stderr)
        results.append(scan_file(model, file_path))

    output_format = resolve_format(args.format, args.output)
    report = build_report(results)

    if output_format == "terminal":
        print_terminal_results(results)
    elif output_format == "markdown":
        markdown = render_markdown_report(report)
        if args.output:
            write_report(args.output, markdown)
        else:
            print(markdown)
    elif output_format == "json":
        json_report = json.dumps(report, indent=2)
        if args.output:
            write_report(args.output, json_report + "\n")
        else:
            print(json_report)

    return 0


def main(argv: list[str] | None = None) -> int:
    """CLI entry point."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if not hasattr(args, "func"):
        parser.print_help()
        return 0

    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
