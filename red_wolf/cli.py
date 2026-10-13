"""
cli.py
------
Command-line entry point. Wires together:
    ScanConfig -> UnauthAccessScanner.run() -> deep_probe_json_endpoints()
    -> build_report_data() -> write_reports()

Two ways to run it:

1) Flag-driven (scriptable, good for CI / automation):
    python -m red_wolf.cli \
        --url https://target.example.com \
        --endpoints-file my_endpoints.txt \
        --wordlist --smart-order --deep-probe \
        --format md json html \
        --output report \
        --i-am-authorized

2) Interactive wizard (no flags needed -- just answer the prompts):
    python -m red_wolf.cli
    python -m red_wolf.cli --interactive
"""

import argparse
import getpass
import os
import re
import sys
import time
import webbrowser
from pathlib import Path

from .scanner import ScanConfig, UnauthAccessScanner
from .wordlists import load_wordlist_from_file
from .deep_probe import deep_probe_json_endpoints
from .report import build_report_data, write_reports, attach_ai_analysis
from .ai_analysis import AIConfig, AIAnalysisError, analyze_report, detect_provider
from .targets import expand_target
from . import __version__


BANNER = r"""
  ____          _  __        __    _  __
 |  _ \ ___  __| | \ \      / /__ | |/ _|
 | |_) / _ \/ _` |  \ \ /\ / / _ \| | |_
 |  _ <  __/ (_| |   \ V  V / (_) | |  _|
 |_| \_\___|\__,_|    \_/\_/ \___/|_|_|
          WOLF  |  RED WOLF
        Unauthenticated Access Recon
""".strip("\n")

WOLF_ART = r"""
                 /\     /\
                /  \___/  \
               /  /     \  \
              /  /  .-.  \  \
             (  (  (o o)  )  )
              \  \  \_/  /  /
               \  '---'  /  /
                \_______/  /
                 /  |  \
                /___|___\
              RED WOLF // HUNTER
""".strip("\n")

BRAND_ASSETS = (
    "assets/eye-wolf.jpg",
    "assets/wolf-shadow.jpg",
    "assets/logo.jpg",
)


def _branding_page() -> Path:
    assets_dir = Path(__file__).resolve().parent.parent / "assets"
    page = assets_dir / "red_wolf_branding.html"
    page.write_text(
        """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>RED WOLF</title>
<style>
body { margin:0; background:#050505; color:#ef2020; font-family:Segoe UI,Arial,sans-serif; text-align:center; }
main { max-width:1100px; margin:0 auto; padding:28px; }
h1 { letter-spacing:12px; margin:8px 0; text-shadow:0 0 16px #a00000; }
p { color:#d8d8d8; letter-spacing:3px; }
.gallery { display:grid; grid-template-columns:2fr 1fr; gap:18px; align-items:center; }
img { width:100%; max-height:520px; object-fit:cover; border:1px solid #8c1111; box-shadow:0 0 22px #350000; }
.wolf { background:#110000; padding:12px; }
code { color:#ff5555; }
</style>
</head>
<body><main>
<h1>RED WOLF</h1><p>Evidence-First Arrow · Adaptive Local Learning</p>
<div class="gallery">
<img src="eye-wolf.jpg" alt="Eye Wolf">
<img src="wolf-shadow.jpg" alt="Wolf Shadow">
</div>
<p class="wolf">WOLF // AUTHORIZED RECON ONLY</p>
<p><code>Local artwork · no external network request</code></p>
</main></body>
</html>
""",
        encoding="utf-8",
    )
    return page


def _safe_print(text: str) -> None:
    """Keep branding from crashing legacy Windows consoles with cp1252."""
    try:
        print(text)
    except UnicodeEncodeError:
        stream = getattr(sys.stdout, "buffer", None)
        if stream is not None:
            stream.write((text + "\n").encode(sys.stdout.encoding or "utf-8", errors="replace"))
            stream.flush()
        else:
            print(text.encode("ascii", errors="replace").decode("ascii"))


def print_branding() -> None:
    """Print the terminal-safe identity; image assets remain available for reports/docs."""
    _safe_print(BANNER)
    _safe_print(WOLF_ART)
    print("        Evidence-First Arrow  |  Adaptive Local Learning")
    print("        Visual assets: " + ", ".join(BRAND_ASSETS))


def open_branding_artwork() -> None:
    """Open the bundled wolf artwork locally when the interactive UI starts."""
    try:
        webbrowser.open(_branding_page().as_uri())
    except OSError as exc:
        print(f"[!] Could not open local branding artwork: {exc}", file=sys.stderr)


AUTHORIZATION_NOTICE = """
================================================================
  This tool sends unauthenticated requests to the target and may
  download files. ONLY run it against a target you are explicitly
  authorized to test -- e.g. a program in scope on HackerOne,
  Bugcrowd, Intigriti, YesWeHack, or Inspectiv, or your own
  infrastructure / lab.

  Re-run with --i-am-authorized (or confirm inside the interactive
  wizard) once you've confirmed scope.
================================================================
""".strip("\n")


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="red_wolf",
        description="Red Wolf -- Detect unauthenticated access to API/admin/file-download endpoints, with optional AI-assisted analysis.",
    )
    parser.add_argument("--version", action="version", version=f"Red Wolf {__version__}")
    parser.add_argument("--interactive", "-i", action="store_true", help="Run an interactive wizard that prompts for the target and options instead of using flags")
    parser.add_argument("--url", help="Base URL of the authorized target, e.g. https://target.example.com")
    parser.add_argument("--endpoints-file", help="Text file with one known endpoint path per line (from Burp/recon)")
    parser.add_argument("--wordlist", action="store_true", help="Also fuzz the built-in default wordlist of common sensitive paths")
    parser.add_argument("--custom-wordlist", help="Path to a custom wordlist file (overrides the built-in default if --wordlist is set)")
    parser.add_argument("--smart-order", action="store_true", help="Order the wordlist by RWO-learned category priority (api > file > admin > misc by default) instead of plain alphabetical order -- finds real findings in fewer requests on average, useful under rate limits or time budgets")
    parser.add_argument("--profile", choices=["focused", "balanced", "full", "comprehensive"], default="balanced", help="Scan scope: focused, balanced, full, or comprehensive discovery plus full paths")
    parser.add_argument("--no-discovery", action="store_true", help="Skip same-origin robots/sitemap/OpenAPI discovery")
    parser.add_argument("--max-discovered", type=int, default=100, help="Maximum discovered paths per target (default: 100)")
    parser.add_argument("--max-requests", type=int, default=2000, help="Maximum HTTP requests per target (default: 2000)")
    parser.add_argument("--exclude-path", action="append", default=[], help="Relative path prefix to exclude; repeat for multiple paths")
    parser.add_argument("--max-response-bytes", type=int, default=1_000_000, help="Maximum response bytes retained per request (default: 1000000)")
    parser.add_argument("--no-learning", action="store_true", help="Disable local adaptive ordering and local scan history")
    parser.add_argument("--feedback-path", help="Record explicit feedback for one path after a scan")
    parser.add_argument("--feedback", choices=["useful", "not-useful"], help="Label --feedback-path for future ordering")
    parser.add_argument("--methods", nargs="+", default=["GET"], help="HTTP methods to try per path (default: GET)")
    parser.add_argument("--timeout", type=int, default=10, help="Per-request timeout in seconds (default: 10)")
    parser.add_argument("--delay", type=float, default=0.3, help="Delay between requests in seconds, to stay polite (default: 0.3)")
    parser.add_argument("--deep-probe", action="store_true", help="Attempt to extract and verify unauthenticated file downloads from JSON API responses")
    parser.add_argument("--format", nargs="+", default=["md", "json"], choices=["md", "json", "html", "sarif"], help="Report format(s) to write")
    parser.add_argument("--output", default="red_wolf_report", help="Output file prefix (default: red_wolf_report)")
    parser.add_argument("--i-am-authorized", action="store_true", help="Confirm you have explicit authorization to test this target")

    ai_group = parser.add_argument_group("AI-assisted analysis (optional)")
    ai_group.add_argument("--ai-analyze", action="store_true", help="Send findings to an LLM for risk narrative, severity opinion, remediation steps, and a submission draft")
    ai_group.add_argument("--ai-provider", default="openai", choices=["openai", "openrouter", "nvidia", "custom"], help="Which API to call (default: openai)")
    ai_group.add_argument("--ai-api-key", help="API key for the AI provider. If omitted, read from RED_WOLF_AI_API_KEY env var")
    ai_group.add_argument("--ai-model", help="Override the default model for the chosen provider")
    ai_group.add_argument("--ai-base-url", help="Required when --ai-provider custom -- any OpenAI-compatible base URL")

    return parser


# ----------------------------------------------------------------------
# Interactive wizard
# ----------------------------------------------------------------------

def _ask(prompt: str, default: str = "") -> str:
    suffix = f" [{default}]" if default else ""
    val = input(f"{prompt}{suffix}: ").strip()
    return val if val else default


def _ask_required(prompt: str, validate=None, error_msg: str = "That doesn't look valid, try again.") -> str:
    while True:
        val = input(f"{prompt}: ").strip()
        if not val:
            print("  -> this field is required.")
            continue
        if validate and not validate(val):
            print(f"  -> {error_msg}")
            continue
        return val


def _ask_yes_no(prompt: str, default: bool = False) -> bool:
    hint = "Y/n" if default else "y/N"
    val = input(f"{prompt} ({hint}): ").strip().lower()
    if not val:
        return default
    return val in ("y", "yes")


SAFE_METHODS = ["GET", "HEAD", "OPTIONS"]
SUPPORTED_METHODS = SAFE_METHODS + ["POST", "PUT", "PATCH", "DELETE", "TRACE"]


def _parse_methods(value: str) -> list[str]:
    """Parse a method selection, with blank/all meaning all safe methods."""
    normalized = value.strip().lower()
    if not normalized or normalized in {"all", "*", "safe", "read"}:
        return SAFE_METHODS.copy()

    requested = [item.upper() for item in re.split(r"[\s,]+", value) if item]
    methods = list(dict.fromkeys(item for item in requested if item in SUPPORTED_METHODS))
    ignored = [item for item in requested if item not in SUPPORTED_METHODS]
    if ignored:
        print(f"  -> ignored unsupported HTTP method(s): {', '.join(ignored)}")
    return methods or SAFE_METHODS.copy()


def run_interactive_wizard():
    """
    Run the quick wizard. Only the target and AI API key are user inputs;
    safe scan and report options use their standard defaults.

    The authorization confirmation remains explicit because this command
    sends unauthenticated requests to the target.
    Returns None if the user cancels or declines authorization.
    """
    print_branding()
    open_branding_artwork()
    print("=== Red Wolf Quick Setup ===\n")

    url = _ask_required(
        "Target URL, CIDR, or wildcard (e.g. https://target.example.com, 192.0.2.0/28, *.example.com)",
        validate=lambda v: bool(v.strip()),
        error_msg="Target cannot be empty.",
    )

    env_key_present = bool(os.environ.get("RED_WOLF_AI_API_KEY"))
    if env_key_present:
        print("Using RED_WOLF_AI_API_KEY for AI analysis.")
        ai_api_key = None
    else:
        ai_api_key = getpass.getpass("AI API key (input hidden): ").strip() or None
        if not ai_api_key:
            print("  -> no API key entered; the scan will run and AI analysis will be skipped.")

    print("\n" + AUTHORIZATION_NOTICE + "\n")
    authorized = _ask_yes_no(
        f"Do you confirm you are explicitly authorized to test {url}?",
        default=False,
    )
    if not authorized:
        print("\n[!] Authorization not confirmed -- aborting. Nothing was sent to the target.", file=sys.stderr)
        return None

    methods_raw = _ask(
        "HTTP methods (Enter/all = complete safe scan; add POST/PUT/PATCH/DELETE only if authorized)",
        default="GET,HEAD,OPTIONS",
    )
    methods = _parse_methods(methods_raw)
    profile = _ask(
        "Scan profile (focused/balanced/full/comprehensive)",
        default="comprehensive",
    ).strip().lower()
    if profile not in {"focused", "balanced", "full", "comprehensive"}:
        profile = "comprehensive"

    ai_provider = detect_provider(ai_api_key)
    ai_base_url = os.environ.get("RED_WOLF_AI_BASE_URL") or None
    ai_model = os.environ.get("RED_WOLF_AI_MODEL") or None
    print(f"AI provider: {ai_provider}")

    return argparse.Namespace(
        url=url,
        endpoints_file=None,
        wordlist=True,
        custom_wordlist=None,
        smart_order=True,
        profile=profile,
        methods=methods,
        timeout=5,
        delay=0.05,
        deep_probe=True,
        format=["md", "json"],
        output="red_wolf_report",
        i_am_authorized=True,
        ai_analyze=bool(ai_api_key),
        ai_provider=ai_provider,
        ai_api_key=ai_api_key,
        ai_model=ai_model,
        ai_base_url=ai_base_url,
        no_discovery=False,
        max_discovered=100,
        no_learning=False,
        feedback_path=None,
        feedback=None,
    )


# ----------------------------------------------------------------------
# Shared execution path (used by both flag-driven and interactive runs)
# ----------------------------------------------------------------------

def execute(args: argparse.Namespace) -> int:
    if not args.url:
        print("[!] No target URL provided. Use --url, or run with --interactive.", file=sys.stderr)
        return 1

    if not args.i_am_authorized:
        print(AUTHORIZATION_NOTICE, file=sys.stderr)
        return 1

    try:
        targets, target_warning = expand_target(args.url)
    except ValueError as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 1
    if target_warning:
        print(f"[!] {target_warning}", file=sys.stderr)
    if not targets:
        print("[!] No resolvable targets found.", file=sys.stderr)
        return 1

    endpoints = []
    if args.endpoints_file:
        endpoints = load_wordlist_from_file(args.endpoints_file)

    custom_wordlist = None
    if args.custom_wordlist:
        custom_wordlist = load_wordlist_from_file(args.custom_wordlist)

    config = ScanConfig(
        base_url=args.url,
        endpoints=endpoints,
        use_wordlist=args.wordlist or bool(custom_wordlist),
        custom_wordlist=custom_wordlist,
        timeout=args.timeout,
        delay=args.delay,
        methods=args.methods,
        smart_order=args.smart_order,
        wordlist_profile=args.profile,
        discovery=not getattr(args, "no_discovery", False),
        max_discovered_paths=getattr(args, "max_discovered", 100),
        max_requests=getattr(args, "max_requests", 2000),
        excluded_paths=list(getattr(args, "exclude_path", [])),
        max_response_bytes=getattr(args, "max_response_bytes", 1_000_000),
        max_discovery_documents=25 if args.profile == "comprehensive" else 12,
        max_javascript_bytes=1_000_000,
        learning=not getattr(args, "no_learning", False),
    )

    print_branding()
    if args.smart_order:
        from .smart_schedule import learn_category_priority
        order, expected = learn_category_priority()
        print(f"[*] Smart ordering (RWO) enabled -- category priority: {' > '.join(order)} "
              f"(expected ~{expected:.1f} requests to first finding)")
    print(f"[*] Target input: {args.url}")
    scanners = []
    discovered_total = 0
    for target in targets:
        target_scanner = UnauthAccessScanner(
            ScanConfig(
                base_url=target,
                endpoints=list(config.endpoints),
                use_wordlist=config.use_wordlist,
                custom_wordlist=config.custom_wordlist,
                timeout=config.timeout,
                delay=config.delay,
                methods=config.methods,
                smart_order=config.smart_order,
                wordlist_profile=config.wordlist_profile,
                discovery=config.discovery,
                max_discovered_paths=config.max_discovered_paths,
                max_discovery_documents=config.max_discovery_documents,
                max_javascript_bytes=config.max_javascript_bytes,
                max_requests=config.max_requests,
                excluded_paths=list(config.excluded_paths),
                max_response_bytes=config.max_response_bytes,
                learning=config.learning,
            )
        )
        discovered = target_scanner.discover_paths()
        target_scanner.config.endpoints.extend(discovered)
        discovered_total += len(discovered)
        scanners.append(target_scanner)
    endpoint_count = sum(len(scanner._build_target_list()) for scanner in scanners)
    request_count = sum(
        min(len(scanner._build_target_list()) * len(args.methods), scanner.config.max_requests)
        for scanner in scanners
    )
    print(f"[*] Expanded to {len(targets)} target(s).")
    print(f"[*] Discovery added {discovered_total} same-origin path(s).")
    print(f"[*] Testing {endpoint_count} endpoint(s), {request_count} total request(s), methods {args.methods} ...")
    started_at = time.monotonic()
    last_progress = {"time": 0.0}

    total_requests = request_count

    def show_progress(completed: int, _total: int, path: str, method: str, completed_offset: int = 0) -> None:
        del _total
        completed += completed_offset
        now = time.monotonic()
        if completed != total_requests and now - last_progress["time"] < 0.1:
            return
        last_progress["time"] = now
        percent = (completed / total_requests * 100) if total_requests else 100.0
        width = 30
        filled = int(width * percent / 100)
        bar = "#" * filled + "-" * (width - filled)
        elapsed = now - started_at
        rate = completed / elapsed if completed and elapsed else 0.0
        remaining = ((total_requests - completed) / rate) if rate else 0.0
        print(
            f"\r[*] [{bar}] {percent:6.2f}% "
            f"{completed}/{total_requests} | {method} {path[:45]:<45} | ETA {remaining:5.1f}s",
            end="",
            flush=True,
        )

    results = []
    accessible = []
    deep_findings = []
    completed_offset = 0
    for scanner in scanners:
        scanner_total = len(scanner._build_target_list()) * len(args.methods)
        target_results = scanner.run(
            progress_callback=lambda done, total, path, method, offset=completed_offset:
                show_progress(done, total, path, method, offset)
        )
        results.extend(target_results)
        target_accessible = scanner.accessible_endpoints()
        accessible.extend(target_accessible)
        if args.deep_probe:
            deep_findings.extend(deep_probe_json_endpoints(scanner, target_accessible))
        completed_offset += scanner_total
    print()
    findings = [result for result in results if result.is_finding()]

    print(f"[*] Done. {len(accessible)} endpoint(s) accessible without auth, {len(findings)} flagged as findings.")

    if args.deep_probe:
        print("[*] Running deep probe (extracting + verifying file downloads from JSON endpoints) ...")
        confirmed = [d for d in deep_findings if d.get("downloaded")]
        print(f"[*] Deep probe confirmed {len(confirmed)} unauthenticated file download(s).")

    learning_summaries = [scanner.learning_summary() for scanner in scanners]
    learning_summary = {
        "enabled": any(item.get("enabled") for item in learning_summaries),
        "target_specific_patterns": sum(item.get("target_specific_patterns", 0) for item in learning_summaries),
        "target_specific_observations": sum(item.get("target_specific_observations", 0) for item in learning_summaries),
        "target_specific_findings": sum(item.get("target_specific_findings", 0) for item in learning_summaries),
    }
    report_data = build_report_data(args.url, results, deep_findings, learning_summary)
    if args.feedback_path and args.feedback:
        from .learning import LearningStore
        for target in targets:
            LearningStore(target).add_feedback(
                args.feedback_path,
                args.feedback == "useful",
            )
        print(f"[*] Recorded local feedback: {args.feedback} for {args.feedback_path}")

    if args.ai_analyze and (report_data["findings_count"] or report_data["confirmed_unauth_downloads"]):
        print(f"[*] Sending findings to AI provider '{args.ai_provider}' for analysis ...")
        ai_config = AIConfig(
            provider=args.ai_provider,
            api_key=args.ai_api_key,
            model=args.ai_model,
            base_url=args.ai_base_url,
            max_tokens=2048,
        )
        try:
            analysis_text = analyze_report(report_data, ai_config)
            attach_ai_analysis(report_data, analysis_text)
            print("[*] AI analysis attached to report.")
        except AIAnalysisError as exc:
            # Never let a failed AI call kill the whole scan -- the
            # scan results are still valid and worth reporting.
            print(f"[!] AI analysis skipped: {exc}", file=sys.stderr)
    elif args.ai_analyze:
        print("[*] No findings to analyze; skipped AI request to conserve provider credits.")

    written = write_reports(report_data, args.output, formats=args.format)

    print("[*] Report(s) written:")
    for path in written:
        print(f"    - {path}")

    return 0


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]

    # No flags at all, or an explicit --interactive/-i request -> wizard.
    if not argv or "--interactive" in argv or "-i" in argv:
        args = run_interactive_wizard()
        if args is None:
            return 1
        return execute(args)

    parser = build_arg_parser()
    args = parser.parse_args(argv)
    return execute(args)


if __name__ == "__main__":
    raise SystemExit(main())
