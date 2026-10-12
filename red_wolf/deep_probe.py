"""
deep_probe.py
-------------
Mirrors the exact 3-step pattern from the equella.monash.edu style
report, but generalized to any JSON-returning API:

    Step 1: List items     -> GET /api/search  (no auth)
    Step 2: Get item detail -> GET /api/item/{id}  (no auth)
    Step 3: Download file   -> GET {download_url}  (no auth)

Instead of hardcoding Equella's exact field names, this module
recursively walks ANY JSON object/array looking for keys that
commonly point to downloadable files (url, download_url, file,
filename + id/uuid pairs), builds candidate absolute URLs, and feeds
them back into the scanner to verify they're really downloadable
with zero authentication.
"""

import json
import hashlib
import re
from pathlib import Path
from typing import List, Set
from urllib.parse import urljoin, urlparse

import requests

# Keys that, across common REST APIs, tend to hold a direct or
# near-direct reference to a file.
FILE_URL_KEYS = {"url", "download_url", "downloadurl", "file_url",
                  "fileurl", "href", "link", "attachment", "path"}

FILE_ID_KEYS = {"uuid", "id", "file_id", "attachment_id"}

FILE_NAME_KEYS = {"filename", "file_name", "name"}

# A crude check: does a string already look like a path/URL to a file
# with a real extension (pdf, docx, zip, etc.)?
FILE_EXT_PATTERN = re.compile(
    r"\.(pdf|docx?|xlsx?|pptx?|zip|rar|7z|csv|txt|png|jpe?g|gif|sql|bak|tar|gz)$",
    re.IGNORECASE,
)


def _same_origin(base_url: str, candidate_url: str) -> bool:
    base = urlparse(base_url)
    candidate = urlparse(candidate_url)
    return (
        candidate.scheme in {"http", "https"}
        and candidate.hostname is not None
        and candidate.hostname.lower() == (base.hostname or "").lower()
        and candidate.port == base.port
    )


def _walk(obj, found_urls: Set[str], found_names: List[str]):
    """
    Recursively walk a parsed JSON structure (dict/list/str/number)
    collecting anything that smells like a file reference.
    """
    if isinstance(obj, dict):
        # Direct URL-ish fields
        for key, value in obj.items():
            lk = key.lower()
            if lk in FILE_URL_KEYS and isinstance(value, str) and value:
                found_urls.add(value)
            if lk in FILE_NAME_KEYS and isinstance(value, str) and FILE_EXT_PATTERN.search(value):
                found_names.append(value)
        # Recurse into nested structures (e.g. "attachments": [...])
        for value in obj.values():
            _walk(value, found_urls, found_names)

    elif isinstance(obj, list):
        for item in obj:
            _walk(item, found_urls, found_names)

    elif isinstance(obj, str):
        if FILE_EXT_PATTERN.search(obj):
            found_names.append(obj)


def extract_candidate_file_refs(json_obj) -> List[str]:
    """
    Given a parsed JSON object (from an API response), return a
    de-duplicated list of strings that look like file URLs or
    filenames with a real extension. These are the candidates we'll
    try to resolve + download next.
    """
    found_urls: Set[str] = set()
    found_names: List[str] = []
    _walk(json_obj, found_urls, found_names)
    # Merge: URLs first (more reliable), then bare filenames.
    # found_names can contain duplicates because _walk both checks a
    # dict value directly against FILE_NAME_KEYS *and* recurses into
    # every value generically -- dedupe while preserving order.
    seen = set(found_urls)
    combined = list(found_urls)
    for name in found_names:
        if name not in seen:
            seen.add(name)
            combined.append(name)
    return combined


def verify_unauth_download(
    base_url: str,
    candidate: str,
    timeout: int = 10,
    max_download_bytes: int = 5_000_000,
    save_dir: Path | None = None,
):
    """
    Try to actually fetch a candidate file reference with a clean,
    unauthenticated session (same discipline as scanner._fresh_session).
    Returns a dict describing whether the download succeeded "for free".

    This is the step that turns "API leaks metadata" into a confirmed,
    demonstrable "unauthenticated file download" finding -- exactly
    the kind of proof a bug bounty triager wants (not just a 200,
    but the actual bytes of a real internal file).
    """
    url = candidate if candidate.startswith("http") else urljoin(base_url, candidate.lstrip("/"))
    session = requests.Session()
    session.trust_env = False

    result = {
        "candidate": candidate,
        "resolved_url": url,
        "downloaded": False,
        "status_code": None,
        "content_type": None,
        "size_bytes": 0,
        "notes": "",
        "saved_path": None,
    }
    if not _same_origin(base_url, url):
        result["notes"] = "candidate outside the target origin"
        return result

    try:
        resp = session.get(url, timeout=timeout, allow_redirects=False, stream=True)
    except requests.RequestException as exc:
        result["notes"] = f"request failed: {exc}"
        return result

    result["status_code"] = resp.status_code
    result["content_type"] = resp.headers.get("Content-Type", "")

    if resp.status_code in (200, 206):
        try:
            content = resp.raw.read(max_download_bytes + 1)
        finally:
            resp.close()
        result["size_bytes"] = min(len(content), max_download_bytes)
        result["downloaded"] = len(content) <= max_download_bytes
        if len(content) > max_download_bytes:
            result["notes"] = "download exceeded configured size limit"
        elif save_dir is not None:
            save_dir.mkdir(parents=True, exist_ok=True)
            digest = hashlib.sha256(url.encode("utf-8")).hexdigest()[:16]
            suffix = Path(urlparse(url).path).suffix.lower()
            suffix = suffix if re.fullmatch(r"\.[a-z0-9]{1,8}", suffix) else ".bin"
            output = save_dir / f"{digest}{suffix}"
            output.write_bytes(content)
            result["saved_path"] = str(output)
    else:
        result["notes"] = f"not downloadable without auth (status {resp.status_code})"

    return result


def deep_probe_json_endpoints(
    scanner,
    candidate_results,
    max_files_per_endpoint: int = 5,
    save_dir: Path | None = None,
):
    """
    Given already-collected EndpointResult objects that look like JSON
    APIs (content_type contains 'json'), re-fetch the body, extract
    file references, and attempt unauthenticated downloads on each.

    Returns a list of dicts: one per confirmed-or-attempted download,
    tagged with which endpoint it came from.
    """
    deep_findings = []
    seen_resolved_urls = {}  # resolved_url -> index into deep_findings, for de-dup across endpoints

    for ep in candidate_results:
        if "json" not in (ep.content_type or "").lower():
            continue
        if not ep.accessible:
            continue

        # Re-fetch full body (scanner only stored a short snippet)
        session = requests.Session()
        session.trust_env = False
        try:
            resp = session.get(
                ep.url,
                timeout=scanner.config.timeout,
                allow_redirects=False,
                stream=True,
            )
            try:
                body = resp.raw.read(scanner.config.max_response_bytes + 1)
            finally:
                resp.close()
            if len(body) > scanner.config.max_response_bytes:
                continue
            data = json.loads(body.decode(resp.encoding or "utf-8", errors="replace"))
        except (requests.RequestException, ValueError, UnicodeError):
            continue

        candidates = extract_candidate_file_refs(data)[:max_files_per_endpoint]
        for candidate in candidates:
            # Resolve first so we can de-dup identical targets found via
            # multiple endpoints (e.g. both /search and /item/{id} point
            # to the same attachment) instead of downloading it N times.
            from urllib.parse import urljoin
            resolved = candidate if candidate.startswith("http") else urljoin(scanner.config.base_url, candidate.lstrip("/"))
            if not _same_origin(scanner.config.base_url, resolved):
                continue

            if resolved in seen_resolved_urls:
                existing = deep_findings[seen_resolved_urls[resolved]]
                if ep.url not in existing["source_endpoints"]:
                    existing["source_endpoints"].append(ep.url)
                continue

            verification = verify_unauth_download(
                scanner.config.base_url,
                candidate,
                scanner.config.timeout,
                scanner.config.max_response_bytes,
                save_dir=save_dir,
            )
            verification["source_endpoints"] = [ep.url]
            seen_resolved_urls[resolved] = len(deep_findings)
            deep_findings.append(verification)

    return deep_findings
