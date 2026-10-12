"""
scanner.py
----------
Core scanning engine for detecting Broken Access Control /
Unauthenticated Access to sensitive endpoints (API, admin, file
download), generalized from patterns like the one reported against
equella.monash.edu:

    - REST API endpoints returning data with no auth
    - Admin pages reachable with no session
    - File download endpoints serving content with no token/cookie
    - Access-Control-Allow-Origin: * present on sensitive responses

Designed to be used as a library (import UnauthAccessScanner) so it
can later be wired into a CLI, a Flask/FastAPI dashboard, or a bigger
recon pipeline -- not just run standalone.
"""

import json
import hashlib
import re
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Callable, List, Optional
from urllib.parse import urljoin, urlparse

import requests


# Keywords that, if present in an "accessible" response body, hint that
# real sensitive data leaked out (not just a generic 200 OK / login page).
SENSITIVE_KEYWORDS = [
    "password", "passwd", "secret", "api_key", "apikey", "access_token",
    "private_key", "md5", "sha1", "sha256", "uuid", "ssn",
    "email", "username", "session", "cookie", "authorization",
    "aws_access_key", "db_password", "connection_string",
]
HIGH_SIGNAL_PATH_TERMS = {
    "api": 12, "graphql": 12, "swagger": 10, "openapi": 10,
    "admin": 10, "internal": 10, "private": 10, "debug": 8,
    "config": 8, "export": 8, "download": 8, "file": 7,
    "attachment": 7, "backup": 7, "actuator": 7, "metrics": 5,
}


@dataclass
class EndpointResult:
    """One tested endpoint and what we learned about it."""
    url: str
    method: str
    status_code: int
    accessible: bool               # True if status looks like "served content"
    cors_wildcard: bool            # True if ACAO: * was present
    content_type: str = ""
    response_size: int = 0
    sensitive_data_found: bool = False
    sample_snippet: str = ""       # short preview of the body (truncated)
    notes: str = ""                # e.g. request errors, timeouts
    elapsed_ms: int = 0
    evidence_score: int = 0
    evidence_reasons: List[str] = field(default_factory=list)
    verification_status: str = "not-run"
    verification_checks: List[str] = field(default_factory=list)
    confidence: int = 0

    def is_finding(self) -> bool:
        """
        A result counts as a "finding" worth reporting if the endpoint
        was reachable WITHOUT auth and either:
          - it returned what looks like sensitive data, or
          - it exposed a permissive CORS wildcard on top of being accessible.
        Plain 200s with no sensitive content (e.g. a generic homepage)
        are not findings -- they're just "accessible", which is normal.
        """
        return (
            self.accessible
            and (self.sensitive_data_found or self.cors_wildcard)
            and self.verification_status in {"confirmed", "probable"}
        )

    def is_candidate_for_verification(self) -> bool:
        """Return true for an accessible response with a meaningful signal."""
        return self.accessible and (self.sensitive_data_found or self.cors_wildcard)


@dataclass
class ScanConfig:
    base_url: str
    endpoints: List[str] = field(default_factory=list)   # user-supplied, from Burp/recon
    use_wordlist: bool = True                             # fuzz common paths too
    custom_wordlist: Optional[List[str]] = None            # overrides DEFAULT_WORDLIST
    timeout: int = 10
    delay: float = 0.3                                     # seconds between requests
    user_agent: str = "UnauthAccessScanner/1.0 (authorized-testing)"
    methods: List[str] = field(default_factory=lambda: ["GET"])
    smart_order: bool = False   # use RWO-learned category priority instead of alphabetical
    wordlist_profile: str = "balanced"
    discovery: bool = True
    max_discovered_paths: int = 100
    max_discovery_documents: int = 25
    max_javascript_bytes: int = 1_000_000
    learning: bool = True
    auto_verify: bool = True
    verification_attempts: int = 2
    learning_namespace: str = ""
    excluded_paths: List[str] = field(default_factory=list)
    max_response_bytes: int = 1_000_000


class UnauthAccessScanner:
    """
    Usage:
        cfg = ScanConfig(base_url="https://target.example.com",
                          endpoints=["more/api/search?q=&start=0&length=10"])
        scanner = UnauthAccessScanner(cfg)
        results = scanner.run()
        findings = scanner.findings()
    """

    def __init__(self, config: ScanConfig):
        self.config = config
        self.results: List[EndpointResult] = []
        self.learning_store = None
        if config.learning:
            from .learning import LearningStore
            self.learning_store = LearningStore(config.base_url, config.learning_namespace)

    # ---- target list assembly -------------------------------------------------

    def _build_target_list(self) -> List[str]:
        """
        Merge user-supplied endpoints with the wordlist (if enabled).
        This is the "both together" discovery mode: manual list ∪ fuzz list.

        If config.smart_order is True, the wordlist portion is reordered
        by RWO-learned category priority (see smart_schedule.py) instead
        of plain alphabetical sorting -- manual endpoints (known-good
        intel) are always tested first either way.
        """
        from .wordlists import get_wordlist

        manual = [p.lstrip("/") for p in self.config.endpoints]
        wordlist_targets: List[str] = []

        if self.config.use_wordlist:
            if self.config.custom_wordlist:
                wordlist_targets = [p.lstrip("/") for p in self.config.custom_wordlist]
            elif self.config.smart_order:
                from .smart_schedule import build_prioritized_wordlist
                wordlist_targets = build_prioritized_wordlist()
            else:
                wordlist_targets = get_wordlist(self.config.wordlist_profile)

        # De-dup while preserving priority: manual first, then wordlist
        # order (alphabetical or RWO-prioritized), skipping repeats.
        seen = set()
        ordered = []
        for p in manual + wordlist_targets:
            if self._is_excluded(p):
                continue
            if p not in seen:
                seen.add(p)
                ordered.append(p)
        if self.config.smart_order:
            ordered.sort(
                key=lambda path: self._path_signal_score(path) + self._learned_path_score(path),
                reverse=True,
            )
        return ordered

    def _is_excluded(self, path: str) -> bool:
        candidate = "/" + path.lstrip("/")
        return any(
            candidate == excluded or candidate.startswith(excluded.rstrip("/") + "/")
            for excluded in ("/" + item.lstrip("/") for item in self.config.excluded_paths)
        )

    def _learned_path_score(self, path: str) -> float:
        if not self.learning_store:
            return 0.0
        from .learning import normalize_path
        return self.learning_store.ranking().get(normalize_path(path), 0.0)

    @staticmethod
    def _path_signal_score(path: str) -> int:
        lowered = path.lower()
        return sum(weight for term, weight in HIGH_SIGNAL_PATH_TERMS.items() if term in lowered)

    def discover_paths(self) -> List[str]:
        """Collect same-origin paths from robots, sitemap, and OpenAPI docs."""
        if not self.config.discovery:
            return []

        seeds = [
            "", "robots.txt", "sitemap.xml", "sitemap_index.xml",
            "openapi.json", "swagger.json", "api-docs", "graphql",
        ]
        discovered: List[str] = []
        seen = set()
        scripts: List[str] = []
        session = self._fresh_session()

        def add_path(candidate: str) -> None:
            parsed = urlparse(candidate)
            base = urlparse(self.config.base_url)
            if parsed.scheme and parsed.netloc and parsed.netloc != base.netloc:
                return
            path = parsed.path or "/"
            if parsed.query:
                path += "?" + parsed.query
            normalized = path.lstrip("/")
            if (
                normalized
                and not self._is_excluded(normalized)
                and normalized not in seen
                and len(discovered) < self.config.max_discovered_paths
            ):
                seen.add(normalized)
                discovered.append(normalized)

        documents_read = 0
        for seed in seeds:
            if documents_read >= self.config.max_discovery_documents:
                break
            try:
                response = session.get(
                    urljoin(self.config.base_url.rstrip("/") + "/", seed),
                    headers={"User-Agent": self.config.user_agent},
                    timeout=self.config.timeout,
                    allow_redirects=False,
                    stream=True,
                )
            except (requests.RequestException, TimeoutError, OSError):
                continue
            if response.status_code != 200:
                continue
            documents_read += 1

            content_type = response.headers.get("Content-Type", "").lower()
            try:
                body_bytes = response.raw.read(self.config.max_javascript_bytes + 1)
            finally:
                response.close()
            body = body_bytes[:self.config.max_javascript_bytes].decode(
                response.encoding or "utf-8", errors="replace"
            )
            if seed == "robots.txt":
                for line in body.splitlines():
                    if line.lower().startswith(("allow:", "disallow:")):
                        add_path(line.split(":", 1)[1].strip())
                    elif line.lower().startswith("sitemap:"):
                        add_path(line.split(":", 1)[1].strip())
            elif "xml" in content_type or seed.endswith(".xml"):
                try:
                    root = ET.fromstring(body)
                    for element in root.iter():
                        if element.tag.lower().endswith("loc") and element.text:
                            add_path(element.text.strip())
                except ET.ParseError:
                    continue
            else:
                try:
                    data = response.json()
                except (ValueError, json.JSONDecodeError):
                    data = None
                if isinstance(data, dict):
                    paths = data.get("paths", {})
                    if isinstance(paths, dict):
                        for path in paths:
                            if isinstance(path, str):
                                add_path(path)
                for href in re.findall(r"""(?:href|src)=["']([^"']+)["']""", body, re.I):
                    if href.startswith("/"):
                        add_path(href)
                    elif href.endswith((".js", ".mjs")):
                        scripts.append(urljoin(response.url, href))

                if seed == "" or "html" in content_type:
                    for script in re.findall(r"""<script[^>]+src=["']([^"']+)["']""", body, re.I):
                        scripts.append(urljoin(response.url, script))

        for script_url in list(dict.fromkeys(scripts))[: self.config.max_discovery_documents]:
            parsed_script = urlparse(script_url)
            base = urlparse(self.config.base_url)
            if parsed_script.netloc and parsed_script.netloc != base.netloc:
                continue
            try:
                response = session.get(
                    script_url,
                    headers={"User-Agent": self.config.user_agent},
                    timeout=self.config.timeout,
                    allow_redirects=False,
                    stream=True,
                )
            except (requests.RequestException, TimeoutError, OSError):
                continue
            if response.status_code != 200:
                continue
            try:
                script_bytes = response.raw.read(self.config.max_javascript_bytes + 1)
            finally:
                response.close()
            script_body = script_bytes[:self.config.max_javascript_bytes].decode(
                response.encoding or "utf-8", errors="replace"
            )
            for candidate in re.findall(
                r"""["']((?:/|https?://)[^"'<>\\\s]{2,200})["']""",
                script_body,
            ):
                add_path(candidate)
            for candidate in re.findall(
                r"""(?:fetch|axios\.(?:get|post|put|patch|delete)|url)\s*\(\s*["']([^"']+)["']""",
                script_body,
                re.I,
            ):
                add_path(candidate)

        return discovered

    # ---- request handling --------------------------------------------------

    def _fresh_session(self) -> requests.Session:
        """
        A brand-new session per request: NO cookies, NO Authorization
        header, NO prior state carried over. This is what makes the
        test meaningful -- we're simulating a completely anonymous,
        unauthenticated client hitting the endpoint cold.
        """
        session = requests.Session()
        session.trust_env = False  # ignore any auth from env vars / netrc
        return session

    def _read_response(self, response: requests.Response) -> tuple[bytes, bool]:
        limit = max(1, self.config.max_response_bytes)
        try:
            body = response.raw.read(limit + 1)
        finally:
            response.close()
        return body[:limit], len(body) > limit

    def test_endpoint(self, path: str, method: str = "GET") -> EndpointResult:
        session = self._fresh_session()
        url = urljoin(self.config.base_url.rstrip("/") + "/", path)
        headers = {"User-Agent": self.config.user_agent}

        start = time.time()
        try:
            resp = session.request(
                method,
                url,
                headers=headers,
                timeout=self.config.timeout,
                allow_redirects=False,  # a redirect to /login is NOT "accessible"
                stream=True,
            )
        except (requests.RequestException, TimeoutError, OSError) as exc:
            return EndpointResult(
                url=url, method=method, status_code=0,
                accessible=False, cors_wildcard=False,
                notes=f"request failed: {exc}",
                elapsed_ms=int((time.time() - start) * 1000),
            )

        elapsed_ms = int((time.time() - start) * 1000)
        body, truncated = self._read_response(resp)

        cors_header = resp.headers.get("Access-Control-Allow-Origin", "")
        cors_wildcard = cors_header.strip() == "*"

        # 2xx / 206 (partial content, common for file downloads) = served something
        accessible = resp.status_code in (200, 201, 206)

        sensitive = False
        snippet = ""
        evidence_score = 0
        evidence_reasons: List[str] = []
        if accessible:
            try:
                body_preview = body.decode(resp.encoding or "utf-8", errors="replace")[:3000]
            except Exception:
                body_preview = ""
            snippet = body_preview[:300].replace("\n", " ")
            lowered = body_preview.lower()
            sensitive = any(keyword in lowered for keyword in SENSITIVE_KEYWORDS)
            if sensitive:
                evidence_score += 45
                evidence_reasons.append("sensitive keyword in response body")
            if "json" in resp.headers.get("Content-Type", "").lower():
                evidence_score += 15
                evidence_reasons.append("structured JSON response")
            if cors_wildcard:
                evidence_score += 25
                evidence_reasons.append("wildcard CORS")
            path_score = self._path_signal_score(path)
            if path_score:
                evidence_score += min(path_score, 30)
                evidence_reasons.append("high-signal endpoint path")

        result = EndpointResult(
            url=url,
            method=method,
            status_code=resp.status_code,
            accessible=accessible,
            cors_wildcard=cors_wildcard,
            content_type=resp.headers.get("Content-Type", ""),
            response_size=len(body),
            sensitive_data_found=sensitive,
            sample_snippet=snippet,
            elapsed_ms=elapsed_ms,
            evidence_score=min(evidence_score, 100),
            evidence_reasons=evidence_reasons,
        )
        if truncated:
            result.notes = f"response truncated at {self.config.max_response_bytes} bytes"
        if self.config.auto_verify and result.is_candidate_for_verification():
            self._verify_result(result, path, method)
        return result

    @staticmethod
    def _response_fingerprint(resp: requests.Response) -> str:
        body = (resp.content or b"")[:8192]
        return hashlib.sha256(body).hexdigest()

    def _verify_result(self, result: EndpointResult, _path: str, method: str) -> None:
        """Repeat read-only evidence checks to reduce transient false positives."""
        del _path
        checks: List[str] = []
        if result.sensitive_data_found:
            checks.append("sensitive response indicator present")
        if result.cors_wildcard:
            checks.append("wildcard CORS present")

        fingerprints = []
        statuses = []
        for _ in range(max(1, min(self.config.verification_attempts, 3))):
            session = self._fresh_session()
            try:
                response = session.request(
                    method,
                    result.url,
                    headers={"User-Agent": self.config.user_agent},
                    timeout=self.config.timeout,
                    allow_redirects=False,
                    stream=True,
                )
            except (requests.RequestException, TimeoutError, OSError):
                continue
            statuses.append(response.status_code)
            body, _ = self._read_response(response)
            fingerprints.append(hashlib.sha256(body[:8192]).hexdigest())

        if not statuses:
            result.verification_status = "unverified"
            result.verification_checks = checks + ["repeat request failed"]
            result.confidence = min(result.evidence_score, 49)
            return

        stable = len(set(statuses)) == 1 and len(set(fingerprints)) == 1
        if stable:
            checks.append("repeat requests returned stable status and body")
        else:
            checks.append("repeat requests were inconsistent")

        login_like = any(
            marker in result.sample_snippet.lower()
            for marker in ("sign in", "log in", "login", "authentication required")
        )
        if login_like:
            checks.append("login-page marker detected")

        if stable and not login_like:
            result.verification_status = "confirmed"
            result.confidence = min(100, max(70, result.evidence_score + 15))
        elif result.evidence_score >= 45 and not login_like:
            result.verification_status = "probable"
            result.confidence = min(69, result.evidence_score)
        else:
            result.verification_status = "unverified"
            result.confidence = min(49, result.evidence_score)
        result.verification_checks = checks

    # ---- orchestration -------------------------------------------------------

    def run(self, progress_callback: Optional[Callable[[int, int, str, str], None]] = None) -> List[EndpointResult]:
        """
        Run the full scan: build target list, hit each one (politely,
        with a delay between requests), collect results.
        """
        targets = self._build_target_list()
        total = len(targets) * len(self.config.methods)
        completed = 0
        results = []
        for path in targets:
            for method in self.config.methods:
                if progress_callback:
                    progress_callback(completed, total, path, method)
                result = self.test_endpoint(path, method)
                results.append(result)
                completed += 1
                if progress_callback:
                    progress_callback(completed, total, path, method)
                if self.config.delay:
                    time.sleep(self.config.delay)
        self.results = results
        if self.learning_store:
            self.learning_store.record(
                (result.url, result.accessible, result.is_finding())
                for result in results
            )
        return results

    def learning_summary(self) -> dict:
        if not self.learning_store:
            return {"enabled": False}
        return self.learning_store.summary()

    def findings(self) -> List[EndpointResult]:
        """Subset of results that actually look like real vulnerabilities."""
        return [r for r in self.results if r.is_finding()]

    def accessible_endpoints(self) -> List[EndpointResult]:
        """Everything that responded 2xx/206 without auth, finding or not."""
        return [r for r in self.results if r.accessible]
