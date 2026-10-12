from pathlib import Path

import pytest


@pytest.fixture
def service_module(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("RED_WOLF_SERVICE_DB", str(tmp_path / "service.db"))
    monkeypatch.setenv("RED_WOLF_ALLOWED_HOSTS", "example.com")
    monkeypatch.setenv("RED_WOLF_SERVICE_TOKEN", "test-token")
    from red_wolf import service

    return service


def test_blocked_network_addresses(service_module):
    assert service_module._blocked_ip("127.0.0.1")
    assert service_module._blocked_ip("169.254.169.254")
    assert service_module._blocked_ip("10.0.0.1")
    assert not service_module._blocked_ip("93.184.216.34")


def test_target_requires_allowlisted_https_host(service_module):
    service_module._resolved_addresses = lambda hostname: {"93.184.216.34"}
    with pytest.raises(service_module.HTTPException) as error:
        service_module._validate_target("http://example.com")
    assert error.value.status_code == 400

    with pytest.raises(service_module.HTTPException) as error:
        service_module._validate_target("https://not-allowed.example")
    assert error.value.status_code == 403

    for invalid in (
        "https://user:pass@example.com",
        "https://example.com/#fragment",
        "https://example.com:bad",
    ):
        with pytest.raises(service_module.HTTPException) as error:
            service_module._validate_target(invalid)
        assert error.value.status_code == 400


def test_job_quota_counts_recent_jobs(service_module):
    service_module._save_job(
        "job-1",
        "tenant-a",
        "https://example.com",
        {"methods": ["GET"], "profile": "focused", "max_discovered": 1},
    )
    service_module._MAX_JOBS_PER_WINDOW = 1
    with pytest.raises(service_module.HTTPException) as error:
        service_module._check_job_quota("tenant-a")
    assert error.value.status_code == 429


def test_scope_exclusions_are_relative_and_normalized(service_module):
    request = service_module.ScanRequest(
        target="https://example.com",
        authorized=True,
        excluded_paths=["/admin/", "/private"],
    )
    assert request.excluded_paths == ["/admin", "/private"]
    with pytest.raises(ValueError):
        service_module.ScanRequest(
            target="https://example.com",
            authorized=True,
            excluded_paths=["https://other.example"],
        )


def test_scanner_excludes_path_subtrees():
    from red_wolf.scanner import ScanConfig, UnauthAccessScanner

    scanner = UnauthAccessScanner(
        ScanConfig(
            base_url="https://example.com",
            endpoints=["admin", "admin/users", "public"],
            use_wordlist=False,
            excluded_paths=["/admin"],
        )
    )
    assert scanner._build_target_list() == ["public"]


def test_scanner_rejects_external_endpoint_urls():
    from red_wolf.scanner import ScanConfig, UnauthAccessScanner

    scanner = UnauthAccessScanner(
        ScanConfig(
            base_url="https://example.com",
            endpoints=["https://other.example/secret", "/api"],
            use_wordlist=False,
        )
    )
    assert scanner._build_target_list() == ["api"]


def test_scanner_respects_request_budget(monkeypatch):
    from red_wolf.scanner import EndpointResult, ScanConfig, UnauthAccessScanner

    scanner = UnauthAccessScanner(
        ScanConfig(
            base_url="https://example.com",
            endpoints=["one", "two"],
            use_wordlist=False,
            methods=["GET", "HEAD"],
            max_requests=3,
            learning=False,
            auto_verify=False,
            delay=0,
        )
    )
    calls = []

    def fake_test(path, method):
        calls.append((path, method))
        return EndpointResult(
            url=f"https://example.com/{path}",
            method=method,
            status_code=404,
            accessible=False,
            cors_wildcard=False,
        )

    monkeypatch.setattr(scanner, "test_endpoint", fake_test)
    assert len(scanner.run()) == 3
    assert len(calls) == 3


def test_scanner_honors_cooperative_cancellation(monkeypatch):
    from red_wolf.scanner import EndpointResult, ScanConfig, UnauthAccessScanner

    stopped = False
    scanner = UnauthAccessScanner(
        ScanConfig(
            base_url="https://example.com",
            endpoints=["one", "two"],
            use_wordlist=False,
            methods=["GET"],
            learning=False,
            auto_verify=False,
            delay=0,
            should_stop=lambda: stopped,
        )
    )

    def fake_test(path, method):
        nonlocal stopped
        stopped = True
        return EndpointResult(
            url=f"https://example.com/{path}",
            method=method,
            status_code=404,
            accessible=False,
            cors_wildcard=False,
        )

    monkeypatch.setattr(scanner, "test_endpoint", fake_test)
    results = scanner.run()
    assert len(results) == 1


def test_scanner_delay_is_interruptible(monkeypatch):
    from red_wolf.scanner import EndpointResult, ScanConfig, UnauthAccessScanner

    stopped = False
    sleeps = []
    scanner = UnauthAccessScanner(
        ScanConfig(
            base_url="https://example.com",
            use_wordlist=False,
            learning=False,
            delay=1,
            should_stop=lambda: stopped,
        )
    )

    def fake_sleep(seconds):
        nonlocal stopped
        sleeps.append(seconds)
        stopped = True

    monkeypatch.setattr("red_wolf.scanner.time.sleep", fake_sleep)
    assert scanner._wait_between_requests() is False
    assert sleeps == [0.1]


def test_cli_parser_exposes_scope_and_response_limits():
    from red_wolf.cli import build_arg_parser

    args = build_arg_parser().parse_args(
        [
            "--url",
            "https://example.com",
            "--exclude-path",
            "/admin",
            "--exclude-path",
            "/internal",
            "--max-requests",
            "25",
            "--max-response-bytes",
            "65536",
        ]
    )
    assert args.exclude_path == ["/admin", "/internal"]
    assert args.max_requests == 25
    assert args.max_response_bytes == 65536


def test_ai_summary_redacts_hosts_queries_and_fragments():
    from red_wolf.ai_analysis import _summarize_for_prompt

    summary = _summarize_for_prompt(
        {
            "target_location": "https://secret.example/?token=do-not-send",
            "total_endpoints_tested": 1,
            "total_accessible_without_auth": 1,
            "findings_count": 1,
            "confirmed_unauth_downloads": 1,
            "findings": [
                {
                    "url": "https://secret.example/api/item?id=secret#fragment",
                    "method": "GET",
                    "status_code": 200,
                    "cors_wildcard": False,
                    "content_type": "application/json",
                    "sensitive_data_found": True,
                    "vrt": "Sensitive Data Exposure",
                }
            ],
            "deep_probe_downloads": [
                {
                    "resolved_url": "https://secret.example/file.pdf?token=secret",
                    "downloaded": True,
                    "status_code": 200,
                }
            ],
        }
    )
    serialized = str(summary)
    assert summary["target_location"] == "<authorized-target>"
    assert "/api/item" in serialized
    assert "secret.example" not in serialized
    assert "secret" not in serialized


def test_deep_probe_rejects_cross_origin_candidates():
    from red_wolf.deep_probe import verify_unauth_download

    result = verify_unauth_download(
        "https://example.com",
        "https://other.example/file.pdf",
    )
    assert result["downloaded"] is False
    assert "outside the target origin" in result["notes"]


def test_multiple_service_tokens_have_isolated_tenants(service_module, monkeypatch):
    monkeypatch.delenv("RED_WOLF_SERVICE_TOKEN", raising=False)
    monkeypatch.setenv("RED_WOLF_SERVICE_TOKENS", "alpha-token,beta-token")
    assert service_module._require_token("alpha-token") != service_module._require_token(
        "beta-token"
    )
    with pytest.raises(service_module.HTTPException) as error:
        service_module._require_token("wrong-token")
    assert error.value.status_code == 401


def test_job_options_are_bounded_and_configurable(service_module):
    request = service_module.ScanRequest(
        target="https://example.com",
        authorized=True,
        timeout=30,
        delay=2,
        discovery=False,
        smart_order=False,
        learning=False,
        share_learning=True,
        auto_verify=False,
        max_response_bytes=2_000_000,
    )
    assert request.timeout == 30
    assert request.delay == 2
    assert request.discovery is False
    assert request.max_response_bytes == 2_000_000
    assert request.share_learning is True
    with pytest.raises(ValueError):
        service_module.ScanRequest(
            target="https://example.com",
            authorized=True,
            timeout=61,
        )


def test_metrics_are_authenticated_and_expose_job_states(service_module):
    service_module._save_job(
        "metrics-job",
        service_module._token_tenant("test-token"),
        "https://example.com",
        {"methods": ["GET"], "profile": "focused", "max_discovered": 1},
    )
    response = service_module.metrics(service_module._token_tenant("test-token"))
    assert response.media_type == "text/plain; version=0.0.4"
    assert 'red_wolf_jobs_total{state="queued"} 1' in response.body.decode()


def test_retention_cleanup_removes_old_jobs(service_module, monkeypatch):
    monkeypatch.setenv("RED_WOLF_RETENTION_DAYS", "1")
    service_module._save_job(
        "old-job",
        "tenant-a",
        "https://example.com",
        {"methods": ["GET"], "profile": "focused", "max_discovered": 1},
    )
    with service_module._connect() as db:
        db.execute(
            "UPDATE jobs SET created_at = ? WHERE job_id = ?",
            ("2000-01-01T00:00:00+00:00", "old-job"),
        )
    assert service_module._cleanup_expired_jobs() == 1


def test_dashboard_asset_is_available(service_module):
    response = service_module.dashboard()
    assert response.media_type == "text/html"
    assert response.path.name == "dashboard.html"


def test_create_list_and_event_job_contract(service_module, monkeypatch):
    tenant_id = service_module._token_tenant("test-token")
    monkeypatch.setattr(
        service_module,
        "_validate_target",
        lambda target: target.rstrip("/"),
    )
    monkeypatch.setattr(
        service_module._executor,
        "submit",
        lambda *args: None,
    )
    request = service_module.ScanRequest(
        target="https://example.com",
        authorized=True,
        discovery=False,
    )
    created = service_module.create_job(request, tenant_id)
    job_id = created["job_id"]
    listed = service_module.list_jobs(tenant_id, limit=25, state=None)
    assert any(item["job_id"] == job_id for item in listed["jobs"])
    events = service_module.get_job_events(job_id, tenant_id)
    assert events["events"][0]["event_type"] == "queued"


def test_cancelled_queued_job_is_not_started(service_module):
    tenant_id = service_module._token_tenant("test-token")
    service_module._save_job(
        "cancel-before-start",
        tenant_id,
        "https://example.com",
        {"methods": ["GET"], "profile": "focused", "max_discovered": 1},
    )
    service_module.cancel_job("cancel-before-start", tenant_id)
    service_module._run_job(
        "cancel-before-start",
        tenant_id,
        "https://example.com",
        {"methods": ["GET"], "profile": "focused", "max_discovered": 1},
    )
    job = service_module.get_job("cancel-before-start", tenant_id)
    assert job["state"] == "cancelled"


def test_worker_submit_failure_marks_job_failed(service_module, monkeypatch):
    tenant_id = service_module._token_tenant("test-token")
    monkeypatch.setattr(service_module, "_validate_target", lambda target: target)

    def fail_submit(*_args):
        raise RuntimeError("executor stopped")

    monkeypatch.setattr(service_module._executor, "submit", fail_submit)
    request = service_module.ScanRequest(target="https://example.com", authorized=True)
    with pytest.raises(service_module.HTTPException) as error:
        service_module.create_job(request, tenant_id)
    assert error.value.status_code == 503
    jobs = service_module.list_jobs(tenant_id, limit=100, state="failed")
    assert len(jobs["jobs"]) == 1


def test_reserve_job_enforces_quota_atomically(service_module):
    service_module._MAX_JOBS_PER_WINDOW = 1
    service_module._reserve_job(
        "reserved-job",
        "tenant-a",
        "https://example.com",
        {"methods": ["GET"], "profile": "focused", "max_discovered": 1},
    )
    with pytest.raises(service_module.HTTPException) as error:
        service_module._reserve_job(
            "rejected-job",
            "tenant-a",
            "https://example.com",
            {"methods": ["GET"], "profile": "focused", "max_discovered": 1},
        )
    assert error.value.status_code == 429
