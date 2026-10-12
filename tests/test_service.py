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
