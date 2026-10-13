import pytest

from red_wolf.cli import build_arg_parser, execute
from red_wolf.scope import ScopePolicy


def test_scope_allows_exact_and_wildcard_hosts(tmp_path):
    scope_file = tmp_path / "scope.txt"
    scope_file.write_text(
        "example.com\n*.authorized.example\n", encoding="utf-8"
    )
    policy = ScopePolicy.from_file(scope_file)

    assert policy.permits("https://example.com/login")
    assert policy.permits("https://authorized.example/")
    assert policy.permits("https://api.authorized.example:8443/")
    assert not policy.permits("https://not-authorized.example/")


def test_explicit_exclusions_override_wildcard_inclusion(tmp_path):
    scope_file = tmp_path / "scope.txt"
    scope_file.write_text(
        "*.example.com\n!internal.example.com\n", encoding="utf-8"
    )
    policy = ScopePolicy.from_file(scope_file)

    allowed, rejected = policy.filter_targets([
        "https://app.example.com",
        "https://internal.example.com",
        "https://outside.example",
    ])

    assert allowed == ["https://app.example.com"]
    assert rejected == [
        "https://internal.example.com",
        "https://outside.example",
    ]


@pytest.mark.parametrize(
    "contents",
    [
        "",
        "!excluded.example.com",
        "https://example.com/path",
        "*.example.com\napi.*.example.com",
        "*.192.0.2.1",
        "example.com#typo",
        "invalid host",
    ],
)
def test_invalid_scope_files_fail_closed(tmp_path, contents):
    scope_file = tmp_path / "scope.txt"
    scope_file.write_text(contents, encoding="utf-8")

    with pytest.raises(ValueError):
        ScopePolicy.from_file(scope_file)


def test_scope_file_option_is_available_from_cli():
    args = build_arg_parser().parse_args([
        "--url", "https://example.com",
        "--scope-file", "scope.txt",
    ])

    assert args.scope_file == "scope.txt"


def test_out_of_scope_target_is_rejected_before_scanning(tmp_path, monkeypatch, capsys):
    scope_file = tmp_path / "scope.txt"
    scope_file.write_text("allowed.example\n", encoding="utf-8")
    args = build_arg_parser().parse_args([
        "--url", "https://outside.example",
        "--scope-file", str(scope_file),
        "--i-am-authorized",
    ])

    def unexpected_scan(*_args, **_kwargs):
        pytest.fail("scanner must not be constructed for an out-of-scope target")

    monkeypatch.setattr("red_wolf.cli.UnauthAccessScanner", unexpected_scan)

    assert execute(args) == 1
    assert "No targets from the target input are included" in capsys.readouterr().err
