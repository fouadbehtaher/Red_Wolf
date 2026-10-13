import json

from red_wolf.cli import build_arg_parser
from red_wolf.report import build_report_data, to_sarif, write_reports
from red_wolf.scanner import EndpointResult


def test_sarif_contains_rules_and_finding_evidence_without_response_snippet():
    results = [
        EndpointResult(
            url="https://example.com/api/users",
            method="GET",
            status_code=200,
            accessible=True,
            cors_wildcard=True,
            sensitive_data_found=True,
            sample_snippet="private-evidence-marker",
            evidence_score=85,
            evidence_reasons=["sensitive response structure"],
            verification_status="confirmed",
            confidence=95,
        ),
        EndpointResult(
            url="https://example.com/public",
            method="GET",
            status_code=200,
            accessible=True,
            cors_wildcard=True,
            verification_status="probable",
            confidence=70,
        ),
    ]
    report = build_report_data(
        "https://example.com",
        results,
        deep_findings=[{"downloaded": True}],
    )

    sarif = json.loads(to_sarif(report))
    run = sarif["runs"][0]

    assert sarif["version"] == "2.1.0"
    assert run["tool"]["driver"]["name"] == "Red Wolf"
    assert len(run["tool"]["driver"]["rules"]) == 2
    assert [result["level"] for result in run["results"]] == ["error", "note"]
    assert run["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == (
        "https://example.com/api/users"
    )
    assert run["results"][0]["properties"]["verificationStatus"] == "confirmed"
    assert run["results"][0]["properties"]["priorityIsHeuristic"] is True
    assert "private-evidence-marker" not in to_sarif(report)


def test_sarif_can_be_written_and_selected_from_cli(tmp_path):
    report = build_report_data("https://example.com", [])
    output_prefix = str(tmp_path / "scan")

    written = write_reports(report, output_prefix, formats=("sarif",))

    assert written == [f"{output_prefix}.sarif"]
    assert json.loads((tmp_path / "scan.sarif").read_text(encoding="utf-8"))["runs"][0]["results"] == []
    args = build_arg_parser().parse_args(["--format", "sarif", "json"])
    assert args.format == ["sarif", "json"]
