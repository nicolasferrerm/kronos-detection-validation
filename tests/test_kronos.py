from pathlib import Path

from core.config import KronosConfig, load_config
from emulators import ASREPRoastEmulator, EntraAppGrantEmulator, KerberoastEmulator
from reports.generator import generate_report
from verifiers import MockVerifier


def test_missing_config_uses_safe_defaults(tmp_path: Path) -> None:
    config = load_config(str(tmp_path / "missing.yaml"))

    assert config.execution.allow_live_actions is False
    assert config.siem.provider == "mock"


def test_all_scenarios_are_simulated_by_default() -> None:
    config = KronosConfig()
    emulators = [
        ASREPRoastEmulator(config),
        KerberoastEmulator(config),
        EntraAppGrantEmulator(config),
    ]

    for emulator in emulators:
        result = emulator.run()
        assert result["status"] == "success"
        assert result["emulation_type"] == "simulated"


def test_mock_verifier_detects_successful_fixture() -> None:
    config = KronosConfig()
    emulator = ASREPRoastEmulator(config)
    result = emulator.run()

    verification = MockVerifier(config).verify_detection(
        result,
        event_id=emulator.event_id,
        mitre_id=emulator.mitre_id,
    )

    assert verification["detected"] is True
    assert verification["log_entries_found"] == 1
    assert "4768" in verification["query_used"]


def test_report_generation(tmp_path: Path) -> None:
    results = [
        {
            "emulator": {
                "name": "Safe fixture",
                "mitre_id": "T1558.004",
                "event_id": "4768",
                "description": "Synthetic test",
            },
            "emulation_result": {"status": "success"},
            "verifier": {
                "detected": True,
                "query_used": "EventCode=4768",
                "log_entries_found": 1,
                "raw_logs": [{"event_id": 4768}],
                "details": "Synthetic match",
            },
        }
    ]

    report = Path(generate_report(results, "Mock", str(tmp_path)))

    assert report.exists()
    content = report.read_text(encoding="utf-8")
    assert "Safe fixture" in content
    assert "T1558.004" in content
