"""LogPulse parser ve analyzer birim testleri."""

from pathlib import Path
from typing import List

from analyzer import detect_anomalies, generate_incident_summary
from models import AnomalyReport, LogEntry
from parser import parse_log_file


def _log_line(
    ip_address: str,
    endpoint: str,
    status_code: int,
    response_time_ms: float,
) -> str:
    """Testlerde kullanılacak erişim logu satırı oluşturur."""

    return (
        f'{ip_address} - [2026-11-04 20:10:01] '
        f'"GET {endpoint}" {status_code} {response_time_ms}'
    )


def parse_log_file_from_text(raw_log: str) -> LogEntry:
    """Tek bir test satırını parser ile LogEntry nesnesine dönüştürür."""

    import tempfile

    with tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        suffix=".log",
        delete=False,
    ) as log_file:
        log_file.write(raw_log)
        file_path = Path(log_file.name)
    try:
        entries = parse_log_file(str(file_path))
        assert entries
        return entries[0]
    finally:
        file_path.unlink()


def _make_logs() -> List[LogEntry]:
    """Isolation Forest testi için yeterli çeşitlilikte log kayıtları üretir."""

    lines = [
        _log_line("192.168.1.1", "/home", 200, 20.0),
        _log_line("192.168.1.2", "/products", 200, 25.0),
        _log_line("192.168.1.3", "/about", 200, 30.0),
        _log_line("192.168.1.4", "/contact", 200, 35.0),
        _log_line("10.0.0.99", "/login", 401, 900.0),
    ]
    return [parse_log_file_from_text(line) for line in lines]


def test_parse_log_file_parses_valid_lines(tmp_path: Path) -> None:
    """Geçerli log satırlarının doğru alanlara ayrıştırıldığını doğrular."""

    log_path = tmp_path / "valid.log"
    log_path.write_text(
        _log_line("192.168.1.10", "/home", 200, 42.5) + "\n",
        encoding="utf-8",
    )

    entries = parse_log_file(str(log_path))

    assert len(entries) == 1
    assert entries[0].ip_address == "192.168.1.10"
    assert entries[0].endpoint == "/home"
    assert entries[0].status_code == 200
    assert entries[0].response_time_ms == 42.5


def test_parse_log_file_skips_invalid_lines(tmp_path: Path) -> None:
    """Bozuk satırların atlanıp geçerli satırların korunmasını doğrular."""

    log_path = tmp_path / "mixed.log"
    log_path.write_text(
        "bozuk log satırı\n"
        + _log_line("192.168.1.10", "/valid", 200, 12.0)
        + "\n",
        encoding="utf-8",
    )

    entries = parse_log_file(str(log_path))

    assert len(entries) == 1
    assert entries[0].endpoint == "/valid"


def test_parse_log_file_returns_empty_for_missing_file(tmp_path: Path) -> None:
    """Bulunamayan dosyada parser'ın boş liste döndürdüğünü doğrular."""

    entries = parse_log_file(str(tmp_path / "missing.log"))

    assert entries == []


def test_detect_anomalies_returns_report_for_each_log() -> None:
    """Anomali analizinin her log için AnomalyReport ürettiğini doğrular."""

    reports = detect_anomalies(_make_logs())

    assert len(reports) == 5
    assert all(isinstance(report, AnomalyReport) for report in reports)
    assert any(report.is_anomaly for report in reports)


def test_detect_anomalies_marks_suspicious_request_high_risk() -> None:
    """Şüpheli login isteğinin yüksek riskli raporlanmasını doğrular."""

    reports = detect_anomalies(_make_logs())

    suspicious_report = next(
        report for report in reports if report.log_entry.endpoint == "/login"
    )
    assert suspicious_report.is_anomaly is True
    assert suspicious_report.risk_level == "Yüksek"


def test_generate_incident_summary_uses_rule_based_fallback() -> None:
    """API anahtarı olmadan SQLi ve path traversal bulgularının raporlandığını doğrular."""

    logs = [
        parse_log_file_from_text(
            _log_line("10.0.0.1", "/search?id=1' OR '1'='1", 500, 300.0)
        ),
        parse_log_file_from_text(
            _log_line("10.0.0.2", "/../../etc/passwd", 403, 250.0)
        ),
    ]
    reports = detect_anomalies(logs)

    summary = generate_incident_summary(reports)

    assert "SİBER GÜVENLİK OLAY MÜDAHALE RAPORU" in summary
    assert "SQL Injection (SQLi)" in summary
    assert "Path Traversal" in summary


def test_generate_incident_summary_handles_empty_anomalies() -> None:
    """Anomali listesi boş olduğunda fallback raporunun üretildiğini doğrular."""

    summary = generate_incident_summary([])

    assert "Analiz edilecek anomali tespit edilmedi." in summary