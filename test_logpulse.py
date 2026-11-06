"""LogPulse parser ve analyzer birim testleri."""

from pathlib import Path
from time import perf_counter
from typing import List
from unittest.mock import patch

import analyzer
from analyzer import (
    build_ai_payload,
    detect_anomalies,
    evaluate_system_benchmark,
    get_detection_breakdown,
    generate_incident_summary,
    is_auth_endpoint,
    mask_sensitive_data,
)
from models import AnomalyReport, LogEntry
from parser import parse_log_file, parse_log_file_with_stats


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
    assert suspicious_report.risk_level == "Orta"


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
    assert "İncelenen anomali sayısı: 0" in summary
    assert "Sistemde herhangi bir anomali veya siber tehdit tespit edilmedi." in summary


def test_detect_anomalies_has_no_false_positives_for_normal_traffic() -> None:
    """Tek tip 200 OK trafiğinin yanlış alarm üretmediğini doğrular."""

    logs = [
        parse_log_file_from_text(
            _log_line("192.168.1.1", "/home", 200, 100.0 + index % 3)
        )
        for index in range(100)
    ]

    assert sum(report.is_anomaly for report in detect_anomalies(logs)) == 0


def test_detect_anomalies_marks_repeated_failed_logins_as_brute_force() -> None:
    """Aynı IP'den gelen üç başarısız girişin tamamının işaretlendiğini doğrular."""

    logs = [
        parse_log_file_from_text(
            _log_line("10.0.0.9", "/login", 401, 200.0 + index)
        )
        for index in range(3)
    ]
    reports = detect_anomalies(logs)

    assert all(report.is_anomaly for report in reports)
    assert all(report.risk_level == "Yüksek" for report in reports)
    assert "Brute Force (Kaba Kuvvet) Girişimi" in generate_incident_summary(reports)


def test_parse_common_log_format_and_counts_invalid_lines(tmp_path: Path) -> None:
    """CLF satırlarının ve atlanan satır istatistiğinin doğru olduğunu doğrular."""

    log_path = tmp_path / "combined.log"
    log_path.write_text(
        '127.0.0.1 - - [10/Oct/2026:13:55:36 +0300] '
        '"GET /index.html HTTP/1.1" 200 2326\n'
        "bozuk satır\n",
        encoding="utf-8",
    )

    entries, skipped_lines = parse_log_file_with_stats(str(log_path))

    assert len(entries) == 1
    assert skipped_lines == 1
    assert entries[0].endpoint == "/index.html"
    assert entries[0].response_time_ms is None


def test_mask_sensitive_data_masks_credentials_and_personal_data() -> None:
    """Token, e-posta ve Bearer bilgilerinin rapor verisinden çıkarıldığını doğrular."""

    masked = mask_sensitive_data(
        "https://example.test?token=abc&email=user@example.test "
        "Authorization: Bearer abc.def.ghi password=hunter2"
    )

    assert "[MASKELENDİ]" in masked
    assert "abc.def.ghi" not in masked
    assert "user@example.test" not in masked
    assert "hunter2" not in masked


def test_successful_login_requests_are_normal() -> None:
    """Üç başarılı login isteğinin brute force alarmı üretmediğini doğrular."""

    logs = [
        parse_log_file_from_text(
            _log_line("10.0.0.9", "/login", 200, 200.0 + index)
        )
        for index in range(3)
    ]
    reports = detect_anomalies(logs)

    assert all(report.is_anomaly is False for report in reports)
    assert all(report.risk_level == "Düşük" for report in reports)


def test_single_favicon_not_found_is_normal() -> None:
    """Tekil favicon 404 kaydının zararsız kabul edildiğini doğrular."""

    report = detect_anomalies(
        [parse_log_file_from_text(_log_line("10.0.0.9", "/favicon.ico", 404, 20.0))]
    )[0]

    assert report.is_anomaly is False
    assert report.risk_level == "Düşük"


def test_encoded_sql_injection_is_detected_on_success_response() -> None:
    """URL kodlu SQL injection saldırısının 200 yanıtla da yakalandığını doğrular."""

    report = detect_anomalies(
        [
            parse_log_file_from_text(
                _log_line("10.0.0.9", "/search?q=%27%20OR%201%3D1", 200, 20.0)
            )
        ]
    )[0]

    assert report.is_anomaly is True
    assert report.risk_level == "Yüksek"
    assert "SQL Injection" in report.triggered_rule


def test_each_anomaly_has_triggered_rule() -> None:
    """Her anomali raporunun açıklayıcı tetikleme kuralı içerdiğini doğrular."""

    reports = detect_anomalies(_make_logs())

    assert all(
        report.triggered_rule and report.triggered_rule != "Normal Trafik"
        for report in reports
        if report.is_anomaly
    )


def _failed_login(timestamp: str) -> LogEntry:
    """Belirtilen zamanda tekil başarısız login kaydı oluşturur."""

    return LogEntry(
        ip_address="10.0.0.20",
        timestamp=timestamp,
        http_method="GET",
        endpoint="/login",
        status_code=401,
        response_time_ms=50.0,
        raw_log="",
    )


def test_summary_does_not_infer_brute_force_from_distant_failures() -> None:
    """Beş dakikadan uzak başarısız girişlerin özette brute force üretmediğini doğrular."""

    reports = detect_anomalies([
        _failed_login("2026-11-04 09:00:00"),
        _failed_login("2026-11-04 12:00:00"),
        _failed_login("2026-11-04 15:00:00"),
    ])

    assert "Brute Force" not in generate_incident_summary(reports)


def test_eight_minute_failed_login_spread_is_not_brute_force() -> None:
    """İlk ve son kayıt arası sekiz dakika olan kümenin işaretlenmediğini doğrular."""

    reports = detect_anomalies([
        _failed_login("2026-11-04 12:00:00"),
        _failed_login("2026-11-04 12:04:00"),
        _failed_login("2026-11-04 12:08:00"),
    ])

    assert all("Brute Force" not in report.triggered_rule for report in reports)


def test_single_unauthorized_login_is_medium_risk() -> None:
    """Tekil 401 login kaydının orta riskli olduğunu doğrular."""

    report = detect_anomalies([_failed_login("2026-11-04 12:00:00")])[0]

    assert report.risk_level == "Orta"
    assert report.triggered_rule == "Yetkisiz Erişim Denemesi (Tekil 401/403)"


def test_naive_and_timezone_log_records_are_processed_together() -> None:
    """Saat dilimli ve saat dilimsiz kayıtların birlikte işlendiğini doğrular."""

    logs = [
        LogEntry(
            ip_address="10.0.0.21",
            timestamp="2026-11-04 12:00:00",
            http_method="GET",
            endpoint="/home",
            status_code=200,
            response_time_ms=20.0,
            raw_log="",
        ),
        LogEntry(
            ip_address="10.0.0.22",
            timestamp="04/Nov/2026:12:01:00 +0300",
            http_method="GET",
            endpoint="/home",
            status_code=200,
            response_time_ms=21.0,
            raw_log="",
        ),
    ]

    assert len(detect_anomalies(logs)) == 2


def test_slow_successful_request_is_detected_by_isolation_forest() -> None:
    """Kural içermeyen aşırı yavaş 200 isteğinin yalnızca ML ile yakalandığını doğrular."""

    logs = [
        LogEntry(
            ip_address=f"10.0.1.{index}",
            timestamp=f"2026-11-04 20:10:{index:02d}",
            http_method="GET",
            endpoint="/home",
            status_code=200,
            response_time_ms=100.0 + index % 3,
            raw_log="",
        )
        for index in range(100)
    ]
    logs.append(
        LogEntry(
            ip_address="10.0.1.200",
            timestamp="2026-11-04 20:12:00",
            http_method="GET",
            endpoint="/home",
            status_code=200,
            response_time_ms=3500.0,
            raw_log="",
        )
    )

    report = detect_anomalies(logs)[-1]

    assert report.is_anomaly is True
    assert report.risk_level == "Orta"
    assert report.triggered_rule.startswith("ML Anomalisi (Isolation Forest)")


def test_masked_ai_payload_matches_preview_data() -> None:
    """URL kodlu e-posta ve parola maskelenmesini ve ortak payload üretimini doğrular."""

    report = detect_anomalies([
        LogEntry(
            ip_address="10.0.0.23",
            timestamp="2026-11-04 12:00:00",
            http_method="GET",
            endpoint="/login?pwd=demo-secret&email=user%40example.com",
            status_code=401,
            response_time_ms=20.0,
            raw_log="GET /login?pwd=demo-secret&email=user%40example.com",
        )
    ])[0]

    payload = build_ai_payload([report])
    assert "demo-secret" not in payload
    assert "user%40example.com" not in payload
    assert "raw_log" not in payload
    assert payload == build_ai_payload([report])


def test_clf_file_to_summary_detects_brute_force(tmp_path: Path) -> None:
    """CLF dosyasından üretilen raporda üç login denemesinin tamamını doğrular."""

    log_path = tmp_path / "brute-force.log"
    log_path.write_text(
        "\n".join(
            f'10.0.0.30 - - [07/Nov/2026:12:0{minute}:00 +0000] '
            f'"POST /login HTTP/1.1" 401 120'
            for minute in range(3)
        ),
        encoding="utf-8",
    )

    reports = detect_anomalies(parse_log_file(str(log_path)))

    assert len(reports) == 3
    assert all(report.is_anomaly for report in reports)
    assert all(report.risk_level == "Yüksek" for report in reports)
    assert all("Brute Force" in report.triggered_rule for report in reports)
    assert "Brute Force" in generate_incident_summary(reports)


def test_unrelated_unauthorized_requests_are_not_brute_force(tmp_path: Path) -> None:
    """Kimlik doğrulama dışı üç 401 isteğinin brute force olmadığını doğrular."""

    log_path = tmp_path / "orders.log"
    log_path.write_text(
        "\n".join(
            f'10.0.0.31 - - [07/Nov/2026:12:0{minute}:00 +0000] '
            f'"GET /orders HTTP/1.1" 401 120'
            for minute in range(3)
        ),
        encoding="utf-8",
    )

    reports = detect_anomalies(parse_log_file(str(log_path)))

    assert all("Brute Force" not in report.triggered_rule for report in reports)
    assert all(report.risk_level == "Orta" for report in reports)


def test_404_scan_requires_five_minute_window(tmp_path: Path) -> None:
    """404 taramasının yalnızca beş dakikalık pencere içinde işaretlendiğini doğrular."""

    spread_path = tmp_path / "spread-404.log"
    spread_path.write_text(
        "\n".join(
            f'10.0.0.32 - - [07/Nov/2026:{hour:02d}:00:00 +0000] '
            f'"GET /missing-{hour} HTTP/1.1" 404 120'
            for hour in range(5)
        ),
        encoding="utf-8",
    )
    clustered_path = tmp_path / "clustered-404.log"
    clustered_path.write_text(
        "\n".join(
            f'10.0.0.32 - - [07/Nov/2026:12:0{minute}:00 +0000] '
            f'"GET /missing-{minute} HTTP/1.1" 404 120'
            for minute in range(5)
        ),
        encoding="utf-8",
    )

    spread_reports = detect_anomalies(parse_log_file(str(spread_path)))
    clustered_reports = detect_anomalies(parse_log_file(str(clustered_path)))

    assert all("tarama" not in report.triggered_rule for report in spread_reports)
    assert all("5 dk içinde 5" in report.triggered_rule for report in clustered_reports)


def test_slow_success_is_ml_only_and_normal_model_is_not_anomaly() -> None:
    """Saf gecikmenin kural değil ML katkısı olduğunu ve normal modelde alarm vermediğini doğrular."""

    logs = [
        LogEntry(
            ip_address=f"10.0.2.{index}",
            timestamp=f"2026-11-07 12:00:{index:02d}",
            http_method="GET",
            endpoint="/home",
            status_code=200,
            response_time_ms=100.0,
            raw_log="",
        )
        for index in range(100)
    ]
    logs.append(
        LogEntry(
            ip_address="10.0.2.200",
            timestamp="2026-11-07 12:02:00",
            http_method="GET",
            endpoint="/home",
            status_code=200,
            response_time_ms=3500.0,
            raw_log="",
        )
    )

    report = detect_anomalies(logs)[-1]
    assert report.ml_flagged is True
    assert report.rule_flagged is False
    assert report.is_anomaly is True
    assert get_detection_breakdown([report]) == {
        "Kural Tabanlı Tespit": 0,
        "Sadece ML (Isolation Forest) Tespiti": 1,
        "Hibrit (Kurallar + ML) Toplam": 1,
    }

    class NormalModel:
        """Test için tüm kayıtları normal kabul eden model taklidi."""

        def fit_predict(self, data: object) -> List[int]:
            """Tüm kayıtlar için normal tahmin döndürür."""

            return [1] * len(data)  # type: ignore[arg-type]

        def decision_function(self, data: object) -> List[float]:
            """Tüm kayıtlar için sıfır anomali skoru döndürür."""

            return [0.0] * len(data)  # type: ignore[arg-type]

    with patch.object(analyzer, "IsolationForest", return_value=NormalModel()):
        normal_report = detect_anomalies(logs)[-1]

    assert normal_report.is_anomaly is False
    assert normal_report.rule_flagged is False
    assert normal_report.ml_flagged is False


def test_ai_payload_contains_only_structured_masked_fields() -> None:
    """AI payload'ının ham log yerine yapısal ve maskelenmiş alanlar içerdiğini doğrular."""

    report = detect_anomalies([
        LogEntry(
            ip_address="192.168.10.22",
            timestamp="2026-11-07 12:00:00",
            http_method="POST",
            endpoint="/login?password=hunter2",
            status_code=401,
            response_time_ms=20.0,
            raw_log="SECRET RAW LOG password=hunter2",
        )
    ])[0]

    payload = build_ai_payload([report])

    assert "raw_log" not in payload
    assert "SECRET RAW LOG" not in payload
    assert "hunter2" not in payload
    assert all(
        field in payload
        for field in (
            "timestamp",
            "IP",
            "method",
            "endpoint",
            "status_code",
            "risk_level",
            "triggered_rule",
        )
    )


def test_extended_default_auth_endpoints_are_brute_force() -> None:
    """WordPress ve API login yollarının varsayılan auth eşleşmesini doğrular."""

    logs = [
        LogEntry(
            ip_address="10.0.40.1",
            timestamp=f"2026-11-07 12:{minute:02d}:00",
            http_method="POST",
            endpoint=endpoint,
            status_code=401,
            response_time_ms=50.0,
            raw_log="",
        )
        for endpoint in ("/wp-login.php", "/api/login")
        for minute in range(3)
    ]
    reports = detect_anomalies(logs)

    assert is_auth_endpoint("/wp-login.php")
    assert is_auth_endpoint("/api/login")
    assert all(report.is_anomaly for report in reports)
    assert all(report.risk_level == "Yüksek" for report in reports)
    assert all("Brute Force" in report.triggered_rule for report in reports)


def test_custom_auth_endpoint_is_brute_force() -> None:
    """Kullanıcı tanımlı auth yolunun üç başarısız denemeyi yakaladığını doğrular."""

    logs = [
        LogEntry(
            ip_address="10.0.40.2",
            timestamp=f"2026-11-07 12:0{index}:00",
            http_method="POST",
            endpoint="/v2/member-check",
            status_code=401,
            response_time_ms=50.0,
            raw_log="",
        )
        for index in range(3)
    ]

    reports = analyzer.analyze_logs(logs, ["/v2/member-check"])

    assert all("Brute Force" in report.triggered_rule for report in reports)
    assert all(report.risk_level == "Yüksek" for report in reports)


def test_five_hundred_404_records_use_fast_sliding_window() -> None:
    """Aynı IP'deki 500 adet 404 kaydının kayan pencereyle hızlı işlendiğini doğrular."""

    logs = [
        LogEntry(
            ip_address="10.0.40.3",
            timestamp="2026-11-07 12:00:00",
            http_method="GET",
            endpoint=f"/missing-{index}",
            status_code=404,
            response_time_ms=20.0,
            raw_log="",
        )
        for index in range(500)
    ]

    started = perf_counter()
    reports = detect_anomalies(logs)
    elapsed = perf_counter() - started

    assert len(reports) == 500
    assert all("5 dk içinde 5" in report.triggered_rule for report in reports)
    assert elapsed < 0.5


def test_evaluate_system_benchmark_reports_combined_quality() -> None:
    """Etiketli benchmark'ın ölçümleri ve birleşik sistem üstünlüğünü doğrular."""

    benchmark = evaluate_system_benchmark()
    rules = benchmark["Yalnızca Kurallar"]
    ml = benchmark["Yalnızca ML (Isolation Forest)"]
    combined = benchmark["Birleşik Sistem (Kurallar + ML)"]

    assert combined["recall"] >= rules["recall"]
    assert combined["recall"] >= ml["recall"]
    assert combined["fpr"] <= 0.05