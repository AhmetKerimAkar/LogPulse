"""Log anomalilerini tespit eden ve olay müdahale raporu üreten işlevler."""

import json
import logging
import re
from collections import Counter
from datetime import datetime
from statistics import median
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import unquote_plus

import pandas as pd
from sklearn.ensemble import IsolationForest

from models import AnomalyReport, LogEntry
from parser import parse_timestamp


logger = logging.getLogger(__name__)

_SQLI_EXPRESSIONS = ("' or", "1=1", "union select")
_TRAVERSAL_EXPRESSIONS = ("../", "etc/passwd")
_GEMINI_MODEL = "gemini-2.5-flash"
_MASKED_VALUE = "[MASKELENDİ]"


def _suspicious_score(endpoint: str) -> int:
    """Endpoint içinde tanımlı şüpheli ifadelerin kaç farklı türde olduğunu hesaplar."""

    normalized_endpoint = unquote_plus(endpoint).lower()
    return sum(
        expression in normalized_endpoint
        for expression in (*_SQLI_EXPRESSIONS, *_TRAVERSAL_EXPRESSIONS, "/admin/config")
    )


def _decoded_attack_rule(endpoint: str) -> Optional[str]:
    """URL çözülmüş endpoint için saldırı kuralı açıklaması üretir."""

    decoded_endpoint = unquote_plus(endpoint).lower()
    for expression in _SQLI_EXPRESSIONS:
        if expression in decoded_endpoint:
            return (
                "SQL Injection Şüphesi: URL-decoded endpoint içinde "
                f"({expression}) deseni"
            )
    for expression in _TRAVERSAL_EXPRESSIONS:
        if expression in decoded_endpoint:
            return (
                "Path Traversal Şüphesi: URL-decoded endpoint içinde "
                f"({expression}) deseni"
            )
    if "/admin/config" in decoded_endpoint:
        return "Admin/Config erişim şüphesi: korumalı yapılandırma endpoint'i"
    return None


def is_auth_endpoint(
    endpoint: str,
    custom_auth_paths: Optional[List[str]] = None,
) -> bool:
    """Endpoint'in varsayılan veya kullanıcı tanımlı auth desenine uyup uymadığını belirler."""

    path = endpoint.split("?", 1)[0].lower().rstrip("/")
    default_paths = (
        "/login", "/wp-login", "wp-login.php", "/api/login", "/signin",
        "/auth", "/token", "/session", "/admin", "/oauth",
    )
    configured_paths = [
        item.strip().lower().split("?", 1)[0].rstrip("/")
        for item in (custom_auth_paths or [])
        if item.strip()
    ]
    return any(pattern in path for pattern in (*default_paths, *configured_paths))


def _window_indices(
    entries: List[Tuple[int, datetime]],
    threshold: int,
) -> Tuple[Set[int], Dict[int, int]]:
    """Sıralı IP kayıtlarında iki işaretçiyle eşik üstü pencere indekslerini bulur."""

    intervals: List[Tuple[int, int, int]] = []
    left = 0
    for right, (_, right_time) in enumerate(entries):
        while (
            right_time - entries[left][1]
        ).total_seconds() > 300:
            left += 1
        window_size = right - left + 1
        if window_size >= threshold:
            intervals.append((left, right, window_size))
    flagged: Set[int] = set()
    counts: Dict[int, int] = {}
    merged: List[Tuple[int, int, int]] = []
    for start, end, size in intervals:
        if merged and start <= merged[-1][1] + 1:
            previous_start, previous_end, previous_size = merged[-1]
            merged[-1] = (
                previous_start,
                max(previous_end, end),
                max(previous_size, size),
            )
        else:
            merged.append((start, end, size))
    for start, end, size in merged:
        for position in range(start, end + 1):
            index = entries[position][0]
            flagged.add(index)
            counts[index] = size
    return flagged, counts


def _precompute_window_flags(
    logs: List[LogEntry],
    custom_auth_paths: Optional[List[str]] = None,
) -> Tuple[Set[int], Dict[int, int], Set[int], Dict[str, Tuple[Set[int], Set[str]]]]:
    """Zamanları IP bazında bir kez sıralayıp auth ve 404 pencerelerini hesaplar."""

    auth_by_ip: Dict[str, List[Tuple[int, datetime]]] = {}
    not_found_by_ip: Dict[str, List[Tuple[int, datetime]]] = {}
    auth_evidence: Dict[str, Tuple[Set[int], Set[str]]] = {}
    for index, log in enumerate(logs):
        timestamp = parse_timestamp(log.timestamp)
        if timestamp is None:
            continue
        if log.status_code in (401, 403) and is_auth_endpoint(
            log.endpoint, custom_auth_paths
        ):
            auth_by_ip.setdefault(log.ip_address, []).append((index, timestamp))
            statuses, endpoints = auth_evidence.setdefault(
                log.ip_address, (set(), set())
            )
            statuses.add(log.status_code)
            endpoints.add(log.endpoint)
        if log.status_code == 404:
            not_found_by_ip.setdefault(log.ip_address, []).append((index, timestamp))

    brute_force_indices: Set[int] = set()
    brute_force_counts: Dict[int, int] = {}
    scan_indices: Set[int] = set()
    for entries in auth_by_ip.values():
        entries.sort(key=lambda item: item[1])
        indices, counts = _window_indices(entries, 3)
        brute_force_indices.update(indices)
        brute_force_counts.update(counts)
    for entries in not_found_by_ip.values():
        entries.sort(key=lambda item: item[1])
        indices, _ = _window_indices(entries, 5)
        scan_indices.update(indices)
    return brute_force_indices, brute_force_counts, scan_indices, auth_evidence


def mask_sensitive_data(text: str) -> str:
    """URL ve log metnindeki kimlik doğrulama verilerini maskeler."""

    patterns = (
        r"(?i)(pwd|pass|passwd|password|token|key|secret|session|email|mail)=([^&\s\"']+)",
        r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+",
        r"(?i)\b[A-Z0-9._%+-]+(?:@|%40)[A-Z0-9.-]+\.[A-Z]{2,}\b",
        r"\b(?P<first>\d{1,3}\.\d{1,3}\.\d{1,3})\.\d{1,3}\b",
    )
    masked = text
    try:
        masked = re.sub(patterns[0], lambda match: f"{match.group(1)}={_MASKED_VALUE}", masked)
        masked = re.sub(patterns[1], _MASKED_VALUE, masked)
        masked = re.sub(patterns[2], _MASKED_VALUE, masked)
        masked = re.sub(patterns[3], r"\g<first>.xxx", masked)
    except (TypeError, re.error) as error:
        logger.error("Hassas veri maskelenemedi: %s", error)
    return masked


def analyze_logs(
    logs: List[LogEntry],
    auth_endpoints: Optional[List[str]] = None,
) -> List[AnomalyReport]:
    """Logları Isolation Forest ile analiz ederek anomali raporları üretir."""

    if not logs:
        return []

    try:
        data_frame = pd.DataFrame(
            [
                {
                    "status_code": log.status_code,
                    "response_time_ms": log.response_time_ms or 0.0,
                    "endpoint_length": len(log.endpoint),
                    "suspicious_score": _suspicious_score(log.endpoint),
                }
                for log in logs
            ]
        )
        (
            brute_force_indices,
            brute_force_counts,
            scan_indices,
            auth_evidence,
        ) = _precompute_window_flags(logs, auth_endpoints)
        model = IsolationForest(contamination="auto", random_state=42)
        predictions = model.fit_predict(data_frame)
        model_scores = -pd.Series(model.decision_function(data_frame)).to_numpy()
        normal_times = [
            log.response_time_ms for log in logs if log.status_code == 200
            and log.response_time_ms is not None
        ]
        time_median = median(normal_times) if normal_times else 0.0
        time_std = (
            float(pd.Series(normal_times).std(ddof=0))
            if normal_times
            else 0.0
        )
        endpoint_lengths = [len(log.endpoint) for log in logs]
        endpoint_median = median(endpoint_lengths)
        endpoint_std = float(pd.Series(endpoint_lengths).std(ddof=0))

        reports: List[AnomalyReport] = []
        for index, (log, prediction, score) in enumerate(
            zip(logs, predictions, model_scores)
        ):
            attack_rule = _decoded_attack_rule(log.endpoint)
            suspicious_score = _suspicious_score(log.endpoint)
            numeric_score = float(score)
            failed_count = brute_force_counts.get(index, 0)
            z_score = (
                (log.response_time_ms - time_median) / time_std
                if time_std > 0 and log.response_time_ms is not None
                else 0.0
            )
            endpoint_z_score = (
                (len(log.endpoint) - endpoint_median) / endpoint_std
                if endpoint_std > 0
                else 0.0
            )
            high_latency = (
                log.status_code >= 500
                and log.response_time_ms is not None
                and log.response_time_ms >= 2000
                and z_score > 2.5
            )
            model_candidate = (
                prediction == -1
                and numeric_score > 0
                and suspicious_score == 0
                and log.status_code == 200
                and (
                    (log.response_time_ms is not None
                     and log.response_time_ms > 1000
                     and z_score > 2.5)
                    or abs(endpoint_z_score) > 2.5
                )
            )
            brute_force = (
                log.status_code in (401, 403)
                and index in brute_force_indices
            )
            unauthorized = log.status_code in (401, 403)
            repeated_not_found = (
                log.status_code == 404
                and index in scan_indices
            )
            rule_flagged = (
                attack_rule is not None
                or brute_force
                or high_latency
                or log.status_code >= 500
                or repeated_not_found
                or unauthorized
            )
            ml_flagged = model_candidate
            if attack_rule:
                triggered_rule = attack_rule
            elif brute_force:
                auth_statuses, auth_paths = auth_evidence.get(
                    log.ip_address, (set(), {log.endpoint})
                )
                triggered_rule = (
                    f"Brute Force: {log.ip_address} adresinden 5 dk içinde "
                    f"{failed_count} adet {', '.join(map(str, sorted(auth_statuses)))} "
                    f"başarısız giriş ({', '.join(sorted(auth_paths))})"
                )
            elif high_latency:
                triggered_rule = "Yüksek Yanıt Süresi + Sunucu Hatası (500)"
            elif model_candidate:
                triggered_rule = (
                    "ML Anomalisi (Isolation Forest): İstatistiksel "
                    "yanıt süresi/istek sapması"
                )
            elif high_latency:
                triggered_rule = "Yüksek Yanıt Süresi (200 OK, z-score > 2.5)"
            elif log.status_code >= 500:
                triggered_rule = f"Sunucu Hatası ({log.status_code})"
            elif repeated_not_found:
                triggered_rule = (
                    f"Tekrarlı 404 taraması: {log.ip_address} adresinden "
                    "5 dk içinde 5 veya daha fazla 404 yanıtı"
                )
            elif log.status_code in (401, 403):
                triggered_rule = "Yetkisiz Erişim Denemesi (Tekil 401/403)"
            else:
                triggered_rule = "Normal Trafik"
            is_anomaly = (
                attack_rule is not None
                or model_candidate
                or brute_force
                or unauthorized
                or rule_flagged
                or ml_flagged
            )
            risk_level = (
                "Yüksek"
                if (
                    attack_rule
                    or brute_force
                    or (high_latency and log.status_code >= 500)
                )
                else "Orta" if is_anomaly else "Düşük"
            )
            reports.append(
                AnomalyReport(
                    log_entry=log,
                    anomaly_score=numeric_score,
                    is_anomaly=is_anomaly,
                    risk_level=risk_level,
                    triggered_rule=triggered_rule,
                    rule_flagged=rule_flagged,
                    ml_flagged=ml_flagged,
                )
            )
        return reports
    except (ValueError, TypeError, RuntimeError) as error:
        logger.error("Anomali analizi başarısız oldu: %s", error)
        return []


def detect_anomalies(
    logs: List[LogEntry],
    auth_endpoints: Optional[List[str]] = None,
) -> List[AnomalyReport]:
    """Eski analyzer API'sini koruyarak logları analiz eder."""

    return analyze_logs(logs, auth_endpoints)


def get_detection_breakdown(reports: List[AnomalyReport]) -> Dict[str, int]:
    """Anomali raporlarını kural, yalnızca ML ve hibrit kategorilerine ayırır."""

    rule_reports = [report for report in reports if report.rule_flagged]
    ml_only = [
        report for report in reports
        if report.ml_flagged and not report.rule_flagged
    ]
    combined = [
        report for report in reports
        if report.rule_flagged or report.ml_flagged
    ]
    return {
        "Kural Tabanlı Tespit": len(rule_reports),
        "Sadece ML (Isolation Forest) Tespiti": len(ml_only),
        "Hibrit (Kurallar + ML) Toplam": len(combined),
    }


def _benchmark_entry(
    index: int,
    endpoint: str,
    status_code: int,
    response_time_ms: float,
    ip_address: str,
) -> LogEntry:
    """Benchmark veri kümesi için tek bir log kaydı oluşturur."""

    return LogEntry(
        ip_address=ip_address,
        timestamp=f"2026-11-07 12:00:{index % 60:02d}",
        http_method="POST" if "login" in endpoint else "GET",
        endpoint=endpoint,
        status_code=status_code,
        response_time_ms=response_time_ms,
        raw_log="benchmark",
    )


def _benchmark_metrics(
    predictions: List[bool],
    labels: List[bool],
) -> Dict[str, float]:
    """Tahmin ve ground-truth listelerinden sınıflandırma ölçümlerini hesaplar."""

    true_positive = sum(prediction and label for prediction, label in zip(predictions, labels))
    false_positive = sum(
        prediction and not label for prediction, label in zip(predictions, labels)
    )
    false_negative = sum(
        not prediction and label for prediction, label in zip(predictions, labels)
    )
    true_negative = sum(
        not prediction and not label for prediction, label in zip(predictions, labels)
    )
    recall = true_positive / (true_positive + false_negative) if (
        true_positive + false_negative
    ) else 0.0
    precision = true_positive / (true_positive + false_positive) if (
        true_positive + false_positive
    ) else 0.0
    f1 = (
        2 * precision * recall / (precision + recall)
        if precision + recall
        else 0.0
    )
    fpr = false_positive / (false_positive + true_negative) if (
        false_positive + true_negative
    ) else 0.0
    return {
        "true_positive": float(true_positive),
        "false_positive": float(false_positive),
        "recall": recall,
        "precision": precision,
        "f1": f1,
        "fpr": fpr,
        "Yakalanan Saldırı (True Positive)": float(true_positive),
        "Yanlış Alarm (False Positive)": float(false_positive),
        "Yakalama Oranı (Recall %)": recall * 100,
        "Kesinlik (Precision %)": precision * 100,
        "F1 Skoru": f1,
        "Yanlış Alarm Oranı (FPR %)": fpr * 100,
    }


def evaluate_system_benchmark() -> Dict[str, Dict[str, float]]:
    """Etiketli saldırı kümesiyle kural, ML ve birleşik sistemi ölçer."""

    logs: List[LogEntry] = []
    labels: List[bool] = []
    for index in range(100):
        logs.append(_benchmark_entry(index, "/home", 200, 100.0 + index % 3, f"10.0.10.{index}"))
        labels.append(False)
    logs.extend([
        _benchmark_entry(100, "/favicon.ico", 404, 20.0, "10.0.20.1"),
        _benchmark_entry(101, "/login", 200, 100.0, "10.0.20.2"),
        _benchmark_entry(102, "/login", 200, 101.0, "10.0.20.2"),
    ])
    labels.extend([False, False, False])

    attack_logs: List[LogEntry] = []
    attack_labels: List[bool] = []
    for offset, endpoint in enumerate(("/login", "/wp-login.php", "/api/login")):
        for attempt in range(3):
            attack_logs.append(
                _benchmark_entry(
                    110 + offset * 3 + attempt,
                    endpoint,
                    401,
                    120.0,
                    f"10.0.30.{offset + 1}",
                )
            )
            attack_labels.append(True)
    attack_logs.extend([
        _benchmark_entry(120, "/search?q=%27%20OR%201%3D1", 200, 100.0, "10.0.31.1"),
        _benchmark_entry(121, "/../../etc/passwd", 403, 100.0, "10.0.31.2"),
    ])
    attack_labels.extend([True, True])
    for attempt in range(5):
        attack_logs.append(
            _benchmark_entry(130 + attempt, f"/missing-{attempt}", 404, 20.0, "10.0.32.1")
        )
        attack_labels.append(True)
    attack_logs.append(_benchmark_entry(140, "/home", 200, 3500.0, "10.0.33.1"))
    attack_labels.append(True)
    logs.extend(attack_logs)
    labels.extend(attack_labels)

    reports = analyze_logs(logs)
    strategies = {
        "Yalnızca Kurallar": [report.rule_flagged for report in reports],
        "Yalnızca ML (Isolation Forest)": [report.ml_flagged for report in reports],
        "Birleşik Sistem (Kurallar + ML)": [
            report.rule_flagged or report.ml_flagged for report in reports
        ],
    }
    return {
        name: _benchmark_metrics(predictions, labels)
        for name, predictions in strategies.items()
    }


def build_ai_payload(reports: List[AnomalyReport]) -> str:
    """AI önizlemesi ve Gemini isteği için aynı maskelenmiş JSON metnini üretir."""

    try:
        return json.dumps(
            [
                {
                    "IP": mask_sensitive_data(report.log_entry.ip_address),
                    "timestamp": report.log_entry.timestamp,
                    "method": report.log_entry.http_method,
                    "endpoint": mask_sensitive_data(report.log_entry.endpoint),
                    "status_code": report.log_entry.status_code,
                    "risk_level": report.risk_level,
                    "triggered_rule": mask_sensitive_data(report.triggered_rule),
                }
                for report in reports
                if report.is_anomaly
            ],
            ensure_ascii=False,
            indent=2,
        )
    except (TypeError, ValueError) as error:
        logger.error("AI payload oluşturulamadı: %s", error)
        return "[]"


def _rule_based_summary(anomalies: List[AnomalyReport]) -> str:
    """Anomalileri güvenlik kurallarıyla değerlendirerek Türkçe rapor üretir."""

    if not anomalies:
        return (
            "SİBER GÜVENLİK OLAY MÜDAHALE RAPORU\n"
            "Yöntem: Kural Tabanlı Yerel Analiz Motoru "
            "(Yedek Mod / API Anahtarı Yok veya Hata)\n\n"
            "İncelenen anomali sayısı: 0\n"
            "Sistemde herhangi bir anomali veya siber tehdit tespit edilmedi.\n"
            "Analiz edilecek anomali tespit edilmedi."
        )

    reports = [report for report in anomalies if report.is_anomaly]
    if not reports:
        return (
            "SİBER GÜVENLİK OLAY MÜDAHALE RAPORU\n"
            "Yöntem: Kural Tabanlı Yerel Analiz Motoru "
            "(Yedek Mod / API Anahtarı Yok veya Hata)\n\n"
            "İncelenen anomali sayısı: 0\n"
            "Sistemde herhangi bir anomali veya siber tehdit tespit edilmedi.\n"
            "Analiz edilecek anomali tespit edilmedi."
        )
    relevant_reports = reports
    status_counts = Counter(
        report.log_entry.status_code for report in relevant_reports
    )
    findings: List[str] = []

    sql_reports = [
        report for report in relevant_reports
        if "SQL Injection" in report.triggered_rule
    ]
    if sql_reports:
        findings.append(
            f"- SQL Injection (SQLi): {len(sql_reports)} şüpheli istek; "
            "parametreli sorgu ve giriş doğrulaması uygulanmalıdır."
        )

    brute_force_reports = [
        report for report in relevant_reports if "Brute Force" in report.triggered_rule
    ]
    if brute_force_reports:
        brute_force_ips = sorted({
            report.log_entry.ip_address for report in brute_force_reports
        })
        brute_force_evidence = sorted({
            f"{report.log_entry.status_code} {report.log_entry.endpoint}"
            for report in brute_force_reports
        })
        findings.append(
            "- Brute Force (Kaba Kuvvet) Girişimi: Aynı kaynaktan tekrarlanan "
            f"yetkisiz erişim denemeleri ({', '.join(brute_force_evidence)}; "
            f"IP: {', '.join(brute_force_ips)}); hesap kilitleme ve oran sınırlama "
            "uygulanmalıdır."
        )

    traversal_reports = [
        report for report in relevant_reports
        if "Path Traversal" in report.triggered_rule
    ]
    if traversal_reports:
        findings.append(
            f"- Path Traversal: {len(traversal_reports)} dizin geçişi denemesi; "
            "endpoint normalizasyonu ve dosya erişim izinleri sıkılaştırılmalıdır."
        )

    if not findings:
        findings.append(
            "- Belirgin saldırı paterni bulunmadı; anomali kayıtları manuel olarak "
            "incelenmelidir."
        )

    status_summary = ", ".join(
        f"{status}: {count}" for status, count in sorted(status_counts.items())
    )
    return (
        "SİBER GÜVENLİK OLAY MÜDAHALE RAPORU\n"
        "Yöntem: Kural Tabanlı Yerel Analiz Motoru "
        "(Yedek Mod / API Anahtarı Yok veya Hata)\n\n"
        f"İncelenen anomali sayısı: {len(relevant_reports)}\n"
        f"Durum kodu dağılımı: {status_summary}\n\n"
        "TESPİTLER\n"
        f"{chr(10).join(findings)}\n\n"
        "KAYIT BAZLI TETİKLENEN KURALLAR\n"
        f"{chr(10).join(f'- {report.triggered_rule}' for report in relevant_reports)}\n\n"
        "ÖNERİLEN AKSİYONLAR\n"
        "1. Etkilenen IP adreslerini ve istek zamanlarını güvenlik duvarı/WAF "
        "kayıtlarıyla korele edin.\n"
        "2. Şüpheli kaynakları geçici olarak engelleyin ve ilgili kimlik bilgilerini "
        "döndürün.\n"
        "3. Uygulama, web sunucusu ve veritabanı loglarını koruyarak adli inceleme "
        "için saklayın.\n"
        "4. Yama, giriş doğrulama, WAF kuralı ve oran sınırlama kontrollerini "
        "doğrulayın."
    )


def generate_incident_summary(
    anomalies: List[AnomalyReport],
    api_key: str = "",
) -> str:
    """Anomaliler için Gemini destekli veya kural tabanlı Türkçe olay raporu üretir."""

    anomaly_reports = [report for report in anomalies if report.is_anomaly]
    fallback_report = _rule_based_summary(anomaly_reports)
    if not api_key:
        return fallback_report

    try:
        import google.generativeai as genai

        genai.configure(api_key=api_key)
        model = genai.GenerativeModel(_GEMINI_MODEL)
        payload = build_ai_payload(anomaly_reports)
        prompt = (
            "Aşağıdaki web erişim logu anomali raporlarını Türkçe, profesyonel "
            "bir Siber Güvenlik Olay Müdahale raporuna dönüştür. SQLi, Brute "
            "Force ve Path Traversal bulgularını; etkilenen IP'leri, kanıtları, "
            "önceliklendirmeyi ve uygulanabilir müdahale adımlarını belirt. "
            "Veri dışı iddialar üretme.\n\n"
            f"Rapor verisi:\n{payload}"
        )
        response = model.generate_content(prompt)
        summary = getattr(response, "text", "")
        if not summary:
            raise ValueError("Gemini boş yanıt döndürdü")
        return f"{summary}\n\nYöntem: Gemini 2.5 Flash AI"
    except Exception as error:
        logger.error("Gemini olay özeti üretilemedi: %s", error)
        return fallback_report