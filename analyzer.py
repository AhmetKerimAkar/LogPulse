"""Log anomalilerini tespit eden ve olay müdahale raporu üreten işlevler."""

import json
import logging
import re
from collections import Counter
from datetime import datetime, timezone
from statistics import median
from typing import Dict, List, Optional, Tuple
from urllib.parse import unquote_plus

import pandas as pd
from sklearn.ensemble import IsolationForest

from models import AnomalyReport, LogEntry


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


def _parse_timestamp(timestamp: str) -> Optional[datetime]:
    """Sample ve CLF zaman damgalarını datetime nesnesine dönüştürür."""

    for format_string in ("%Y-%m-%d %H:%M:%S", "%d/%b/%Y:%H:%M:%S %z"):
        try:
            parsed = datetime.strptime(timestamp, format_string)
            if parsed.tzinfo is not None:
                parsed = parsed.astimezone(timezone.utc)
            return parsed.replace(tzinfo=None)
        except ValueError:
            continue
    logger.warning("Zaman damgası ayrıştırılamadı: %s", timestamp)
    return None


def _brute_force_window_counts(logs: List[LogEntry]) -> List[int]:
    """Her başlangıç kaydı için ileriye dönük 300 saniyelik pencereyi hesaplar."""

    failed_by_ip: dict[str, List[Tuple[int, Optional[datetime]]]] = {}
    for index, log in enumerate(logs):
        if log.status_code in (401, 403):
            failed_by_ip.setdefault(log.ip_address, []).append(
                (index, _parse_timestamp(log.timestamp))
            )

    counts = [0] * len(logs)
    for failures in failed_by_ip.values():
        ordered = sorted(
            (item for item in failures if item[1] is not None),
            key=lambda item: item[1],
        )
        for start_position, (start_index, start_time) in enumerate(ordered):
            cluster = [
                item for item in ordered[start_position:]
                if (item[1] - start_time).total_seconds() <= 300
            ]
            if len(cluster) >= 3:
                for cluster_index, _ in cluster:
                    counts[cluster_index] = max(counts[cluster_index], len(cluster))
    return counts


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


def detect_anomalies(logs: List[LogEntry]) -> List[AnomalyReport]:
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
        brute_force_counts = _brute_force_window_counts(logs)
        model = IsolationForest(contamination="auto", random_state=42)
        predictions = model.fit_predict(data_frame)
        model_scores = -model.decision_function(data_frame)
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
            failed_count = brute_force_counts[index]
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
                log.status_code == 200
                and log.response_time_ms is not None
                and log.response_time_ms > 1000
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
            brute_force = log.status_code in (401, 403) and failed_count >= 3
            unauthorized = log.status_code in (401, 403)
            repeated_not_found = (
                log.status_code == 404
                and sum(
                    other.ip_address == log.ip_address
                    and other.status_code == 404
                    for other in logs
                ) >= 5
            )
            if attack_rule:
                triggered_rule = attack_rule
            elif brute_force:
                triggered_rule = (
                    f"Brute Force: {log.ip_address} adresinden 5 dk içinde "
                    f"{failed_count} adet {log.status_code} başarısız giriş"
                )
            elif high_latency and log.status_code >= 500:
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
                    "5 veya daha fazla 404 yanıtı"
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
                or high_latency
                or log.status_code >= 500
                or repeated_not_found
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
                )
            )
        return reports
    except (ValueError, TypeError, RuntimeError) as error:
        logger.error("Anomali analizi başarısız oldu: %s", error)
        return []


def get_detection_breakdown(reports: List[AnomalyReport]) -> Dict[str, int]:
    """Anomali raporlarını kural, yalnızca ML ve hibrit kategorilerine ayırır."""

    anomaly_reports = [report for report in reports if report.is_anomaly]
    ml_only = [
        report for report in anomaly_reports
        if report.triggered_rule.startswith("ML Anomalisi (Isolation Forest)")
    ]
    rule_reports = [report for report in anomaly_reports if report not in ml_only]
    hybrid = [
        report for report in rule_reports
        if report.anomaly_score > 0
    ]
    return {
        "Kural Tabanlı Tespit": len(rule_reports) - len(hybrid),
        "Sadece ML (Isolation Forest) Tespiti": len(ml_only),
        "Hibrit (Kurallar + ML) Toplam": len(hybrid),
    }


def build_ai_payload(reports: List[AnomalyReport]) -> str:
    """AI önizlemesi ve Gemini isteği için aynı maskelenmiş JSON metnini üretir."""

    try:
        return json.dumps(
            [
                {
                    "IP": mask_sensitive_data(report.log_entry.ip_address),
                    "timestamp": report.log_entry.timestamp,
                    "endpoint": mask_sensitive_data(report.log_entry.endpoint),
                    "status_code": report.log_entry.status_code,
                    "raw_log": mask_sensitive_data(report.log_entry.raw_log),
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

    brute_force_ips = sorted({
        report.log_entry.ip_address
        for report in relevant_reports
        if "Brute Force" in report.triggered_rule
    })
    if brute_force_ips:
        findings.append(
            "- Brute Force (Kaba Kuvvet) Girişimi: Aynı kaynaktan tekrarlanan "
            "401 /login yetkisiz erişim denemeleri "
            f"({', '.join(brute_force_ips)}); hesap kilitleme ve oran sınırlama "
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