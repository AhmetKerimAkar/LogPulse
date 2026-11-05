"""Log anomalilerini tespit eden ve olay müdahale raporu üreten işlevler."""

import json
import logging
import re
from collections import Counter
from statistics import median
from typing import List

import pandas as pd
from sklearn.ensemble import IsolationForest

from models import AnomalyReport, LogEntry


logger = logging.getLogger(__name__)

_SUSPICIOUS_EXPRESSIONS = ("' or", "../", "admin", "login", "passwd")
_GEMINI_MODEL = "gemini-2.5-flash"
_MASKED_VALUE = "[MASKELENDİ]"


def _suspicious_score(endpoint: str) -> int:
    """Endpoint içinde tanımlı şüpheli ifadelerin kaç farklı türde olduğunu hesaplar."""

    normalized_endpoint = endpoint.lower()
    return sum(
        expression in normalized_endpoint
        for expression in _SUSPICIOUS_EXPRESSIONS
    )


def _risk_level(
    is_anomaly: bool,
    anomaly_score: float,
    status_code: int,
    suspicious_score: int,
) -> str:
    """Model sonucu ve güvenlik göstergelerine göre risk seviyesini belirler."""

    if (
        is_anomaly
        and (
            suspicious_score > 0
            or status_code >= 500
            or anomaly_score >= 0.1
        )
    ):
        return "Yüksek"
    if is_anomaly or status_code >= 400:
        return "Orta"
    return "Düşük"


def mask_sensitive_data(text: str) -> str:
    """URL ve log metnindeki kimlik doğrulama verilerini maskeler."""

    patterns = (
        r"(?i)(token|key|password|secret|session)=([^&\s\"']+)",
        r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+",
        r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b",
    )
    masked = text
    try:
        masked = re.sub(patterns[0], lambda match: f"{match.group(1)}={_MASKED_VALUE}", masked)
        masked = re.sub(patterns[1], _MASKED_VALUE, masked)
        masked = re.sub(patterns[2], _MASKED_VALUE, masked)
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
                    "response_time_ms": log.response_time_ms,
                    "endpoint_length": len(log.endpoint),
                    "suspicious_score": _suspicious_score(log.endpoint),
                }
                for log in logs
            ]
        )
        failed_login_counts = Counter(
            log.ip_address
            for log in logs
            if log.status_code in (401, 403)
            or log.endpoint.split("?", 1)[0].lower() == "/login"
        )
        model = IsolationForest(contamination="auto", random_state=42)
        predictions = model.fit_predict(data_frame)
        model_scores = -model.decision_function(data_frame)
        normal_times = [
            log.response_time_ms for log in logs if log.status_code == 200
        ]
        time_median = median(normal_times) if normal_times else 0.0
        time_std = (
            float(pd.Series(normal_times).std(ddof=0))
            if normal_times
            else 0.0
        )

        reports: List[AnomalyReport] = []
        for log, prediction, score in zip(logs, predictions, model_scores):
            suspicious_score = _suspicious_score(log.endpoint)
            numeric_score = float(score)
            failed_count = failed_login_counts[log.ip_address]
            z_score = (
                (log.response_time_ms - time_median) / time_std
                if time_std > 0
                else 0.0
            )
            high_latency = (
                log.status_code == 200
                and log.response_time_ms > 500
                and z_score > 2.5
            )
            model_candidate = (
                prediction == -1 and numeric_score > 0 and suspicious_score > 0
            )
            brute_force = (
                failed_count >= 3
                and (
                    log.status_code in (401, 403)
                    or log.endpoint.split("?", 1)[0].lower() == "/login"
                )
            )
            is_anomaly = (
                model_candidate
                or log.status_code >= 400
                or high_latency
                or brute_force
            )
            reports.append(
                AnomalyReport(
                    log_entry=log,
                    anomaly_score=numeric_score,
                    is_anomaly=is_anomaly,
                    risk_level=_risk_level(
                        is_anomaly,
                        numeric_score,
                        log.status_code,
                        suspicious_score,
                    ),
                )
            )
            if brute_force:
                reports[-1].risk_level = "Yüksek"
        return reports
    except (ValueError, TypeError, RuntimeError) as error:
        logger.error("Anomali analizi başarısız oldu: %s", error)
        return []


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
    ip_counts = Counter(report.log_entry.ip_address for report in relevant_reports)
    findings: List[str] = []

    sql_reports = [
        report for report in relevant_reports
        if "' or" in report.log_entry.endpoint.lower()
    ]
    if sql_reports:
        findings.append(
            f"- SQL Injection (SQLi): {len(sql_reports)} şüpheli istek; "
            "parametreli sorgu ve giriş doğrulaması uygulanmalıdır."
        )

    brute_force_ips = [
        ip for ip, count in ip_counts.items()
        if count >= 3
        and sum(
            report.log_entry.ip_address == ip
            and report.log_entry.status_code in (401, 403)
            for report in relevant_reports
        ) >= 3
    ]
    if brute_force_ips:
        findings.append(
            "- Brute Force (Kaba Kuvvet) Girişimi: Aynı kaynaktan tekrarlanan "
            "401 /login yetkisiz erişim denemeleri "
            f"({', '.join(brute_force_ips)}); hesap kilitleme ve oran sınırlama "
            "uygulanmalıdır."
        )

    traversal_reports = [
        report for report in relevant_reports
        if "../" in report.log_entry.endpoint
    ]
    if traversal_reports:
        findings.append(
            f"- Path Traversal: {len(traversal_reports)} dizin geçişi denemesi; "
            "endpoint normalizasyonu ve dosya erişim izinleri sıkılaştırılmalıdır."
        )

    if not findings:
        findings.append(
            "- Belirgin SQLi, Brute Force veya Path Traversal paterni bulunmadı; "
            "anomali kayıtları manuel olarak incelenmelidir."
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
        payload = json.dumps(
            [
                {
                    "ip_address": report.log_entry.ip_address,
                    "timestamp": report.log_entry.timestamp,
                    "endpoint": mask_sensitive_data(report.log_entry.endpoint),
                    "status_code": report.log_entry.status_code,
                    "response_time_ms": report.log_entry.response_time_ms,
                    "raw_log": mask_sensitive_data(report.log_entry.raw_log),
                    "anomaly_score": report.anomaly_score,
                    "risk_level": report.risk_level,
                }
                for report in anomaly_reports
            ],
            ensure_ascii=False,
            indent=2,
        )
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