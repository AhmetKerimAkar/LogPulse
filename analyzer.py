"""Log anomalilerini tespit eden ve olay müdahale raporu üreten işlevler."""

import json
import logging
from collections import Counter
from typing import Dict, List

import pandas as pd
from sklearn.ensemble import IsolationForest

from models import AnomalyReport, LogEntry


logger = logging.getLogger(__name__)

_SUSPICIOUS_EXPRESSIONS = ("' or", "../", "admin", "login", "passwd")


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
        model = IsolationForest(contamination=0.3, random_state=42)
        predictions = model.fit_predict(data_frame)
        model_scores = -model.decision_function(data_frame)

        reports: List[AnomalyReport] = []
        for log, prediction, score in zip(logs, predictions, model_scores):
            suspicious_score = _suspicious_score(log.endpoint)
            is_anomaly = prediction == -1
            numeric_score = float(score)
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
        return reports
    except (ValueError, TypeError, RuntimeError) as error:
        logger.error("Anomali analizi başarısız oldu: %s", error)
        return []


def _rule_based_summary(anomalies: List[AnomalyReport]) -> str:
    """Anomalileri güvenlik kurallarıyla değerlendirerek Türkçe rapor üretir."""

    if not anomalies:
        return (
            "SİBER GÜVENLİK OLAY MÜDAHALE RAPORU\n\n"
            "Analiz edilecek anomali tespit edilmedi."
        )

    reports = [report for report in anomalies if report.is_anomaly]
    relevant_reports = reports or anomalies
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
            "- Brute Force: Aynı kaynaktan tekrarlanan yetkisiz erişim denemeleri "
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
        "SİBER GÜVENLİK OLAY MÜDAHALE RAPORU\n\n"
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

    fallback_report = _rule_based_summary(anomalies)
    if not api_key:
        return fallback_report

    try:
        import google.generativeai as genai

        genai.configure(api_key=api_key)
        model = genai.GenerativeModel("gemini-1.5-flash")
        payload = json.dumps(
            [report.model_dump() for report in anomalies],
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
        return summary
    except Exception as error:
        logger.error("Gemini olay özeti üretilemedi: %s", error)
        return fallback_report