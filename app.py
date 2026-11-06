"""LogPulse Streamlit tabanlı siber güvenlik kontrol paneli."""

import logging
import os
import tempfile
from typing import List, Optional

import pandas as pd
import streamlit as st

from analyzer import (
    build_ai_payload,
    detect_anomalies,
    get_detection_breakdown,
    generate_incident_summary,
)
from models import AnomalyReport
from parser import parse_log_file, parse_log_file_with_stats


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

_PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
_SAMPLE_LOG_PATH = os.path.join(_PROJECT_ROOT, "sample.log")


def _read_uploaded_logs(uploaded_file: object) -> List[AnomalyReport]:
    """Yüklenen log dosyasını geçici dosya üzerinden analiz eder."""

    reports, _ = _read_uploaded_logs_with_stats(uploaded_file)
    return reports


def _read_uploaded_logs_with_stats(
    uploaded_file: object,
) -> tuple[List[AnomalyReport], int]:
    """Yüklenen log dosyasını analiz ederek atlanan satırları da döndürür."""

    temporary_path: Optional[str] = None
    try:
        file_name = getattr(uploaded_file, "name", "uploaded.log")
        if not str(file_name).lower().endswith(".log"):
            st.error("Lütfen yalnızca .log uzantılı bir dosya yükleyin.")
            return [], 0

        with tempfile.NamedTemporaryFile(
            mode="wb",
            suffix=".log",
            delete=False,
        ) as temporary_file:
            temporary_file.write(uploaded_file.getvalue())
            temporary_path = temporary_file.name

        return detect_incidents_from_path_with_stats(temporary_path)
    except (OSError, TypeError, ValueError) as error:
        logger.error("Yüklenen log dosyası işlenemedi: %s", error)
        st.error("Yüklenen dosya işlenemedi.")
        return [], 0
    finally:
        if temporary_path is not None:
            try:
                os.remove(temporary_path)
            except OSError as error:
                logger.warning("Geçici dosya silinemedi: %s", error)


def detect_incidents_from_path(file_path: str) -> List[AnomalyReport]:
    """Belirtilen log dosyasını okuyup anomali raporlarına dönüştürür."""

    logs = parse_log_file(file_path)
    return detect_anomalies(logs)


def detect_incidents_from_path_with_stats(
    file_path: str,
) -> tuple[List[AnomalyReport], int]:
    """Log dosyasını analiz eder ve atlanan satır sayısını da döndürür."""

    logs, skipped_lines = parse_log_file_with_stats(file_path)
    return detect_anomalies(logs), skipped_lines


def _reports_to_dataframe(reports: List[AnomalyReport]) -> pd.DataFrame:
    """Anomali raporlarını kontrol panelinde gösterilecek tabloya dönüştürür."""

    rows = []
    for report in reports:
        log_entry = report.log_entry
        rows.append(
            {
                "IP Adresi": log_entry.ip_address,
                "Zaman": log_entry.timestamp,
                "Metot": log_entry.http_method,
                "Endpoint": log_entry.endpoint,
                "Durum": log_entry.status_code,
                "Yanıt (ms)": (
                    log_entry.response_time_ms
                    if log_entry.response_time_ms is not None
                    else "Kaydedilmemiş"
                ),
                "Anomali": "Evet" if report.is_anomaly else "Hayır",
                "Anomali Skoru": round(report.anomaly_score, 4),
                "Risk": report.risk_level,
                "Tetiklenen Kural / Neden": report.triggered_rule,
            }
        )
    return pd.DataFrame(rows)


def _risk_color(row: pd.Series) -> List[str]:
    """Tablodaki risk ve anomali hücreleri için renk stilleri döndürür."""

    styles = [""] * len(row)
    risk_index = row.index.get_loc("Risk")
    anomaly_index = row.index.get_loc("Anomali")
    risk_colors = {"Yüksek": "#fecaca", "Orta": "#fef3c7", "Düşük": "#dcfce7"}
    styles[risk_index] = f"background-color: {risk_colors.get(row['Risk'], '')}"
    if row["Anomali"] == "Evet":
        styles[anomaly_index] = "background-color: #fee2e2; color: #991b1b"
    return styles


def main() -> None:
    """LogPulse kontrol panelini oluşturur ve Streamlit üzerinde çalıştırır."""

    st.set_page_config(
        page_title="LogPulse | AI Log Analizi",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="expanded",
    )
    st.title("🛡️ LogPulse")
    st.caption("AI Destekli Log Analiz ve Anomali Tespit Motoru")

    with st.sidebar:
        st.header("⚙️ Veri Kaynağı")
        source = st.radio(
            "Analiz kaynağı",
            ("sample.log", "Yeni .log dosyası"),
            index=0,
        )
        uploaded_file = st.file_uploader(
            "Log dosyası yükle",
            type=["log"],
            help="Sunucu erişim logu formatında bir .log dosyası seçin.",
        )
        api_key = st.text_input(
            "Gemini API Key (isteğe bağlı)",
            type="password",
            help="Boş bırakılırsa kural tabanlı rapor üretilir.",
        )

    if source == "Yeni .log dosyası":
        if uploaded_file is None:
            st.info("Analize başlamak için bir .log dosyası yükleyin.")
            return
        reports, skipped_lines = _read_uploaded_logs_with_stats(uploaded_file)
    else:
        if not os.path.exists(_SAMPLE_LOG_PATH):
            st.error("sample.log dosyası bulunamadı.")
            return
        reports, skipped_lines = detect_incidents_from_path_with_stats(_SAMPLE_LOG_PATH)

    if not reports:
        st.warning("Geçerli log kaydı bulunamadı veya analiz sonucu boş döndü.")
        return

    anomaly_count = sum(report.is_anomaly for report in reports)
    measured_times = [
        report.log_entry.response_time_ms
        for report in reports
        if report.log_entry.response_time_ms is not None
    ]
    average_response = (
        f"{sum(measured_times) / len(measured_times):.2f} ms"
        if measured_times
        else "Yanıt süresi kaydedilmemiş"
    )
    risk_order = {"Düşük": 1, "Orta": 2, "Yüksek": 3}
    highest_risk = max(
        (report.risk_level for report in reports),
        key=lambda risk: risk_order[risk],
    )

    metric_columns = st.columns(5)
    metric_columns[0].metric("Toplam Log Sayısı", len(reports))
    metric_columns[1].metric("Tespit Edilen Anomali", anomaly_count)
    metric_columns[2].metric("Ortalama Yanıt Süresi", average_response)
    metric_columns[3].metric("En Yüksek Risk", highest_risk)
    metric_columns[4].metric("Atlanan / Hatalı Satır", skipped_lines)

    breakdown = get_detection_breakdown(reports)
    st.subheader("🔎 Tespit Katmanı Dağılımı")
    st.dataframe(
        pd.DataFrame([breakdown]),
        width="stretch",
        hide_index=True,
    )

    st.subheader("📋 Log ve Anomali Detayları")
    data_frame = _reports_to_dataframe(reports)
    st.dataframe(
        data_frame.style.apply(_risk_color, axis=1),
        width="stretch",
        hide_index=True,
    )

    st.subheader("⏱️ Yanıt Süresi Analizi")
    if measured_times:
        chart_data = pd.DataFrame({"Yanıt Süresi (ms)": measured_times})
        st.line_chart(chart_data, width="stretch")
    else:
        st.info("Yanıt süresi kaydedilmemiş")

    st.subheader("🚨 Olay Müdahale")
    if api_key.strip():
        st.info("Rapor yöntemi: Gemini 2.5 Flash AI")
    else:
        st.caption(
            "Rapor yöntemi: Kural Tabanlı Yerel Analiz Motoru "
            "(Yedek Mod / API Anahtarı Yok veya Hata)"
        )
    preview = build_ai_payload(reports)
    with st.expander("AI'ya Gönderilecek Maskelenmiş Veri Önizlemesi"):
        st.code(preview, language="json")
    if st.button(
        "Olay Müdahale (Incident Response) Raporu Oluştur",
        type="primary",
        width="stretch",
    ):
        with st.spinner("Olay müdahale raporu hazırlanıyor..."):
            summary = generate_incident_summary(reports, api_key.strip())
        st.success("Rapor oluşturuldu.")
        st.markdown(
            f'<div style="background-color:#111827;color:#f9fafb;padding:1.25rem;'
            f'border-radius:0.75rem;white-space:pre-wrap">{summary}</div>',
            unsafe_allow_html=True,
        )


if __name__ == "__main__":
    main()