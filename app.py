"""LogPulse Streamlit tabanlı siber güvenlik kontrol paneli."""

import logging
import os
import tempfile
from typing import List, Optional

import pandas as pd
import streamlit as st

from analyzer import generate_incident_summary, detect_anomalies
from models import AnomalyReport
from parser import parse_log_file


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

_PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
_SAMPLE_LOG_PATH = os.path.join(_PROJECT_ROOT, "sample.log")


def _read_uploaded_logs(uploaded_file: object) -> List[AnomalyReport]:
    """Yüklenen log dosyasını geçici dosya üzerinden analiz eder."""

    temporary_path: Optional[str] = None
    try:
        file_name = getattr(uploaded_file, "name", "uploaded.log")
        if not str(file_name).lower().endswith(".log"):
            st.error("Lütfen yalnızca .log uzantılı bir dosya yükleyin.")
            return []

        with tempfile.NamedTemporaryFile(
            mode="wb",
            suffix=".log",
            delete=False,
        ) as temporary_file:
            temporary_file.write(uploaded_file.getvalue())
            temporary_path = temporary_file.name

        return detect_incidents_from_path(temporary_path)
    except (OSError, TypeError, ValueError) as error:
        logger.error("Yüklenen log dosyası işlenemedi: %s", error)
        st.error("Yüklenen dosya işlenemedi.")
        return []
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
                "Yanıt (ms)": log_entry.response_time_ms,
                "Anomali": "Evet" if report.is_anomaly else "Hayır",
                "Anomali Skoru": round(report.anomaly_score, 4),
                "Risk": report.risk_level,
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
        reports = _read_uploaded_logs(uploaded_file)
    else:
        if not os.path.exists(_SAMPLE_LOG_PATH):
            st.error("sample.log dosyası bulunamadı.")
            return
        reports = detect_incidents_from_path(_SAMPLE_LOG_PATH)

    if not reports:
        st.warning("Geçerli log kaydı bulunamadı veya analiz sonucu boş döndü.")
        return

    anomaly_count = sum(report.is_anomaly for report in reports)
    average_response = sum(
        report.log_entry.response_time_ms for report in reports
    ) / len(reports)
    risk_order = {"Düşük": 1, "Orta": 2, "Yüksek": 3}
    highest_risk = max(
        (report.risk_level for report in reports),
        key=lambda risk: risk_order[risk],
    )

    metric_columns = st.columns(4)
    metric_columns[0].metric("Toplam Log Sayısı", len(reports))
    metric_columns[1].metric("Tespit Edilen Anomali", anomaly_count)
    metric_columns[2].metric("Ortalama Yanıt Süresi", f"{average_response:.2f} ms")
    metric_columns[3].metric("En Yüksek Risk", highest_risk)

    st.subheader("📋 Log ve Anomali Detayları")
    data_frame = _reports_to_dataframe(reports)
    st.dataframe(
        data_frame.style.apply(_risk_color, axis=1),
        width="stretch",
        hide_index=True,
    )

    st.subheader("⏱️ Yanıt Süresi Analizi")
    chart_data = pd.DataFrame(
        {
            "Yanıt Süresi (ms)": [
                report.log_entry.response_time_ms for report in reports
            ]
        }
    )
    st.line_chart(chart_data, width="stretch")

    st.subheader("🚨 Olay Müdahale")
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