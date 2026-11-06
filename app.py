"""LogPulse Streamlit tabanlı siber güvenlik kontrol paneli."""

import logging
import importlib
import os
import sys
import tempfile
from types import ModuleType
from typing import Any, Callable, List, Optional, Tuple

import pandas as pd
import streamlit as st

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

_PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
_SAMPLE_LOG_PATH = os.path.join(_PROJECT_ROOT, "sample.log")


def _reload_local_module(module_name: str) -> Optional[ModuleType]:
    """Yerel modülü canlı güncellemeleri alacak şekilde yeniden yükler."""

    try:
        module = importlib.import_module(module_name)
        return importlib.reload(module)
    except (ImportError, AttributeError) as error:
        logger.error("Yerel modül yüklenemedi (%s): %s", module_name, error)
        cached_module = sys.modules.get(module_name)
        return cached_module if isinstance(cached_module, ModuleType) else None


_models_module = _reload_local_module("models")
_parser_module = _reload_local_module("parser")
_analyzer_module = _reload_local_module("analyzer")


def _fallback_parse_log_file(file_path: str) -> List[Any]:
    """Parser kullanılamadığında güvenli boş kayıt listesi döndürür."""

    logger.error("Parser fonksiyonu kullanılamıyor: %s", file_path)
    return []


def _fallback_parse_log_file_with_stats(file_path: str) -> Tuple[List[Any], int]:
    """Parser istatistik fonksiyonu kullanılamadığında güvenli sonuç döndürür."""

    logger.error("Parser istatistik fonksiyonu kullanılamıyor: %s", file_path)
    return [], 0


def _fallback_detect_anomalies(
    logs: List[Any],
    auth_endpoints: Optional[List[str]] = None,
) -> List[Any]:
    """Analyzer kullanılamadığında güvenli boş rapor listesi döndürür."""

    logger.error("Anomali tespit fonksiyonu kullanılamıyor.")
    return []


def _fallback_benchmark() -> dict[str, dict[str, float]]:
    """Benchmark fonksiyonu kullanılamadığında güvenli boş sonuç döndürür."""

    logger.error("Benchmark fonksiyonu kullanılamıyor.")
    return {}


def _fallback_summary(reports: List[Any], api_key: str = "") -> str:
    """Özet fonksiyonu kullanılamadığında kullanıcıya açık hata döndürür."""

    logger.error("Olay özeti fonksiyonu kullanılamıyor.")
    return "Olay özeti oluşturulamadı; yerel analyzer modülü kullanılamıyor."


def _fallback_breakdown(reports: List[Any]) -> dict[str, int]:
    """Tespit kırılımı kullanılamadığında güvenli sıfır değerleri döndürür."""

    return {
        "Kural Tabanlı Tespit": 0,
        "Sadece ML (Isolation Forest) Tespiti": 0,
        "Hibrit (Kurallar + ML) Toplam": 0,
    }


def _fallback_payload(reports: List[Any]) -> str:
    """AI payload fonksiyonu kullanılamadığında güvenli boş JSON döndürür."""

    return "[]"


def _module_callable(
    module: Optional[ModuleType],
    name: str,
    fallback: Callable[..., Any],
) -> Callable[..., Any]:
    """Modüldeki fonksiyonu getattr ile güvenli fallback seçerek alır."""

    candidate = getattr(module, name, None) if module is not None else None
    return candidate if callable(candidate) else fallback


parse_log_file = _module_callable(
    _parser_module, "parse_log_file", _fallback_parse_log_file
)
parse_log_file_with_stats = _module_callable(
    _parser_module,
    "parse_log_file_with_stats",
    _fallback_parse_log_file_with_stats,
)
analyze_logs = _module_callable(
    _analyzer_module, "analyze_logs", _fallback_detect_anomalies
)
detect_anomalies = analyze_logs
evaluate_system_benchmark = _module_callable(
    _analyzer_module, "evaluate_system_benchmark", _fallback_benchmark
)
generate_incident_summary = _module_callable(
    _analyzer_module, "generate_incident_summary", _fallback_summary
)
get_detection_breakdown = _module_callable(
    _analyzer_module, "get_detection_breakdown", _fallback_breakdown
)
build_ai_payload = _module_callable(
    _analyzer_module, "build_ai_payload", _fallback_payload
)
AnomalyReport = getattr(_models_module, "AnomalyReport", Any)


def _read_uploaded_logs(
    uploaded_file: object,
    auth_endpoints: Optional[List[str]] = None,
) -> List[Any]:
    """Yüklenen log dosyasını geçici dosya üzerinden analiz eder."""

    reports, _ = _read_uploaded_logs_with_stats(uploaded_file, auth_endpoints)
    return reports


def _read_uploaded_logs_with_stats(
    uploaded_file: object,
    auth_endpoints: Optional[List[str]] = None,
) -> tuple[List[Any], int]:
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

        return detect_incidents_from_path_with_stats(temporary_path, auth_endpoints)
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


def detect_incidents_from_path(
    file_path: str,
    auth_endpoints: Optional[List[str]] = None,
) -> List[Any]:
    """Belirtilen log dosyasını okuyup anomali raporlarına dönüştürür."""

    logs = parse_log_file(file_path)
    return analyze_logs(logs, auth_endpoints)


def detect_incidents_from_path_with_stats(
    file_path: str,
    auth_endpoints: Optional[List[str]] = None,
) -> tuple[List[Any], int]:
    """Log dosyasını analiz eder ve atlanan satır sayısını da döndürür."""

    logs, skipped_lines = parse_log_file_with_stats(file_path)
    return analyze_logs(logs, auth_endpoints), skipped_lines


def _reports_to_dataframe(reports: List[Any]) -> pd.DataFrame:
    """Anomali raporlarını kontrol panelinde gösterilecek tabloya dönüştürür."""

    rows = []
    for report in reports:
        log_entry = getattr(report, "log_entry", None)
        response_time = getattr(log_entry, "response_time_ms", None)
        rows.append(
            {
                "IP Adresi": getattr(log_entry, "ip_address", "Bilinmiyor"),
                "Zaman": getattr(log_entry, "timestamp", "Bilinmiyor"),
                "Metot": getattr(log_entry, "http_method", "Bilinmiyor"),
                "Endpoint": getattr(log_entry, "endpoint", ""),
                "Durum": getattr(log_entry, "status_code", 0),
                "Yanıt (ms)": (
                    response_time
                    if response_time is not None
                    else "Kaydedilmemiş"
                ),
                "Anomali": "Evet" if getattr(report, "is_anomaly", False) else "Hayır",
                "Anomali Skoru": round(getattr(report, "anomaly_score", 0.0), 4),
                "Risk": getattr(report, "risk_level", "Düşük"),
                "Tetiklenen Kural / Neden": getattr(
                    report, "triggered_rule", "Normal Trafik"
                ),
            }
        )
    return pd.DataFrame(rows)


def _report_log_entry(report: object) -> object:
    """Raporun log kaydını güvenli varsayılanla döndürür."""

    return getattr(report, "log_entry", None)


def _report_is_anomaly(report: object) -> bool:
    """Raporun anomali alanını güvenli varsayılanla okur."""

    return bool(getattr(report, "is_anomaly", False))


def _report_risk(report: object) -> str:
    """Rapor risk seviyesini geçerli güvenli varsayılanla döndürür."""

    return str(getattr(report, "risk_level", "Düşük"))


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
        custom_auth_text = st.text_input(
            "Özel Giriş Adresleri (Brute Force)",
            help="Birden fazla adresi virgülle ayırın; örn. /v2/member-check, /custom-login",
        )
    custom_auth_endpoints = [
        item.strip() for item in custom_auth_text.split(",") if item.strip()
    ]

    if source == "Yeni .log dosyası":
        if uploaded_file is None:
            st.info("Analize başlamak için bir .log dosyası yükleyin.")
            return
        reports, skipped_lines = _read_uploaded_logs_with_stats(
            uploaded_file, custom_auth_endpoints
        )
    else:
        if not os.path.exists(_SAMPLE_LOG_PATH):
            st.error("sample.log dosyası bulunamadı.")
            return
        reports, skipped_lines = detect_incidents_from_path_with_stats(
            _SAMPLE_LOG_PATH, custom_auth_endpoints
        )

    if not reports:
        st.warning("Geçerli log kaydı bulunamadı veya analiz sonucu boş döndü.")
        return

    anomaly_count = sum(_report_is_anomaly(report) for report in reports)
    measured_times = [
        getattr(_report_log_entry(report), "response_time_ms", None)
        for report in reports
        if getattr(_report_log_entry(report), "response_time_ms", None) is not None
    ]
    average_response = (
        f"{sum(measured_times) / len(measured_times):.2f} ms"
        if measured_times
        else "Yanıt süresi kaydedilmemiş"
    )
    risk_order = {"Düşük": 1, "Orta": 2, "Yüksek": 3}
    highest_risk = max(
        (_report_risk(report) for report in reports),
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
    with st.expander("📊 Doğruluk ve Performans Ölçümü (Benchmark)"):
        benchmark = evaluate_system_benchmark()
        if benchmark:
            benchmark_rows = [
                {
                    "Sistem": name,
                    "Yakalanan Saldırı (TP)": values.get(
                        "Yakalanan Saldırı (True Positive)", 0
                    ),
                    "Yanlış Alarm (FP)": values.get(
                        "Yanlış Alarm (False Positive)", 0
                    ),
                    "Recall %": values.get("Yakalama Oranı (Recall %)", 0.0),
                    "Precision %": values.get("Kesinlik (Precision %)", 0.0),
                    "F1": values.get("F1 Skoru", 0.0),
                    "FPR %": values.get("Yanlış Alarm Oranı (FPR %)", 0.0),
                }
                for name, values in benchmark.items()
            ]
            st.dataframe(pd.DataFrame(benchmark_rows), hide_index=True)

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