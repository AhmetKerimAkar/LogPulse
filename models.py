"""LogPulse uygulamasının veri modelleri."""

from typing import Literal

from pydantic import BaseModel


class LogEntry(BaseModel):
    """Bir web sunucusu erişim logu kaydını temsil eder."""

    ip_address: str
    timestamp: str
    http_method: str
    endpoint: str
    status_code: int
    response_time_ms: float
    raw_log: str


class AnomalyReport(BaseModel):
    """Bir erişim logu için anomali tespiti ve risk değerlendirmesini temsil eder."""

    log_entry: LogEntry
    anomaly_score: float
    is_anomaly: bool
    risk_level: Literal["Düşük", "Orta", "Yüksek"]