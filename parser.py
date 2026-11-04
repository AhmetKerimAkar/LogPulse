"""Erişim loglarını uygulama veri modellerine dönüştüren yardımcılar."""

import logging
import re
from typing import List

from models import LogEntry


logger = logging.getLogger(__name__)

_LOG_PATTERN = re.compile(
    r'^(?P<ip_address>\S+)\s+-\s+\[(?P<timestamp>[^\]]+)\]\s+'
    r'"(?P<http_method>[A-Z]+)\s+(?P<endpoint>.+)"\s+'
    r'(?P<status_code>\d{3})\s+(?P<response_time_ms>\d+(?:\.\d+)?)\s*$'
)


def parse_log_file(file_path: str) -> List[LogEntry]:
    """Log dosyasını ayrıştırarak geçerli satırlardan LogEntry listesi oluşturur."""

    log_entries: List[LogEntry] = []

    try:
        with open(file_path, "r", encoding="utf-8") as log_file:
            for line_number, raw_line in enumerate(log_file, start=1):
                raw_log = raw_line.rstrip("\r\n")

                try:
                    match = _LOG_PATTERN.match(raw_log)
                    if match is None:
                        raise ValueError("Log satırı beklenen formatla eşleşmiyor")

                    values = match.groupdict()
                    log_entries.append(
                        LogEntry(
                            ip_address=values["ip_address"],
                            timestamp=values["timestamp"],
                            http_method=values["http_method"],
                            endpoint=values["endpoint"],
                            status_code=int(values["status_code"]),
                            response_time_ms=float(values["response_time_ms"]),
                            raw_log=raw_log,
                        )
                    )
                except (TypeError, ValueError) as error:
                    logger.warning(
                        "Bozuk log satırı atlandı (satır %d): %s",
                        line_number,
                        error,
                    )
    except (OSError, UnicodeError) as error:
        logger.error("Log dosyası okunamadı (%s): %s", file_path, error)

    return log_entries