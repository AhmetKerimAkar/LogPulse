"""Erişim loglarını uygulama veri modellerine dönüştüren yardımcılar."""

import logging
import re
from typing import List, Tuple

from models import LogEntry


logger = logging.getLogger(__name__)

_LOG_PATTERN = re.compile(
    r'^(?P<ip_address>\S+)\s+-\s+(?:-\s+)?\[(?P<timestamp>[^\]]+)\]\s+'
    r'"(?P<http_method>[A-Z]+)\s+(?P<endpoint>.+)"\s+'
    r'(?P<status_code>\d{3})(?:\s+(?P<extra_fields>.*))?$'
)


def parse_log_file(file_path: str) -> List[LogEntry]:
    """Log dosyasını ayrıştırarak geçerli satırlardan LogEntry listesi oluşturur."""

    entries, _ = parse_log_file_with_stats(file_path)
    return entries


def parse_log_file_with_stats(file_path: str) -> Tuple[List[LogEntry], int]:
    """Log kayıtlarını ve ayrıştırılamayan satırların sayısını döndürür."""

    log_entries: List[LogEntry] = []
    skipped_lines = 0

    try:
        with open(file_path, "r", encoding="utf-8") as log_file:
            for line_number, raw_line in enumerate(log_file, start=1):
                raw_log = raw_line.rstrip("\r\n")

                try:
                    match = _LOG_PATTERN.match(raw_log)
                    if match is None:
                        raise ValueError("Log satırı beklenen formatla eşleşmiyor")

                    values = match.groupdict()
                    endpoint = values["endpoint"]
                    if " HTTP/" in endpoint:
                        endpoint = endpoint.rsplit(" HTTP/", 1)[0]
                    extra_fields = (values["extra_fields"] or "").split()
                    response_time_ms = 0.0
                    if extra_fields and "/" not in values["timestamp"]:
                        try:
                            response_time_ms = float(extra_fields[-1])
                        except ValueError:
                            response_time_ms = 0.0
                    log_entries.append(
                        LogEntry(
                            ip_address=values["ip_address"],
                            timestamp=values["timestamp"],
                            http_method=values["http_method"],
                            endpoint=endpoint,
                            status_code=int(values["status_code"]),
                            response_time_ms=response_time_ms,
                            raw_log=raw_log,
                        )
                    )
                except (TypeError, ValueError) as error:
                    skipped_lines += 1
                    logger.warning(
                        "Bozuk log satırı atlandı (satır %d): %s",
                        line_number,
                        error,
                    )
    except (OSError, UnicodeError) as error:
        logger.error("Log dosyası okunamadı (%s): %s", file_path, error)
        skipped_lines += 1

    return log_entries, skipped_lines