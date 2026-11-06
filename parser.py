"""Erişim loglarını uygulama veri modellerine dönüştüren yardımcılar."""

import logging
import re
from datetime import datetime, timezone
from typing import List, Optional, Tuple

from models import LogEntry


logger = logging.getLogger(__name__)

_LOG_PATTERN = re.compile(
    r'^(?P<ip_address>\S+)\s+-\s+(?:-\s+)?\[(?P<timestamp>[^\]]+)\]\s+'
    r'"(?P<http_method>[A-Z]+)\s+(?P<endpoint>.+)"\s+'
    r'(?P<status_code>\d{3})(?:\s+(?P<extra_fields>.*))?$'
)


def parse_timestamp(ts_str: str) -> Optional[datetime]:
    """ISO veya CLF zaman damgasını UTC saat dilimsiz datetime nesnesine çevirir."""

    for format_string in (
        "%Y-%m-%d %H:%M:%S",
        "%d/%b/%Y:%H:%M:%S %z",
        "%d/%b/%Y:%H:%M:%S",
    ):
        try:
            parsed = datetime.strptime(ts_str, format_string)
            if parsed.tzinfo is not None:
                parsed = parsed.astimezone(timezone.utc)
            return parsed.replace(tzinfo=None)
        except ValueError:
            continue
    logger.warning("Zaman damgası ayrıştırılamadı: %s", ts_str)
    return None


def _normalize_timestamp(timestamp: str) -> str:
    """Saat dilimli zaman damgasını UTC saat dilimsiz biçime dönüştürür."""

    parsed = parse_timestamp(timestamp)
    return (
        parsed.strftime("%d/%b/%Y:%H:%M:%S")
        if parsed is not None
        else timestamp
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
                    response_time_ms = None
                    if extra_fields and "/" not in values["timestamp"]:
                        try:
                            response_time_ms = float(extra_fields[-1])
                        except ValueError:
                            response_time_ms = None
                    log_entries.append(
                        LogEntry(
                            ip_address=values["ip_address"],
                            timestamp=_normalize_timestamp(values["timestamp"]),
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