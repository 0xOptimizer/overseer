import json
import sys
from datetime import datetime

from overseer.detector import BotDetector


def _parse_time(raw: str | None) -> datetime:
    if not raw:
        return datetime.utcnow()
    try:
        return datetime.fromisoformat(raw.strip())
    except Exception:
        return datetime.utcnow()


def _str(value, max_len: int | None = None) -> str | None:
    if value is None:
        return None
    result = str(value).strip()
    if not result or result == "-":
        return None
    if max_len:
        result = result[:max_len]
    return result


def _int(value, fallback: int = 0) -> int:
    try:
        return int(str(value).strip())
    except Exception:
        return fallback


def _float(value, fallback: float = 0.0) -> float:
    try:
        return float(str(value).strip())
    except Exception:
        return fallback


def _extract_json_objects(line: str) -> list[str]:
    objects = []
    depth = 0
    start = None
    for i, ch in enumerate(line):
        if ch == "{":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0 and start is not None:
                objects.append(line[start:i + 1])
                start = None
    return objects


def _parse_single(raw: str, detector: BotDetector) -> tuple | None:
    try:
        d = json.loads(raw)

        if not isinstance(d, dict):
            return None

        ip = _str(d.get("ip"), 45) or ""
        uri = _str(d.get("uri")) or ""
        ua = _str(d.get("user_agent")) or ""
        status = _int(d.get("status"))
        host = _str(d.get("host"), 255) or ""
        method = _str(d.get("method"), 10)
        referrer = _str(d.get("referrer"))
        upstream = _str(d.get("upstream"), 255)
        duration = _float(d.get("duration"))
        country = _str(d.get("country"), 2)
        recorded_at = _parse_time(_str(d.get("time")))

        if not ip or not host:
            return None

        detection = detector.analyze(ip, uri, ua, status)

        return (
            recorded_at,
            ip,
            host,
            uri,
            referrer,
            method,
            status,
            upstream,
            duration,
            ua or None,
            detection.score,
            int(detection.is_bot),
            int(detection.is_attack),
            detection.bot_reason,
            country,
        )
    except json.JSONDecodeError:
        return None
    except Exception as exc:
        sys.stderr.write(f"Overseer parse error: {exc}\n")
        return None


def parse_line(line: str, detector: BotDetector) -> list[tuple]:
    line = line.strip()
    if not line:
        return []
    objects = _extract_json_objects(line)
    if not objects:
        return []
    return [r for r in (_parse_single(o, detector) for o in objects) if r is not None]