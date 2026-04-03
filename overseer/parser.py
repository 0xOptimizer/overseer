import json
import sys
from datetime import datetime

from overseer.detector import BotDetector


def parse_time(raw: str) -> datetime:
    try:
        return datetime.fromisoformat(raw)
    except Exception:
        return datetime.utcnow()


def parse_line(line: str, detector: BotDetector) -> tuple | None:
    line = line.strip()
    if not line:
        return None
    try:
        d = json.loads(line)
        ip = (d.get("ip") or "")[:45]
        uri = d.get("uri") or ""
        ua = d.get("user_agent") or ""
        status = int(d.get("status") or 0)

        detection = detector.analyze(ip, uri, ua, status)

        return (
            parse_time(d.get("time") or ""),
            ip,
            (d.get("host") or "")[:255],
            uri,
            d.get("referrer") or None,
            (d.get("method") or "")[:10],
            status,
            d.get("upstream") or None,
            float(d.get("duration") or 0),
            ua or None,
            detection.score,
            int(detection.is_bot),
            int(detection.is_attack),
            detection.bot_reason,
        )
    except Exception as exc:
        sys.stderr.write(f"Overseer parse error: {exc}\n")
        return None