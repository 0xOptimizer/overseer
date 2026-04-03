import re
import time
from dataclasses import dataclass

from overseer.config import Config
from overseer.tracker import RateTracker

_BOT_UA = re.compile(
    r"(sqlmap|nikto|masscan|nmap|zgrab|gobuster|dirbuster|wfuzz|nuclei|"
    r"hydra|curl|python-requests|python-urllib|go-http-client|libwww-perl|"
    r"wget|scrapy|phantomjs|headlesschrome|selenium|mechanize|httpclient|"
    r"dataforseo|semrushbot|ahrefsbot|dotbot|mj12bot|blexbot|petalbot|"
    r"bytespider|gptbot|claudebot|ccbot|ia_archiver|archive\.org_bot)",
    re.IGNORECASE,
)

_ATTACK_URI = re.compile(
    r"(\.\./|\.\.\\|%2e%2e|%252e|"
    r"/etc/passwd|/etc/shadow|/proc/self|"
    r"\.env|\.git/|\.svn/|\.DS_Store|"
    r"wp-admin|wp-login|phpMyAdmin|phpmyadmin|"
    r"/admin/config|/config\.php|/configuration\.php|"
    r"select\s+.*\s+from|union\s+select|drop\s+table|insert\s+into|"
    r"<script|javascript:|onerror=|onload=|"
    r"/shell\.|/cmd\.|/c99\.|/r57\.|/webshell|"
    r"eval\(|base64_decode\(|system\(|exec\(|"
    r"\.php\?|\.asp\?|\.aspx\?|\.jsp\?)",
    re.IGNORECASE,
)

_SUSPICIOUS_URI = re.compile(
    r"(/robots\.txt|/sitemap\.xml|/xmlrpc\.php|"
    r"/actuator|/health|/metrics|/swagger|/api-docs|"
    r"/backup|/dump|/db|/database|/sql|"
    r"/\.well-known/|/crossdomain\.xml|/clientaccesspolicy\.xml)",
    re.IGNORECASE,
)


@dataclass(slots=True)
class Detection:
    score: int
    is_bot: bool
    is_attack: bool
    bot_reason: str | None


class BotDetector:
    def __init__(self, config: Config) -> None:
        self._config = config
        self._tracker = RateTracker(config)

    def analyze(
        self,
        ip: str,
        uri: str,
        user_agent: str,
        status: int,
    ) -> Detection:
        score = 0
        reasons: list[str] = []
        is_bot = False
        is_attack = False

        ua = user_agent or ""
        uri = uri or ""
        now = time.time()

        rate = self._tracker.record(ip, status, now)
        count_404 = self._tracker.get_404_count(ip)
        count_403 = self._tracker.get_403_count(ip)

        if not ua.strip():
            score += 30
            reasons.append("empty_ua")
            is_bot = True
        elif _BOT_UA.search(ua):
            score += 40
            reasons.append("known_bot_ua")
            is_bot = True

        if _ATTACK_URI.search(uri):
            score += 50
            reasons.append("attack_uri")
            is_attack = True
        elif _SUSPICIOUS_URI.search(uri):
            score += 15
            reasons.append("suspicious_uri")

        if rate >= self._config.rate_burst_threshold:
            score += 25
            reasons.append(f"burst_rate:{rate}req/min")
            is_bot = True

        if count_404 >= self._config.error_404_threshold:
            score += 20
            reasons.append(f"404_scan:{count_404}")
            is_bot = True

        if count_403 >= self._config.error_403_threshold:
            score += 15
            reasons.append(f"403_scan:{count_403}")

        if status in (400, 444):
            score += 10
            reasons.append(f"status_{status}")

        return Detection(
            score=min(score, 100),
            is_bot=is_bot,
            is_attack=is_attack,
            bot_reason=",".join(reasons) if reasons else None,
        )