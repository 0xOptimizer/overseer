import os
from dataclasses import dataclass, field
from dotenv import load_dotenv

load_dotenv()


@dataclass
class Config:
    db_host: str = field(default_factory=lambda: os.getenv("DB_HOST", "127.0.0.1"))
    db_port: int = field(default_factory=lambda: int(os.getenv("DB_PORT", "3306")))
    db_user: str = field(default_factory=lambda: os.getenv("DB_USER", ""))
    db_password: str = field(default_factory=lambda: os.getenv("DB_PASSWORD", ""))
    db_name: str = field(default_factory=lambda: os.getenv("DB_NAME", "nydus"))
    db_pool_size: int = field(default_factory=lambda: int(os.getenv("DB_POOL_SIZE", "3")))

    log_files: list[str] = field(
        default_factory=lambda: [
            f.strip()
            for f in os.getenv("LOG_FILES", "").split(",")
            if f.strip()
        ]
    )

    rate_window_seconds: int = field(
        default_factory=lambda: int(os.getenv("RATE_WINDOW_SECONDS", "60"))
    )
    rate_burst_threshold: int = field(
        default_factory=lambda: int(os.getenv("RATE_BURST_THRESHOLD", "60"))
    )
    error_404_threshold: int = field(
        default_factory=lambda: int(os.getenv("ERROR_404_THRESHOLD", "10"))
    )
    error_403_threshold: int = field(
        default_factory=lambda: int(os.getenv("ERROR_403_THRESHOLD", "5"))
    )

    poll_interval: float = field(
        default_factory=lambda: float(os.getenv("POLL_INTERVAL", "0.5"))
    )
    cleanup_interval: int = field(
        default_factory=lambda: int(os.getenv("CLEANUP_INTERVAL", "300"))
    )

    def validate(self) -> None:
        missing = []
        if not self.db_user:
            missing.append("DB_USER")
        if not self.db_password:
            missing.append("DB_PASSWORD")
        if not self.db_name:
            missing.append("DB_NAME")
        if not self.log_files:
            missing.append("LOG_FILES")
        if missing:
            raise EnvironmentError(
                f"Overseer: missing required environment variables: {', '.join(missing)}"
            )

    def to_pool_config(self) -> dict:
        return {
            "host": self.db_host,
            "port": self.db_port,
            "user": self.db_user,
            "password": self.db_password,
            "database": self.db_name,
            "pool_name": "overseer_pool",
            "pool_size": self.db_pool_size,
        }