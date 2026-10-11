from pathlib import Path
from datetime import datetime, timezone, timedelta
from typing import Literal

from pydantic import Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


ROOT = Path(__file__).resolve().parents[2]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="CODEAUDIT_", env_file=(ROOT / ".env", ROOT / "backend" / ".env"), env_file_encoding="utf-8", extra="ignore", populate_by_name=True)
    daily_limit: int = Field(default=10, ge=1)
    temporary_limit_date_jst: str = "2026-10-11"
    temporary_daily_limit: int = Field(default=60, ge=1)
    temporary_daily_budget_usd: float = Field(default=60.0, gt=0)
    concurrency: int = Field(default=2, ge=1, le=20)
    timeout_seconds: int = Field(default=780, ge=10, le=3600)
    tool_timeout_seconds: int = Field(default=90, ge=1)
    max_repository_mb: int = Field(default=20, ge=1)
    max_file_bytes: int = Field(default=512_000, ge=100)
    max_files: int = Field(default=2000, ge=1, le=10000)
    max_report_bytes: int = Field(default=800_000, ge=10000, le=900000)
    retention_hours: int = Field(default=24, ge=1, le=24)
    accepting_audits: bool = True
    store: Literal["sqlite", "firestore"] = "sqlite"
    firestore_database: str = "codeaudit"
    dispatcher: Literal["local", "cloud_run"] = "local"
    database_path: Path = ROOT / ".audit-work" / "audits.sqlite3"
    work_root: Path = ROOT / ".audit-work" / "tmp"
    project: str = Field(default="jumpeicloud", validation_alias="GOOGLE_CLOUD_PROJECT")
    region: str = "asia-northeast1"
    job_name: str = "codeaudit-worker"
    identity_salt: SecretStr = SecretStr("")
    admin_reset_token: SecretStr = SecretStr("")
    gemini_api_key: SecretStr = Field(default=SecretStr(""), validation_alias="GEMINI_API_KEY")
    gemini_model: str = "gemini-3.5-flash-lite"
    ai_enabled: bool = True
    ai_chunk_chars: int = Field(default=48000, ge=1000, le=100000)
    ai_max_total_tokens: int = Field(default=360000, ge=1000)
    ai_max_output_tokens: int = Field(default=6000, ge=100, le=16000)
    ai_max_calls: int = Field(default=64, ge=2, le=100)
    ai_price_ceiling_per_million: float = Field(default=20.0, gt=0)
    ai_max_cost_usd: float = Field(default=3.0, gt=0)
    daily_budget_usd: float = Field(default=10.0, gt=0)
    gitleaks_bin: str = "gitleaks"
    semgrep_bin: str = "semgrep"
    trivy_bin: str = "trivy"

    @model_validator(mode="after")
    def validate_runtime(self):
        if self.dispatcher == "cloud_run" and self.store != "firestore":
            raise ValueError("Cloud Run JobsにはFirestoreを指定してください")
        if self.store == "firestore" and len(self.identity_salt.get_secret_value()) < 32:
            raise ValueError("クラウドでは32文字以上のidentity_saltが必要です")
        return self

    def effective_limits(self, now: float | None = None):
        """Temporary development allowance applies only on 2026-10-11 JST."""
        import time
        day = datetime.fromtimestamp(now if now is not None else time.time(), timezone(timedelta(hours=9))).strftime("%Y-%m-%d")
        if day == self.temporary_limit_date_jst:
            return self.temporary_daily_limit, self.temporary_daily_budget_usd
        return self.daily_limit, self.daily_budget_usd

    def public_limits(self):
        result = {name: getattr(self, name) for name in ("daily_limit", "concurrency", "timeout_seconds", "max_repository_mb", "max_files", "max_file_bytes", "retention_hours", "accepting_audits", "ai_max_total_tokens", "ai_max_cost_usd", "daily_budget_usd")}
        result["daily_limit"], result["daily_budget_usd"] = self.effective_limits()
        return result

    def reservation(self) -> float:
        if not self.ai_enabled or (not self.gemini_api_key.get_secret_value() and self.dispatcher != "cloud_run"):
            return 0.0
        return min(self.ai_max_cost_usd, self.ai_max_total_tokens * self.ai_price_ceiling_per_million / 1_000_000)
