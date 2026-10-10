import re
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field, field_validator

Severity = Literal["critical", "high", "medium", "low", "info"]
Category = Literal["confirmed", "configuration", "recommendation"]


class AuditRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    repository_url: str = Field(max_length=300)

    @field_validator("repository_url")
    @classmethod
    def validate_repository(cls, value: str) -> str:
        pattern = r"https://github\.com/[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9_.-]+/?"
        if not re.fullmatch(pattern, value) or value.rstrip("/").split("/")[-1] in {".", ".."}:
            raise ValueError("公開GitHubリポジトリのHTTPS URLを指定してください")
        result = value.rstrip("/").removesuffix(".git")
        if result.split("/")[-1] in {"", ".", ".."}:
            raise ValueError("リポジトリ名が不正です")
        return result


class Finding(BaseModel):
    model_config = ConfigDict(extra="forbid")
    source: Literal["gitleaks", "semgrep", "trivy", "gemini"]
    rule_id: str = Field(max_length=200)
    severity: Severity
    category: Category
    title: str = Field(max_length=300)
    file: str = Field(max_length=300)
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)
    evidence: str = Field(max_length=2000)
    reason: str = Field(max_length=2000)
    impact: str = Field(max_length=2000)
    remediation: str = Field(max_length=3000)
    confidence: float | None = Field(default=None, ge=0, le=1)
    evidence_verified: bool = False
    github_url: str = ""


class AIFinding(BaseModel):
    model_config = ConfigDict(extra="forbid")
    severity: Severity
    category: Category
    title: str = Field(max_length=300)
    file: str = Field(max_length=300)
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)
    evidence: str = Field(min_length=1, max_length=2000)
    reason: str = Field(max_length=2000)
    impact: str = Field(max_length=2000)
    remediation: str = Field(max_length=3000)
    confidence: float = Field(ge=0, le=1)


class AIResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    summary: str = Field(max_length=5000)
    analyzed_segments: list[str] = Field(max_length=10000)
    findings: list[AIFinding] = Field(max_length=100)
