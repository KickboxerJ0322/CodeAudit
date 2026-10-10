import re
import gzip
import tarfile
import time
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from urllib.parse import quote
import httpx
from app.config import Settings
from app.models import AuditRequest


class AuditError(Exception):
    """A user-safe message; never raw remote/tool output."""


@dataclass
class Repository:
    url: str
    sha: str
    root: Path
    files: dict[str, str]
    excluded: list[dict]
    archive_bytes: int
    expanded_bytes: int


GENERATED = {".git", "node_modules", "vendor", "dist", "build", "coverage", ".next", ".venv", "venv", "__pycache__", ".cache"}


class LimitedReader:
    def __init__(self, stream, limit, deadline):
        self.stream, self.remaining, self.deadline = stream, limit, deadline

    def read(self, size=-1):
        if time.monotonic() > self.deadline:
            raise AuditError("アーカイブ読み取りの時間上限を超えました")
        data = self.stream.read(min(size if size >= 0 else self.remaining + 1, self.remaining + 1))
        self.remaining -= len(data)
        if self.remaining < 0:
            raise AuditError("アーカイブ展開ストリームの容量上限を超えました")
        return data


def safe_path(name: str) -> PurePosixPath:
    path = PurePosixPath(name)
    if not name or "\\" in name or ":" in name or "\x00" in name or any(ord(c) < 32 for c in name) or path.is_absolute() or any(p in {".", ".."} for p in name.split("/")) or len(name) > 300:
        raise AuditError("アーカイブに安全でないパスが含まれています")
    return path


def unpack(archive: Path, target: Path, settings: Settings, deadline: float) -> tuple[dict, list, int]:
    files, excluded, seen = {}, [], set()
    expanded, count, root_name = 0, 0, None
    target.mkdir(parents=True, exist_ok=True)
    try:
        with gzip.open(archive, "rb") as compressed, tarfile.open(fileobj=LimitedReader(compressed, settings.max_repository_mb * 1024 * 1024 + settings.max_files * 1024, deadline), mode="r|") as tar:
            for member in tar:
                if time.monotonic() > deadline:
                    raise AuditError("アーカイブ展開の時間上限を超えました")
                count += 1
                if count > settings.max_files * 3:
                    raise AuditError("アーカイブ項目数の上限を超えました")
                path = safe_path(member.name.rstrip("/"))
                if root_name is None:
                    root_name = path.parts[0]
                if path.parts[0] != root_name:
                    raise AuditError("アーカイブのルートが不正です")
                if member.issym() or member.islnk() or not (member.isfile() or member.isdir()):
                    raise AuditError("リンクまたは特殊ファイルを含むため取得を拒否しました")
                if len(path.parts) == 1:
                    if not member.isdir():
                        raise AuditError("アーカイブの構造が不正です")
                    continue
                relative = PurePosixPath(*path.parts[1:]).as_posix()
                if relative.casefold() in seen:
                    raise AuditError("アーカイブに重複するパスがあります")
                seen.add(relative.casefold())
                if any(part.endswith((".", " ")) or part.split(".")[0].upper() in {"CON", "PRN", "AUX", "NUL", *[f"COM{i}" for i in range(1, 10)], *[f"LPT{i}" for i in range(1, 10)]} for part in path.parts):
                    raise AuditError("OSで安全に扱えないパスを含んでいます")
                if member.isdir():
                    continue
                expanded += member.size
                if member.size < 0 or expanded > settings.max_repository_mb * 1024 * 1024:
                    raise AuditError("展開後のリポジトリが容量上限を超えました")
                if len(files) + len(excluded) >= settings.max_files:
                    raise AuditError("ファイル数の上限を超えました")
                reason = None
                if any(p in GENERATED for p in path.parts[1:]) or relative.endswith((".min.js", ".min.css", ".map")):
                    reason = "生成物・外部依存"
                elif member.size > settings.max_file_bytes:
                    reason = "単一ファイル容量上限"
                if reason:
                    excluded.append({"file": relative, "reason": reason})
                    continue
                source = tar.extractfile(member)
                if source is None:
                    raise AuditError("ファイルを読み取れません")
                raw = source.read(settings.max_file_bytes + 1)
                try:
                    text = raw.decode("utf-8")
                    if b"\x00" in raw or any(ord(c) < 9 or 13 < ord(c) < 32 for c in text):
                        raise UnicodeError()
                except UnicodeError:
                    excluded.append({"file": relative, "reason": "バイナリまたはUTF-8以外"})
                    continue
                destination = target.joinpath(*PurePosixPath(relative).parts)
                if not destination.resolve().is_relative_to(target.resolve()):
                    raise AuditError("作業領域外へのアクセスを拒否しました")
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(raw)
                files[relative] = text
    except (tarfile.TarError, OSError, EOFError) as exc:
        raise AuditError("アーカイブの読み取りに失敗しました") from exc
    if not files:
        raise AuditError("分析可能なUTF-8テキストファイルがありません")
    return files, excluded, expanded


async def fetch_repository(url: str, work: Path, settings: Settings, client: httpx.AsyncClient | None = None) -> Repository:
    url = AuditRequest(repository_url=url).repository_url
    owner, repo = url.split("/")[-2:]
    work.mkdir(parents=True, exist_ok=True)
    archive = work / "repository.tar.gz"
    deadline = time.monotonic() + settings.timeout_seconds
    own = client is None
    client = client or httpx.AsyncClient(timeout=30, follow_redirects=False, trust_env=False, headers={"User-Agent": "CodeAudit/0.2", "Accept": "application/vnd.github+json"})
    async def metadata(endpoint):
        response = await client.get(endpoint)
        if response.status_code != 200 or len(response.content) > 1_000_000:
            raise AuditError("GitHub情報を取得できません。公開URLまたはGitHubの回数制限を確認してください")
        try:
            return response.json()
        except ValueError as exc:
            raise AuditError("GitHub応答が不正です") from exc
    try:
        info = await metadata(f"https://api.github.com/repos/{owner}/{repo}")
        if info.get("private") is not False or not isinstance(info.get("default_branch"), str):
            raise AuditError("公開リポジトリのみ監査できます")
        commit = await metadata(f"https://api.github.com/repos/{owner}/{repo}/commits/{quote(info['default_branch'], safe='')}")
        sha = commit.get("sha", "")
        if not re.fullmatch(r"[0-9a-f]{40}", sha):
            raise AuditError("コミットSHAを確認できません")
        size = 0
        async with client.stream("GET", f"https://codeload.github.com/{owner}/{repo}/tar.gz/{sha}") as response:
            if response.status_code != 200:
                raise AuditError("GitHubアーカイブを取得できません（リダイレクトも拒否します）")
            with archive.open("wb") as output:
                async for data in response.aiter_bytes():
                    if time.monotonic() > deadline:
                        raise AuditError("GitHub取得の時間上限を超えました")
                    size += len(data)
                    if size > settings.max_repository_mb * 1024 * 1024:
                        raise AuditError("取得容量の上限を超えました")
                    output.write(data)
        files, excluded, expanded = unpack(archive, work / "source", settings, deadline)
        archive.unlink(missing_ok=True)
        return Repository(url, sha, work / "source", files, excluded, size, expanded)
    except httpx.HTTPError as exc:
        raise AuditError("GitHubとの通信に失敗しました") from exc
    finally:
        if own:
            await client.aclose()
