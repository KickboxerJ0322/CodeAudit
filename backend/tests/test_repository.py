import asyncio
import io
import tarfile
import time
import httpx
import pytest
from app.repository import AuditError, fetch_repository, unpack


def archive(entries):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        for name, content, kind in entries:
            item = tarfile.TarInfo(name)
            item.type = kind
            item.size = len(content) if kind == tarfile.REGTYPE else 0
            item.linkname = "../../escape"
            tar.addfile(item, io.BytesIO(content) if item.size else None)
    return buffer.getvalue()


def test_targets_and_exclusions(settings, tmp_path):
    file = tmp_path / "archive.gz"
    file.write_bytes(archive([(n, c, tarfile.REGTYPE) for n, c in [("repo/a.py", b"print('ok')\n"), ("repo/dist/b.js", b"generated"), ("repo/image.png", b"\x00binary"), ("repo/large.txt", b'a' * 1001)]]))
    files, excluded, size = unpack(file, tmp_path / "source", settings, time.monotonic() + 10)
    assert list(files) == ["a.py"]
    assert len(excluded) == 3 and size > 1000


@pytest.mark.parametrize("name,kind", [("repo/../../escape", tarfile.REGTYPE), ("/absolute", tarfile.REGTYPE), ("repo/link", tarfile.SYMTYPE), ("repo/link", tarfile.LNKTYPE), ("repo/device", tarfile.CHRTYPE), ("repo/C:/escape", tarfile.REGTYPE), ("repo/back\\slash", tarfile.REGTYPE), ("repo/CON.txt", tarfile.REGTYPE)])
def test_hostile_archive_rejected(settings, tmp_path, name, kind):
    file = tmp_path / "archive.gz"
    file.write_bytes(archive([(name, b"x", kind)]))
    with pytest.raises(AuditError):
        unpack(file, tmp_path / "source", settings, time.monotonic() + 10)
    assert not (tmp_path / "escape").exists()


def test_expansion_and_file_count(settings, tmp_path):
    settings.max_files = 1
    file = tmp_path / "archive.gz"
    file.write_bytes(archive([("repo/a.py", b"a", tarfile.REGTYPE), ("repo/b.py", b"b", tarfile.REGTYPE)]))
    with pytest.raises(AuditError, match="ファイル数"):
        unpack(file, tmp_path / "source", settings, time.monotonic() + 10)
    settings.max_files = 2000
    settings.max_repository_mb = 1
    file.write_bytes(archive([("repo/a.txt", b'a' * (1024 * 1024 + 1), tarfile.REGTYPE)]))
    with pytest.raises(AuditError, match="容量"):
        unpack(file, tmp_path / "source2", settings, time.monotonic() + 10)


def test_duplicate_casefold(settings, tmp_path):
    file = tmp_path / "archive.gz"
    file.write_bytes(archive([("repo/A.py", b"a", tarfile.REGTYPE), ("repo/a.py", b"b", tarfile.REGTYPE)]))
    with pytest.raises(AuditError, match="重複"):
        unpack(file, tmp_path / "source", settings, time.monotonic() + 10)


def test_pax_header_bomb_is_bounded(settings, tmp_path):
    settings.max_files = 1
    settings.max_repository_mb = 1
    file = tmp_path / 'pax.gz'
    with tarfile.open(file, 'w:gz', format=tarfile.PAX_FORMAT) as tar:
        item = tarfile.TarInfo('repo/a.py')
        item.pax_headers = {'comment': 'x' * 2_000_000}
        item.size = 1
        tar.addfile(item, io.BytesIO(b'x'))
    with pytest.raises(AuditError, match='ストリーム'):
        unpack(file, tmp_path / 'source', settings, time.monotonic() + 10)


@pytest.mark.parametrize("private,redirect", [(False, False), (True, False), (False, True)])
def test_github_only_sha_and_redirect(settings, tmp_path, private, redirect):
    calls = []
    sha = "a" * 40
    def respond(request):
        calls.append(str(request.url))
        assert request.url.host in {"api.github.com", "codeload.github.com"}
        if request.url.path.endswith('/commits/main'):
            return httpx.Response(200, json={"sha": sha})
        if request.url.host == "api.github.com":
            return httpx.Response(200, json={"private": private, "default_branch": "main"})
        if redirect:
            return httpx.Response(302, headers={"Location": "http://127.0.0.1/private"})
        assert request.url.path.endswith(sha)
        return httpx.Response(200, content=archive([("repo/a.py", b"print(1)", tarfile.REGTYPE)]))
    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as client:
            if private or redirect:
                with pytest.raises(AuditError):
                    await fetch_repository("https://github.com/a/b", tmp_path / "job", settings, client)
            else:
                repo = await fetch_repository("https://github.com/a/b", tmp_path / "job", settings, client)
                assert repo.sha == sha and repo.files == {"a.py": "print(1)"}
    asyncio.run(run())
    assert len(calls) == (1 if private else 3)
