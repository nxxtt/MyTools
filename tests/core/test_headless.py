"""Testes de integracao real do headless (chromium via playwright).

Usam um servidor HTTP local (http.server) e o chromium instalado.
Nao mockam o playwright: validam comportamento real de evaluate e
confirm_js_execution. Precisam de asyncio.sleep real (marcador real_sleep)
porque o browser interno do playwright usa timeouts de verdade.
"""

import socket
import threading
from collections.abc import Iterator
from functools import partial
from http.server import (
    BaseHTTPRequestHandler,
    SimpleHTTPRequestHandler,
    ThreadingHTTPServer,
)
from pathlib import Path
from urllib.parse import urlsplit

import pytest

from mytools.core import headless as h

pytestmark = [pytest.mark.real_sleep, pytest.mark.integration]


class _ForwardProxy(BaseHTTPRequestHandler):
    """Proxy HTTP simples que reencaminha GET para o destino absoluto."""

    def do_GET(self) -> None:
        parts = urlsplit(self.path)
        host, port = parts.hostname, parts.port or 80
        path = parts.path or "/"
        if parts.query:
            path = f"{path}?{parts.query}"
        with socket.create_connection((host, port), timeout=10) as sock:
            sock.sendall(
                (
                    f"GET {path} HTTP/1.1\r\nHost: {host}:{port}\r\n"
                    "Connection: close\r\n\r\n"
                ).encode()
            )
            raw = b""
            while True:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                raw += chunk
        _, _, body = raw.partition(b"\r\n\r\n")
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args) -> None:
        pass


@pytest.fixture(scope="module")
def proxy_server() -> Iterator[str]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _ForwardProxy)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()
    thread.join(timeout=5)


@pytest.fixture(scope="module")
def http_server(tmp_path_factory) -> Iterator[str]:
    """Servidor HTTP local servindo HTML com marcadores JS."""
    root: Path = tmp_path_factory.mktemp("headless")
    (root / "index.html").write_text(
        "<html><body><script>window.MARKER = 'headless-ok';</script></body></html>",
        encoding="utf-8",
    )
    (root / "dialog.html").write_text(
        "<html><body><script>setTimeout(() => alert('x'), 0);</script></body></html>",
        encoding="utf-8",
    )
    (root / "click.html").write_text(
        '<html><body><button onclick="alert(1)">go</button></body></html>',
        encoding="utf-8",
    )
    (root / "clickfail.html").write_text(
        '<html><body><a id="h" href="#" style="display:none" onclick="alert(1)">x</a>'
        '<button onclick="alert(2)">go</button></body></html>',
        encoding="utf-8",
    )
    (root / "clickmulti.html").write_text(
        '<html><body><button onclick="alert(1)">a</button>'
        '<button onclick="alert(2)">b</button></body></html>',
        encoding="utf-8",
    )
    handler = partial(SimpleHTTPRequestHandler, directory=str(root))
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()
    thread.join(timeout=5)


@pytest.mark.skipif(not h.browser_available(), reason="chromium nao instalado")
class TestBrowserAvailable:
    def test_true_when_chromium_installed(self) -> None:
        assert h.browser_available() is True

    def test_false_when_playwright_missing(self, monkeypatch) -> None:
        import builtins

        real_import = builtins.__import__

        def fake_import(name, *args, **kwargs):
            if name == "playwright":
                raise ImportError("no playwright")
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", fake_import)
        assert h.browser_available() is False


class TestBrowserDir:
    def test_env_override_valid(self, tmp_path, monkeypatch) -> None:
        monkeypatch.setenv("PLAYWRIGHT_BROWSERS_PATH", str(tmp_path))
        assert h._browser_dir() == tmp_path

    def test_env_override_invalid(self, tmp_path, monkeypatch) -> None:
        monkeypatch.setenv("PLAYWRIGHT_BROWSERS_PATH", str(tmp_path / "missing"))
        assert h._browser_dir() is None

    def test_no_env_no_dir(self, monkeypatch) -> None:
        monkeypatch.delenv("PLAYWRIGHT_BROWSERS_PATH", raising=False)
        monkeypatch.setattr(Path, "home", lambda: Path("Z:/nao-existe-home"))
        assert h._browser_dir() is None

    def test_no_env_linux_cache(self, tmp_path, monkeypatch) -> None:
        cache = tmp_path / ".cache" / "ms-playwright"
        cache.mkdir(parents=True)
        monkeypatch.delenv("PLAYWRIGHT_BROWSERS_PATH", raising=False)
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        assert h._browser_dir() == cache

    def test_no_env_windows_fallback(self, tmp_path, monkeypatch) -> None:
        fallback = tmp_path / "AppData" / "Local" / "ms-playwright"
        fallback.mkdir(parents=True)
        monkeypatch.delenv("PLAYWRIGHT_BROWSERS_PATH", raising=False)
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        assert h._browser_dir() == fallback

    def test_browser_available_no_chromium(self, tmp_path, monkeypatch) -> None:
        (tmp_path / "firefox-123").mkdir()
        monkeypatch.setenv("PLAYWRIGHT_BROWSERS_PATH", str(tmp_path))
        assert h.browser_available() is False

    def test_browser_available_dir_none(self, monkeypatch) -> None:
        monkeypatch.setattr(h, "_browser_dir", lambda: None)
        assert h.browser_available() is False


@pytest.mark.skipif(not h.browser_available(), reason="chromium nao instalado")
class TestEvaluate:
    @pytest.mark.asyncio
    async def test_returns_js_value(self, http_server) -> None:
        result = await h.evaluate(f"{http_server}/index.html", "() => window.MARKER")
        assert result == "headless-ok"

    @pytest.mark.asyncio
    async def test_passes_arg(self, http_server) -> None:
        result = await h.evaluate(
            f"{http_server}/index.html", "(a) => a + 1", 41, timeout=15.0
        )
        assert result == 42

    @pytest.mark.asyncio
    async def test_verify_true(self, http_server) -> None:
        result = await h.evaluate(
            f"{http_server}/index.html", "() => 7", verify=True, timeout=15.0
        )
        assert result == 7

    @pytest.mark.asyncio
    async def test_raises_headless_error(self, monkeypatch) -> None:
        monkeypatch.setattr(h, "browser_available", lambda: False)
        with pytest.raises(h.HeadlessError):
            await h.evaluate("http://localhost:1/", "() => 1")

    @pytest.mark.asyncio
    async def test_with_proxy(self, http_server, proxy_server) -> None:
        result = await h.evaluate(
            f"{http_server}/index.html",
            "() => window.MARKER",
            timeout=15.0,
            proxy=proxy_server,
        )
        assert result == "headless-ok"


@pytest.mark.skipif(not h.browser_available(), reason="chromium nao instalado")
class TestConfirmJsExecution:
    @pytest.mark.asyncio
    async def test_dialog_on_load(self, http_server) -> None:
        assert await h.confirm_js_execution(f"{http_server}/dialog.html") is True

    @pytest.mark.asyncio
    async def test_dialog_on_click(self, http_server) -> None:
        assert await h.confirm_js_execution(f"{http_server}/click.html") is True

    @pytest.mark.asyncio
    async def test_click_failure_then_success(self, http_server) -> None:
        assert await h.confirm_js_execution(f"{http_server}/clickfail.html") is True

    @pytest.mark.asyncio
    async def test_click_breaks_after_first_dialog(self, http_server) -> None:
        assert await h.confirm_js_execution(f"{http_server}/clickmulti.html") is True

    @pytest.mark.asyncio
    async def test_click_via_proxy(self, http_server, proxy_server) -> None:
        assert (
            await h.confirm_js_execution(
                f"{http_server}/click.html", timeout=15.0, proxy=proxy_server
            )
            is True
        )

    @pytest.mark.asyncio
    async def test_no_dialog(self, http_server) -> None:
        assert await h.confirm_js_execution(f"{http_server}/index.html") is False

    @pytest.mark.asyncio
    async def test_raises_headless_error(self, monkeypatch) -> None:
        monkeypatch.setattr(h, "browser_available", lambda: False)
        with pytest.raises(h.HeadlessError):
            await h.confirm_js_execution("http://localhost:1/")
