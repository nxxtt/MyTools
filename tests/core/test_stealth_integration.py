import argparse

import httpx
import pytest
import respx

from mytools.core.utils import (
    StealthContext,
    create_async_client,
    fetch,
    get_stealth_ctx,
    init_scanner,
)


def _make_args(**overrides: object) -> argparse.Namespace:
    defaults = {
        "verbose": False,
        "log_file": None,
        "quiet": False,
        "color": None,
        "theme": None,
        "severity_override": None,
        "random_delay": False,
        "jitter": 0.0,
        "user_agent_rotate": False,
        "impersonate": None,
        "tor": False,
        "waf_evasion": False,
        "pad_headers": 0,
        "fragment": 0,
        "fragment_tcp": 0,
        "src_port_random": False,
    }
    defaults.update(overrides)
    return argparse.Namespace(**defaults)


class TestStealthContextFromArgs:
    def test_no_stealth_returns_none(self):
        ctx = StealthContext.from_args(_make_args())
        assert ctx is None

    def test_random_delay(self):
        ctx = StealthContext.from_args(_make_args(random_delay=True))
        assert ctx is not None
        assert ctx.random_delay is True

    def test_jitter(self):
        ctx = StealthContext.from_args(_make_args(jitter=2.5))
        assert ctx is not None
        assert ctx.jitter == 2.5

    def test_user_agent_rotate(self):
        ctx = StealthContext.from_args(_make_args(user_agent_rotate=True))
        assert ctx is not None
        assert ctx.user_agent_rotate is True

    def test_impersonate(self):
        ctx = StealthContext.from_args(_make_args(impersonate="chrome"))
        assert ctx is not None
        assert ctx.impersonate == "chrome"

    def test_tor(self):
        ctx = StealthContext.from_args(_make_args(tor=True))
        assert ctx is not None
        assert ctx.tor is True

    def test_waf_evasion(self):
        ctx = StealthContext.from_args(_make_args(waf_evasion=True))
        assert ctx is not None
        assert ctx.waf_evasion is True

    def test_pad_headers(self):
        ctx = StealthContext.from_args(_make_args(pad_headers=50))
        assert ctx is not None
        assert ctx.pad_headers == 50

    def test_fragment(self):
        ctx = StealthContext.from_args(_make_args(fragment=100))
        assert ctx is not None
        assert ctx.fragment == 100

    def test_fragment_tcp(self):
        ctx = StealthContext.from_args(_make_args(fragment_tcp=64))
        assert ctx is not None
        assert ctx.fragment_tcp == 64

    def test_src_port_random(self):
        ctx = StealthContext.from_args(_make_args(src_port_random=True))
        assert ctx is not None
        assert ctx.src_port_random is True

    def test_frozen(self):
        ctx = StealthContext.from_args(_make_args(random_delay=True))
        with pytest.raises(AttributeError):
            ctx.random_delay = False  # type: ignore[misc]

    def test_multiple_flags(self):
        ctx = StealthContext.from_args(
            _make_args(random_delay=True, waf_evasion=True, pad_headers=30)
        )
        assert ctx is not None
        assert ctx.random_delay is True
        assert ctx.waf_evasion is True
        assert ctx.pad_headers == 30


class TestInitScannerSetsCtx:
    def test_sets_global_ctx(self):
        args = _make_args(waf_evasion=True)
        init_scanner(args)
        ctx = get_stealth_ctx()
        assert ctx is not None
        assert ctx.waf_evasion is True

    def test_no_stealth_keeps_none(self):
        init_scanner(_make_args())
        assert get_stealth_ctx() is None


class TestCreateAsyncClientStealth:
    def test_no_stealth_default_headers(self):
        init_scanner(_make_args())
        client = create_async_client()
        assert isinstance(client, httpx.AsyncClient)
        from mytools.core.utils import __version__

        assert client.headers["User-Agent"] == f"MyTools/{__version__}"

    def test_user_agent_rotate_changes_ua(self):
        init_scanner(_make_args(user_agent_rotate=True))
        user_agents = set()
        for _ in range(20):
            c = create_async_client()
            user_agents.add(c.headers["User-Agent"])
        assert len(user_agents) > 1

    def test_pad_headers_adds_fake_headers(self):
        init_scanner(_make_args(pad_headers=10))
        client = create_async_client()
        assert len(client.headers) >= 10

    def test_src_port_random_creates_custom_transport(self):
        init_scanner(_make_args(src_port_random=True))
        client = create_async_client()
        assert isinstance(client, httpx.AsyncClient)
        assert client._transport is not None


class TestFetchStealth:
    @respx.mock
    @pytest.mark.anyio
    async def test_waf_evasion_modifies_url(self):
        init_scanner(_make_args(waf_evasion=True))
        route = respx.route(method="GET").mock(
            return_value=httpx.Response(200, content=b"ok")
        )
        client = httpx.AsyncClient()
        status, _, body, _ = await fetch(client, "http://example.com/path?q=1")
        assert status == 200
        assert body == b"ok"
        assert route.called

    @respx.mock
    @pytest.mark.anyio
    async def test_user_agent_rotate_sets_ua(self):
        init_scanner(_make_args(user_agent_rotate=True))
        captured_uas: list[str] = []

        def capture(request):
            captured_uas.append(request.headers.get("User-Agent", ""))
            return httpx.Response(200, content=b"ok")

        respx.route(method="GET").mock(side_effect=capture)
        client = httpx.AsyncClient()
        await fetch(client, "http://example.com/test")
        assert len(captured_uas) == 1
        from mytools.core.utils import __version__

        assert captured_uas[0] != f"MyTools/{__version__}"

    @respx.mock
    @pytest.mark.anyio
    async def test_user_agent_rotate_keeps_existing_headers(self):
        init_scanner(_make_args(user_agent_rotate=True))
        captured: dict[str, dict[str, str]] = {}

        def capture(request):
            captured["headers"] = dict(request.headers)
            return httpx.Response(200, content=b"ok")

        respx.route(method="GET").mock(side_effect=capture)
        client = httpx.AsyncClient()
        status, _, _, _ = await fetch(
            client, "http://example.com/test", headers={"X-Custom": "1"}
        )
        assert status == 200
        assert captured["headers"].get("x-custom") == "1"
        assert "user-agent" in captured["headers"]

    @respx.mock
    @pytest.mark.anyio
    async def test_no_stealth_fetch_unchanged(self):
        init_scanner(_make_args())
        respx.get("http://example.com/plain").mock(
            return_value=httpx.Response(200, content=b"plain")
        )
        client = httpx.AsyncClient()
        status, _, body, _ = await fetch(client, "http://example.com/plain")
        assert status == 200
        assert body == b"plain"

    def test_src_port_random_with_impersonate(self, monkeypatch):
        init_scanner(_make_args(src_port_random=True, impersonate="chrome120"))
        captured: dict[str, object] = {}

        class FakeSession:
            def __init__(self, **kw: object) -> None:
                captured.update(kw)
                self.headers: dict[str, str] = {}
                self.cookies: dict[str, str] = {}

        fake_mod = argparse.Namespace(AsyncSession=FakeSession)
        monkeypatch.setattr(
            "sys.modules",
            {
                **__import__("sys").modules,
                "curl_cffi": fake_mod,
                "curl_cffi.requests": fake_mod,
            },
        )
        client = create_async_client()
        assert isinstance(client, object)
        assert "local_address" in captured
        assert captured["local_address"] is not None
        addr = captured["local_address"]
        assert isinstance(addr, tuple)
        assert addr[0] == "127.0.0.1"
        assert isinstance(addr[1], int)

    def test_fragment_with_impersonate_warns(self, monkeypatch, caplog):
        init_scanner(
            _make_args(
                fragment=10,
                impersonate="chrome120",
            )
        )

        class FakeSession:
            def __init__(self, **kw: object) -> None:
                self.headers: dict[str, str] = {}
                self.cookies: dict[str, str] = {}

        fake_mod = argparse.Namespace(AsyncSession=FakeSession)
        monkeypatch.setattr(
            "sys.modules",
            {
                **__import__("sys").modules,
                "curl_cffi": fake_mod,
                "curl_cffi.requests": fake_mod,
            },
        )
        import logging

        with caplog.at_level(logging.WARNING):
            create_async_client()
        assert "fragmentacao e impersonate nao combinaveis" in caplog.text

    @respx.mock
    @pytest.mark.anyio
    async def test_pad_headers_in_fetch(self):
        init_scanner(_make_args(pad_headers=10))
        captured: dict[str, dict[str, str]] = {}

        def capture(request):
            captured["headers"] = dict(request.headers)
            return httpx.Response(200, content=b"ok")

        respx.route(method="GET").mock(side_effect=capture)
        client = httpx.AsyncClient()
        status, _, _, _ = await fetch(client, "http://example.com/test")
        assert status == 200
        assert len(captured["headers"]) >= 10


class TestFragmentedSocket:
    def test_no_fragment_passthrough(self):
        from mytools.core.stealth import FragmentedSocket

        sent: list[bytes] = []

        class FakeSock:
            def sendall(self, data: bytes, **kw: object) -> None:
                sent.append(data)

        fs = FragmentedSocket(FakeSock(), fragment=0, fragment_tcp=0)
        fs.sendall(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
        assert len(sent) == 1
        assert sent[0] == b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"

    def test_fragment_tcp_splits_data(self):
        from mytools.core.stealth import FragmentedSocket

        sent: list[bytes] = []

        class FakeSock:
            def sendall(self, data: bytes, **kw: object) -> None:
                sent.append(data)

        fs = FragmentedSocket(FakeSock(), fragment=0, fragment_tcp=4)
        fs.sendall(b"ABCDEFGH")
        assert len(sent) == 2
        assert sent[0] == b"ABCD"
        assert sent[1] == b"EFGH"

    def test_fragment_http_splits_headers(self):
        from mytools.core.stealth import FragmentedSocket

        sent: list[bytes] = []

        class FakeSock:
            def sendall(self, data: bytes, **kw: object) -> None:
                sent.append(data)

        request = b"GET / HTTP/1.1\r\nHost: example.com\r\nX-Custom: value\r\n\r\n"
        fs = FragmentedSocket(FakeSock(), fragment=5, fragment_tcp=0)
        fs.sendall(request)
        # Should have multiple header fragments + body
        assert len(sent) > 1
        # All pieces together should reconstruct the request
        full = b"".join(sent)
        assert full.startswith(b"GET / HTTP/1.1\r\n")
        assert b"Host: example.com" in full

    def test_from_context_reads_stealth(self):
        from mytools.core.stealth import FragmentedSocket
        from mytools.core.utils import StealthContext

        ctx = StealthContext(fragment=10, fragment_tcp=8)
        fs = FragmentedSocket.from_context(object(), ctx)
        assert fs._fragment == 10
        assert fs._fragment_tcp == 8

    def test_from_context_no_ctx(self):
        from mytools.core.stealth import FragmentedSocket

        fs = FragmentedSocket.from_context(object(), None)
        assert fs._fragment == 0
        assert fs._fragment_tcp == 0

    def test_proxy_methods_to_wrapped(self):
        from mytools.core.stealth import FragmentedSocket

        class FakeSock:
            def __init__(self) -> None:
                self.timeout = 10
                self._closed = False

            def settimeout(self, t: float) -> None:
                self.timeout = t

            def close(self) -> None:
                self._closed = True

        real = FakeSock()
        fs = FragmentedSocket(real)
        fs.settimeout(5)
        assert real.timeout == 5
        fs.close()
        assert real._closed


class TestFragmentedTransport:
    def test_build_fragmented_transport_returns_transport(self):
        from mytools.core.stealth import (
            _FragmentedTransport,
            build_fragmented_transport,
        )

        t = build_fragmented_transport(fragment=10)
        assert isinstance(t, _FragmentedTransport)
        assert hasattr(t, "handle_async_request")
        assert hasattr(t, "_pool")

    def test_build_fragmented_transport_no_frag_returns_default(self):
        import httpx

        from mytools.core.stealth import (
            _FragmentedTransport,
            build_fragmented_transport,
        )

        t = build_fragmented_transport(fragment=0, fragment_tcp=0)
        assert isinstance(t, httpx.AsyncHTTPTransport)
        assert not isinstance(t, _FragmentedTransport)

    @pytest.mark.anyio
    async def test_fragmented_network_stream_no_frag_passthrough(self):
        from mytools.core.stealth import _FragmentedNetworkStream

        written: list[bytes] = []

        class FakeStream:
            async def write(self, data: bytes, timeout: float | None = None) -> None:
                written.append(data)

        fs = _FragmentedNetworkStream(FakeStream(), fragment=0, fragment_tcp=0)
        await fs.write(b"hello")
        assert written == [b"hello"]

    @pytest.mark.anyio
    async def test_fragmented_network_stream_tcp_frag(self):
        from mytools.core.stealth import _FragmentedNetworkStream

        written: list[bytes] = []

        class FakeStream:
            async def write(self, data: bytes, timeout: float | None = None) -> None:
                written.append(data)

        fs = _FragmentedNetworkStream(FakeStream(), fragment=0, fragment_tcp=4)
        await fs.write(b"ABCDEFGH")
        assert written == [b"ABCD", b"EFGH"]

    @pytest.mark.anyio
    async def test_fragmented_network_stream_http_frag(self):
        from mytools.core.stealth import _FragmentedNetworkStream

        written: list[bytes] = []

        class FakeStream:
            async def write(self, data: bytes, timeout: float | None = None) -> None:
                written.append(data)

        fs = _FragmentedNetworkStream(FakeStream(), fragment=5, fragment_tcp=0)
        data = b"GET / HTTP/1.1\r\nHost: x.com\r\n\r\nbody"
        await fs.write(data)
        assert len(written) >= 2
        full = b"".join(written)
        assert full == data
