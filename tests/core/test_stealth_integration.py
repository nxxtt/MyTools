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


class TestFetchStealth:
    @respx.mock
    @pytest.mark.anyio
    async def test_waf_evasion_modifies_url(self):
        init_scanner(_make_args(waf_evasion=True))
        route = respx.route(method="GET").mock(return_value=httpx.Response(200, content=b"ok"))
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
    async def test_no_stealth_fetch_unchanged(self):
        init_scanner(_make_args())
        respx.get("http://example.com/plain").mock(
            return_value=httpx.Response(200, content=b"plain")
        )
        client = httpx.AsyncClient()
        status, _, body, _ = await fetch(client, "http://example.com/plain")
        assert status == 200
        assert body == b"plain"
