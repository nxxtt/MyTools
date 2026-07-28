"""Testes do modulo subdomaintakeover."""

import asyncio
from dataclasses import asdict
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from mytools.web.subdomaintakeover import (
    TakeoverAttempt,
    TakeoverResult,
    _check_http_fingerprint,
    _enumerate_crtsh,
    _enumerate_wordlist,
    _get_services,
    _match_service,
    _resolve_cname,
    banner_art,
    build_parser,
    main,
    print_results,
    run_scan,
)

# ---------------------------------------------------------------------------
# _get_services
# ---------------------------------------------------------------------------


class TestServiceFingerprints:
    def test_services_loaded(self) -> None:
        services = _get_services()
        assert isinstance(services, dict)
        assert len(services) > 0

    def test_has_s3(self) -> None:
        services = _get_services()
        assert "s3" in services
        assert "cname_suffix" in services["s3"]
        assert "http_signatures" in services["s3"]

    def test_has_azure(self) -> None:
        services = _get_services()
        assert "azure" in services

    def test_has_heroku(self) -> None:
        services = _get_services()
        assert "heroku" in services

    def test_has_github_pages(self) -> None:
        services = _get_services()
        assert "github_pages" in services

    def test_all_have_cname_suffix(self) -> None:
        services = _get_services()
        for name, svc in services.items():
            assert "cname_suffix" in svc, f"{name} missing cname_suffix"
            assert isinstance(svc["cname_suffix"], str), f"{name} cname_suffix not str"

    def test_all_have_http_signatures(self) -> None:
        services = _get_services()
        for name, svc in services.items():
            assert "http_signatures" in svc, f"{name} missing http_signatures"
            assert isinstance(svc["http_signatures"], list), f"{name} http_signatures not list"
            assert len(svc["http_signatures"]) > 0, f"{name} http_signatures empty"


# ---------------------------------------------------------------------------
# _match_service
# ---------------------------------------------------------------------------


class TestMatchService:
    def test_match_s3(self) -> None:
        services = _get_services()
        result = _match_service("myapp.s3.amazonaws.com", services)
        assert result is not None
        assert result[0] == "s3"

    def test_match_azure(self) -> None:
        services = _get_services()
        result = _match_service("myapp.azurewebsites.net", services)
        assert result is not None
        assert result[0] == "azure"

    def test_match_heroku(self) -> None:
        services = _get_services()
        result = _match_service("myapp.herokuapp.com", services)
        assert result is not None
        assert result[0] == "heroku"

    def test_match_github(self) -> None:
        services = _get_services()
        result = _match_service("user.github.io", services)
        assert result is not None
        assert result[0] == "github_pages"

    def test_no_match(self) -> None:
        services = _get_services()
        result = _match_service("myapp.example.com", services)
        assert result is None

    def test_case_insensitive(self) -> None:
        services = _get_services()
        result = _match_service("MYAPP.S3.AMAZONAWS.COM", services)
        assert result is not None
        assert result[0] == "s3"


# ---------------------------------------------------------------------------
# _enumerate_wordlist
# ---------------------------------------------------------------------------


class TestEnumerateWordlist:
    def test_basic(self) -> None:
        subs = _enumerate_wordlist("example.com")
        assert len(subs) > 0
        assert all(s.endswith(".example.com") for s in subs)

    def test_has_www(self) -> None:
        subs = _enumerate_wordlist("example.com")
        assert "www.example.com" in subs

    def test_has_mail(self) -> None:
        subs = _enumerate_wordlist("example.com")
        assert "mail.example.com" in subs

    def test_no_duplicates(self) -> None:
        subs = _enumerate_wordlist("example.com")
        assert len(subs) == len(set(subs))

    def test_extra_wordlist(self, tmp_path: object) -> None:
        import pathlib

        wl = pathlib.Path(str(tmp_path)) / "extra.txt"
        wl.write_text("custom1\ncustom2\n# comment\n\n")
        subs = _enumerate_wordlist("example.com", str(wl))
        assert "custom1.example.com" in subs
        assert "custom2.example.com" in subs

    def test_extra_wordlist_missing_file(self) -> None:
        subs = _enumerate_wordlist("example.com", "/nonexistent/file.txt")
        assert len(subs) > 0


# ---------------------------------------------------------------------------
# _resolve_cname
# ---------------------------------------------------------------------------


class TestResolveCNAME:
    def test_no_cname(self) -> None:
        with patch("mytools.web.subdomaintakeover.dns.resolver.Resolver") as mock_r:
            mock_instance = MagicMock()
            mock_r.return_value = mock_instance
            mock_instance.resolve.side_effect = __import__("dns").resolver.NoAnswer()
            result = _resolve_cname("nonexistent.example.com")
            assert result is None

    def test_nxdomain(self) -> None:
        with patch("mytools.web.subdomaintakeover.dns.resolver.Resolver") as mock_r:
            mock_instance = MagicMock()
            mock_r.return_value = mock_instance
            mock_instance.resolve.side_effect = __import__("dns").resolver.NXDOMAIN()
            result = _resolve_cname("nonexistent.example.com")
            assert result is None

    def test_timeout(self) -> None:
        with patch("mytools.web.subdomaintakeover.dns.resolver.Resolver") as mock_r:
            mock_instance = MagicMock()
            mock_r.return_value = mock_instance
            mock_instance.resolve.side_effect = __import__("dns").resolver.Timeout()
            result = _resolve_cname("timeout.example.com")
            assert result is None


# ---------------------------------------------------------------------------
# _enumerate_crtsh
# ---------------------------------------------------------------------------


class TestEnumerateCrtsh:
    def test_rate_limit_fallback(self) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 429
        mock_resp.raise_for_status.side_effect = __import__("httpx").HTTPStatusError(
            message="429",
            request=MagicMock(),
            response=mock_resp,
        )
        with patch("mytools.web.subdomaintakeover.httpx.get", return_value=mock_resp):
            result = _enumerate_crtsh("example.com")
            assert result == []

    def test_success(self) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = [
            {"name_value": "www.example.com"},
            {"name_value": "api.example.com"},
            {"name_value": "*.example.com"},
        ]
        mock_resp.raise_for_status = MagicMock()
        with patch("mytools.web.subdomaintakeover.httpx.get", return_value=mock_resp):
            result = _enumerate_crtsh("example.com")
            assert "www.example.com" in result
            assert "api.example.com" in result
            assert "*.example.com" not in result

    def test_connection_error_fallback(self) -> None:
        with patch("mytools.web.subdomaintakeover.httpx.get", side_effect=Exception("connection")):
            result = _enumerate_crtsh("example.com")
            assert result == []


# ---------------------------------------------------------------------------
# _check_http_fingerprint
# ---------------------------------------------------------------------------


class TestCheckHTTPFingerprint:
    def test_match_found(self) -> None:
        async def run() -> tuple[int, bool, str]:
            client = MagicMock()
            resp = MagicMock()
            resp.status_code = 200
            resp.text = "NoSuchBucket: The specified bucket does not exist"
            client.get = AsyncMock(return_value=resp)
            client.__aenter__ = AsyncMock(return_value=client)
            client.__aexit__ = AsyncMock(return_value=False)
            async with client:
                return await _check_http_fingerprint(
                    client,
                    "test.s3.amazonaws.com",
                    ["NoSuchBucket"],
                )

        status, match, sig = asyncio.run(run())
        assert status == 200
        assert match is True
        assert sig == "NoSuchBucket"

    def test_no_match(self) -> None:
        async def run() -> tuple[int, bool, str]:
            client = MagicMock()
            resp = MagicMock()
            resp.status_code = 200
            resp.text = "<html>Hello World</html>"
            client.get = AsyncMock(return_value=resp)
            client.__aenter__ = AsyncMock(return_value=client)
            client.__aexit__ = AsyncMock(return_value=False)
            async with client:
                return await _check_http_fingerprint(
                    client,
                    "test.example.com",
                    ["NoSuchBucket"],
                )

        status, match, _sig = asyncio.run(run())
        assert status == 200
        assert match is False

    def test_connection_error(self) -> None:
        async def run() -> tuple[int, bool, str]:
            client = MagicMock()
            client.get = AsyncMock(side_effect=Exception("connect error"))
            client.__aenter__ = AsyncMock(return_value=client)
            client.__aexit__ = AsyncMock(return_value=False)
            async with client:
                return await _check_http_fingerprint(
                    client,
                    "test.example.com",
                    ["NoSuchBucket"],
                )

        status, match, _sig = asyncio.run(run())
        assert status == 0
        assert match is False


# ---------------------------------------------------------------------------
# TakeoverAttempt
# ---------------------------------------------------------------------------


class TestTakeoverAttempt:
    def test_creation(self) -> None:
        a = TakeoverAttempt(
            subdomain="test.example.com",
            cname_target="test.s3.amazonaws.com",
            service="s3",
            http_status=200,
            http_match=True,
            vulnerable=True,
            details="CNAME -> test.s3.amazonaws.com [s3]",
        )
        assert a.subdomain == "test.example.com"
        assert a.vulnerable is True

    def test_frozen(self) -> None:
        a = TakeoverAttempt(
            subdomain="test.example.com",
            cname_target="test.s3.amazonaws.com",
            service="s3",
            http_status=200,
            http_match=True,
            vulnerable=True,
            details="...",
        )
        with pytest.raises(AttributeError):
            a.vulnerable = False  # type: ignore[misc]


# ---------------------------------------------------------------------------
# TakeoverResult
# ---------------------------------------------------------------------------


class TestTakeoverResult:
    def test_creation(self) -> None:
        r = TakeoverResult(
            target="example.com",
            subdomains_scanned=100,
            dangling_cnames=2,
            attempts=[],
            vulnerable_subdomains=["a.example.com", "b.example.com"],
            overall_status="vulnerable",
        )
        assert r.target == "example.com"
        assert r.overall_status == "vulnerable"

    def test_asdict(self) -> None:
        r = TakeoverResult(
            target="example.com",
            subdomains_scanned=0,
            dangling_cnames=0,
            attempts=[],
            vulnerable_subdomains=[],
            overall_status="secure",
        )
        d = asdict(r)
        assert d["target"] == "example.com"
        assert d["overall_status"] == "secure"

    def test_frozen(self) -> None:
        r = TakeoverResult(
            target="example.com",
            subdomains_scanned=0,
            dangling_cnames=0,
            attempts=[],
            vulnerable_subdomains=[],
            overall_status="secure",
        )
        with pytest.raises(AttributeError):
            r.target = "other.com"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# build_parser
# ---------------------------------------------------------------------------


class TestBuildParser:
    def test_has_domain(self) -> None:
        parser = build_parser()
        assert any(a.dest == "domain" for a in parser._actions)

    def test_has_wordlist(self) -> None:
        parser = build_parser()
        assert any(a.dest == "wordlist" for a in parser._actions)

    def test_has_concurrency(self) -> None:
        parser = build_parser()
        assert any(a.dest == "concurrency" for a in parser._actions)

    def test_default_concurrency(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["example.com"])
        assert args.concurrency == 10

    def test_custom_concurrency(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["example.com", "--concurrency", "20"])
        assert args.concurrency == 20

    def test_wordlist(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["example.com", "--wordlist", "subs.txt"])
        assert args.wordlist == "subs.txt"


# ---------------------------------------------------------------------------
# print_results
# ---------------------------------------------------------------------------


class TestPrintResults:
    def test_secure(self, capsys: pytest.CaptureFixture[str]) -> None:
        r = TakeoverResult(
            target="example.com",
            subdomains_scanned=50,
            dangling_cnames=0,
            attempts=[],
            vulnerable_subdomains=[],
            overall_status="secure",
        )
        print_results(r)
        out = capsys.readouterr().out
        assert "SECURE" in out or "Nenhum" in out

    def test_vulnerable(self, capsys: pytest.CaptureFixture[str]) -> None:
        a = TakeoverAttempt(
            subdomain="test.example.com",
            cname_target="test.s3.amazonaws.com",
            service="s3",
            http_status=200,
            http_match=True,
            vulnerable=True,
            details="CNAME -> test.s3.amazonaws.com [s3], HTTP 200",
        )
        r = TakeoverResult(
            target="example.com",
            subdomains_scanned=10,
            dangling_cnames=1,
            attempts=[a],
            vulnerable_subdomains=["test.example.com"],
            overall_status="vulnerable",
        )
        print_results(r)
        out = capsys.readouterr().out
        assert "VULNERAVEIS" in out or "VULNERAVEL" in out
        assert "test.example.com" in out


# ---------------------------------------------------------------------------
# banner
# ---------------------------------------------------------------------------


class TestBanner:
    def test_callable(self) -> None:
        assert callable(banner_art)


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------


class TestMain:
    def test_main_no_args(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("sys.argv", ["mytools-subtakeover"])
        monkeypatch.setattr("builtins.input", lambda _: (_ for _ in ()).throw(EOFError))
        result = main()
        assert result == 0


# ---------------------------------------------------------------------------
# run_scan
# ---------------------------------------------------------------------------


class TestRunScan:
    def test_no_subdomains(self) -> None:
        async def run() -> TakeoverResult:
            with patch("mytools.web.subdomaintakeover._enumerate_subdomains", return_value=[]):
                return await run_scan(domain="example.com")

        result = asyncio.run(run())
        assert result.overall_status == "secure"
        assert result.subdomains_scanned == 0

    def test_vulnerable(self) -> None:
        async def run() -> TakeoverResult:
            with (
                patch(
                    "mytools.web.subdomaintakeover._enumerate_subdomains",
                    return_value=["test.example.com"],
                ),
                patch(
                    "mytools.web.subdomaintakeover._resolve_cname",
                    return_value="test.s3.amazonaws.com",
                ),
                patch(
                    "mytools.web.subdomaintakeover._get_services",
                    return_value={
                        "s3": {
                            "cname_suffix": ".s3.amazonaws.com",
                            "http_signatures": ["NoSuchBucket"],
                        },
                    },
                ),
            ):
                client = MagicMock()
                resp = MagicMock()
                resp.status_code = 200
                resp.text = "NoSuchBucket: bucket not found"
                client.get = AsyncMock(return_value=resp)
                client.aclose = AsyncMock()
                client.__aenter__ = AsyncMock(return_value=client)
                client.__aexit__ = AsyncMock(return_value=False)
                with patch("mytools.web.subdomaintakeover.create_async_client", return_value=client):
                    return await run_scan(domain="example.com")

        result = asyncio.run(run())
        assert result.overall_status == "vulnerable"
        assert len(result.vulnerable_subdomains) == 1
        assert result.vulnerable_subdomains[0] == "test.example.com"

    def test_secure(self) -> None:
        async def run() -> TakeoverResult:
            with (
                patch(
                    "mytools.web.subdomaintakeover._enumerate_subdomains",
                    return_value=["test.example.com"],
                ),
                patch(
                    "mytools.web.subdomaintakeover._resolve_cname",
                    return_value="test.example.com.cdn.cloudflare.net",
                ),
                patch(
                    "mytools.web.subdomaintakeover._get_services",
                    return_value={
                        "s3": {
                            "cname_suffix": ".s3.amazonaws.com",
                            "http_signatures": ["NoSuchBucket"],
                        },
                    },
                ),
            ):
                client = MagicMock()
                client.aclose = AsyncMock()
                client.__aenter__ = AsyncMock(return_value=client)
                client.__aexit__ = AsyncMock(return_value=False)
                with patch("mytools.web.subdomaintakeover.create_async_client", return_value=client):
                    return await run_scan(domain="example.com")

        result = asyncio.run(run())
        assert result.overall_status == "secure"

    def test_no_cname(self) -> None:
        async def run() -> TakeoverResult:
            with (
                patch(
                    "mytools.web.subdomaintakeover._enumerate_subdomains",
                    return_value=["test.example.com"],
                ),
                patch(
                    "mytools.web.subdomaintakeover._resolve_cname",
                    return_value=None,
                ),
                patch(
                    "mytools.web.subdomaintakeover._get_services",
                    return_value={"s3": {"cname_suffix": ".s3.amazonaws.com", "http_signatures": []}},
                ),
            ):
                client = MagicMock()
                client.aclose = AsyncMock()
                client.__aenter__ = AsyncMock(return_value=client)
                client.__aexit__ = AsyncMock(return_value=False)
                with patch("mytools.web.subdomaintakeover.create_async_client", return_value=client):
                    return await run_scan(domain="example.com")

        result = asyncio.run(run())
        assert result.overall_status == "secure"
        assert result.dangling_cnames == 0
