"""Testes do modulo sqliscan."""

import asyncio
from dataclasses import asdict
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from mytools.web.sqliscan import (
    SQLiAttempt,
    SQLiResult,
    _build_inject_url,
    _detect_db_error,
    _extract_params,
    _test_boolean_blind,
    _test_error,
    _test_time_blind,
    _test_union,
    banner_art,
    build_parser,
    main,
    print_results,
    run_scan,
)

# ---------------------------------------------------------------------------
# _detect_db_error
# ---------------------------------------------------------------------------


class TestDetectDbError:
    def test_mysql(self) -> None:
        body = b"You have an error in your SQL syntax near '1'"
        assert _detect_db_error(body) == "mysql"

    def test_postgresql(self) -> None:
        body = b"PG::SyntaxError at line 42"
        assert _detect_db_error(body) == "postgresql"

    def test_mssql(self) -> None:
        body = b"Incorrect syntax near the keyword 'SELECT'"
        assert _detect_db_error(body) == "mssql"

    def test_oracle(self) -> None:
        body = b"ORA-01756: quoted string not properly terminated"
        assert _detect_db_error(body) == "oracle"

    def test_sqlite(self) -> None:
        body = b'SQLITE_ERROR: unrecognized token: "xyz"'
        assert _detect_db_error(body) == "sqlite"

    def test_no_error(self) -> None:
        body = b"<html><body>Hello world</body></html>"
        assert _detect_db_error(body) == ""


# ---------------------------------------------------------------------------
# _build_inject_url
# ---------------------------------------------------------------------------


class TestBuildInjectUrl:
    def test_basic(self) -> None:
        url = _build_inject_url("http://test.com/?id=1", "id", "' OR 1=1--")
        assert "' OR 1=1--" in url
        assert "id=" in url

    def test_multiple_params(self) -> None:
        url = _build_inject_url("http://test.com/?id=1&q=test", "q", "payload")
        assert "payload" in url
        assert "id=1" in url


# ---------------------------------------------------------------------------
# _extract_params
# ---------------------------------------------------------------------------


class TestExtractParams:
    def test_url_params(self) -> None:
        params = _extract_params("http://test.com/?id=1&q=test")
        assert "id" in params
        assert "q" in params

    def test_forced_param(self) -> None:
        params = _extract_params("http://test.com/", forced_param="custom")
        assert params == ["custom"]

    def test_no_params_default(self) -> None:
        params = _extract_params("http://test.com/")
        assert len(params) > 0
        assert "id" in params


# ---------------------------------------------------------------------------
# build_parser
# ---------------------------------------------------------------------------


class TestBuildParser:
    def test_basic(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["https://target.com"])
        assert args.url == "https://target.com"

    def test_default_category(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["https://target.com"])
        assert args.category == "all"

    def test_category(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["https://target.com", "-c", "error"])
        assert args.category == "error"

    def test_invalid_category(self) -> None:
        parser = build_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["https://target.com", "-c", "invalid"])

    def test_time_threshold(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["https://target.com", "--time-threshold", "2.5"])
        assert args.time_threshold == 2.5


# ---------------------------------------------------------------------------
# SQLiAttempt / SQLiResult
# ---------------------------------------------------------------------------


class TestSQLiAttempt:
    def test_frozen(self) -> None:
        a = SQLiAttempt(
            technique="error",
            category="error",
            injection_point="id",
            url="http://test.com",
            payload="'",
            status_baseline=200,
            status_test=500,
            size_baseline=100,
            size_test=500,
            time_baseline=0.1,
            time_test=0.1,
            db_detected="mysql",
            content_match=True,
            timing_match=False,
            vulnerable=True,
            details="DB detectado: mysql",
            error="",
        )
        with pytest.raises(AttributeError):
            a.vulnerable = False  # type: ignore[misc]

    def test_exploit_default(self) -> None:
        a = SQLiAttempt(
            technique="error",
            category="error",
            injection_point="id",
            url="http://test.com",
            payload="'",
            status_baseline=200,
            status_test=500,
            size_baseline=100,
            size_test=500,
            time_baseline=0.1,
            time_test=0.1,
            db_detected="mysql",
            content_match=True,
            timing_match=False,
            vulnerable=True,
            details="",
            error="",
        )
        assert a.exploit == ""
        assert a.tool == ""


class TestSQLiResult:
    def test_frozen(self) -> None:
        r = SQLiResult(
            target="http://test.com",
            baseline_status=200,
            baseline_size=100,
            tls=True,
            attempts=[],
            vulnerable_techniques=[],
            blocked_techniques=[],
            issues=[],
            overall_status="secure",
        )
        with pytest.raises(AttributeError):
            r.overall_status = "x"  # type: ignore[misc]

    def test_asdict(self) -> None:
        r = SQLiResult(
            target="http://test.com",
            baseline_status=200,
            baseline_size=100,
            tls=True,
            attempts=[],
            vulnerable_techniques=[],
            blocked_techniques=[],
            issues=[],
            overall_status="secure",
        )
        d = asdict(r)
        assert d["target"] == "http://test.com"
        assert d["baseline_size"] == 100


# ---------------------------------------------------------------------------
# print_results
# ---------------------------------------------------------------------------


class TestPrintResults:
    def test_secure(self, capsys: pytest.CaptureFixture[str]) -> None:
        r = SQLiResult(
            target="http://test.com",
            baseline_status=200,
            baseline_size=100,
            tls=False,
            attempts=[],
            vulnerable_techniques=[],
            blocked_techniques=[],
            issues=[],
            overall_status="secure",
        )
        print_results(r)
        assert "SECURE" in capsys.readouterr().out

    def test_vulnerable(self, capsys: pytest.CaptureFixture[str]) -> None:
        r = SQLiResult(
            target="http://test.com",
            baseline_status=200,
            baseline_size=100,
            tls=False,
            attempts=[],
            vulnerable_techniques=["error"],
            blocked_techniques=[],
            issues=["1 payload(s) confirmado(s)"],
            overall_status="vulnerable",
        )
        print_results(r)
        assert "VULNERABLE" in capsys.readouterr().out


# ---------------------------------------------------------------------------
# banner
# ---------------------------------------------------------------------------


class TestBanner:
    def test_exists(self) -> None:
        assert callable(banner_art)


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------


class TestMain:
    def test_main_no_args(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("sys.argv", ["mytools-sqli"])
        monkeypatch.setattr("builtins.input", lambda _: (_ for _ in ()).throw(EOFError))
        result = main()
        assert result == 0


# ---------------------------------------------------------------------------
# _test_error
# ---------------------------------------------------------------------------


class TestErrorBased:
    def test_mysql_detected(self) -> None:
        async def run() -> list[SQLiAttempt]:
            client = MagicMock()
            resp = MagicMock()
            resp.status_code = 500
            resp.content = b"You have an error in your SQL syntax near ''"
            client.get = AsyncMock(return_value=resp)
            client.__aenter__ = AsyncMock(return_value=client)
            client.__aexit__ = AsyncMock(return_value=False)
            async with client:
                baseline = (200, 1000, b"<html>ok</html>", 0.1)
                return await _test_error(
                    client, "http://test.com/?id=1", ["id"], baseline, ["'"]
                )

        attempts = asyncio.run(run())
        assert len(attempts) == 1
        assert attempts[0].vulnerable is True
        assert attempts[0].db_detected == "mysql"

    def test_no_error(self) -> None:
        async def run() -> list[SQLiAttempt]:
            client = MagicMock()
            resp = MagicMock()
            resp.status_code = 200
            resp.content = b"<html>Hello</html>"
            client.get = AsyncMock(return_value=resp)
            client.__aenter__ = AsyncMock(return_value=client)
            client.__aexit__ = AsyncMock(return_value=False)
            async with client:
                baseline = (200, 1000, b"<html>ok</html>", 0.1)
                return await _test_error(
                    client, "http://test.com/?id=1", ["id"], baseline, ["'"]
                )

        attempts = asyncio.run(run())
        assert len(attempts) == 1
        assert attempts[0].vulnerable is False


# ---------------------------------------------------------------------------
# _test_boolean_blind
# ---------------------------------------------------------------------------


class TestBooleanBlind:
    def test_consistent_diff(self) -> None:
        async def run() -> list[SQLiAttempt]:
            call_count = 0

            async def mock_get(url: str, **kwargs: object) -> MagicMock:
                nonlocal call_count
                call_count += 1
                resp = MagicMock()
                resp.status_code = 200
                if "1=1" in url:
                    resp.content = b"<html>" + b"x" * 2000 + b"</html>"
                else:
                    resp.content = b"<html>" + b"x" * 100 + b"</html>"
                return resp

            client = MagicMock()
            client.get = mock_get
            client.__aenter__ = AsyncMock(return_value=client)
            client.__aexit__ = AsyncMock(return_value=False)
            async with client:
                baseline = (200, 1000, b"<html>ok</html>", 0.1)
                return await _test_boolean_blind(
                    client,
                    "http://test.com/?id=1",
                    ["id"],
                    baseline,
                    pairs=[["' AND 1=1--", "' AND 1=2--"]],
                )

        attempts = asyncio.run(run())
        assert len(attempts) == 1
        assert attempts[0].vulnerable is True

    def test_inconsistent_diff(self) -> None:
        async def run() -> list[SQLiAttempt]:
            call_count = 0

            async def mock_get(url: str, **kwargs: object) -> MagicMock:
                nonlocal call_count
                call_count += 1
                resp = MagicMock()
                resp.status_code = 200
                resp.content = b"<html>" + b"x" * 1000 + b"</html>"
                return resp

            client = MagicMock()
            client.get = mock_get
            client.__aenter__ = AsyncMock(return_value=client)
            client.__aexit__ = AsyncMock(return_value=False)
            async with client:
                baseline = (200, 1000, b"<html>ok</html>", 0.1)
                return await _test_boolean_blind(
                    client,
                    "http://test.com/?id=1",
                    ["id"],
                    baseline,
                    pairs=[["' AND 1=1--", "' AND 1=2--"]],
                )

        attempts = asyncio.run(run())
        assert len(attempts) == 1
        assert attempts[0].vulnerable is False


# ---------------------------------------------------------------------------
# _test_time_blind
# ---------------------------------------------------------------------------


class TestTimeBlind:
    def test_above_threshold(self) -> None:
        async def run() -> list[SQLiAttempt]:
            async def mock_get(url: str, **kwargs: object) -> MagicMock:
                resp = MagicMock()
                resp.status_code = 200
                resp.content = b"<html>ok</html>"
                return resp

            client = MagicMock()
            client.get = mock_get
            client.__aenter__ = AsyncMock(return_value=client)
            client.__aexit__ = AsyncMock(return_value=False)

            with patch("mytools.web.sqliscan.time") as mock_time:
                call_n = [0]
                mock_time.monotonic.side_effect = lambda: (
                    (call_n.__setitem__(0, call_n[0] + 1) or 0.0)
                    or (4.0 if call_n[0] % 2 == 0 else 0.1)
                )

                async with client:
                    baseline = (200, 1000, b"<html>ok</html>", 0.1)
                    return await _test_time_blind(
                        client,
                        "http://test.com/?id=1",
                        ["id"],
                        baseline,
                        payloads=["' AND SLEEP(3)--"],
                    )

        attempts = asyncio.run(run())
        assert len(attempts) >= 1

    def test_below_threshold(self) -> None:
        async def run() -> list[SQLiAttempt]:
            async def mock_get(url: str, **kwargs: object) -> MagicMock:
                resp = MagicMock()
                resp.status_code = 200
                resp.content = b"<html>ok</html>"
                return resp

            client = MagicMock()
            client.get = mock_get
            client.__aenter__ = AsyncMock(return_value=client)
            client.__aexit__ = AsyncMock(return_value=False)

            with patch("mytools.web.sqliscan.time") as mock_time:
                mock_time.monotonic.side_effect = [0.0, 0.2]

                async with client:
                    baseline = (200, 1000, b"<html>ok</html>", 0.1)
                    return await _test_time_blind(
                        client,
                        "http://test.com/?id=1",
                        ["id"],
                        baseline,
                        payloads=["' AND SLEEP(3)--"],
                    )

        attempts = asyncio.run(run())
        assert len(attempts) == 1
        assert attempts[0].vulnerable is False


# ---------------------------------------------------------------------------
# _test_union
# ---------------------------------------------------------------------------


class TestUnion:
    def test_wrong_columns(self) -> None:
        async def run() -> list[SQLiAttempt]:
            async def mock_get(url: str, **kwargs: object) -> MagicMock:
                resp = MagicMock()
                resp.status_code = 500
                resp.content = b"Error: The used SELECT statements have a different number of columns"
                return resp

            client = MagicMock()
            client.get = mock_get
            client.__aenter__ = AsyncMock(return_value=client)
            client.__aexit__ = AsyncMock(return_value=False)
            async with client:
                baseline = (200, 1000, b"<html>ok</html>", 0.1)
                return await _test_union(
                    client,
                    "http://test.com/?id=1",
                    ["id"],
                    baseline,
                    payloads=["' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--"],
                )

        attempts = asyncio.run(run())
        assert len(attempts) == 1
        assert attempts[0].vulnerable is False
        assert (
            "wrong" in attempts[0].details.lower()
            or "precisa" in attempts[0].details.lower()
        )


# ---------------------------------------------------------------------------
# run_scan
# ---------------------------------------------------------------------------


class TestRunScan:
    def test_invalid_category(self) -> None:
        async def run() -> SQLiResult:
            client = MagicMock()
            resp = MagicMock()
            resp.status_code = 200
            resp.content = b"<html>ok</html>"
            resp.cookies = {}
            client.get = AsyncMock(return_value=resp)
            client.__aenter__ = AsyncMock(return_value=client)
            client.__aexit__ = AsyncMock(return_value=False)
            with patch("mytools.web.sqliscan.create_async_client") as mock:
                mock.return_value.__aenter__ = AsyncMock(return_value=client)
                mock.return_value.__aexit__ = AsyncMock(return_value=False)
                return await run_scan(url="http://test.com/?id=1", category="invalid")

        result = asyncio.run(run())
        assert result.overall_status == "error"

    def test_baseline_error(self) -> None:
        async def run() -> SQLiResult:
            client = MagicMock()
            resp = MagicMock()
            resp.status_code = 0
            resp.content = b""
            resp.cookies = {}
            client.get = AsyncMock(return_value=resp)
            client.__aenter__ = AsyncMock(return_value=client)
            client.__aexit__ = AsyncMock(return_value=False)
            with patch("mytools.web.sqliscan.create_async_client") as mock:
                mock.return_value.__aenter__ = AsyncMock(return_value=client)
                mock.return_value.__aexit__ = AsyncMock(return_value=False)
                return await run_scan(url="http://test.com/?id=1", category="all")

        result = asyncio.run(run())
        assert result.overall_status == "error"
        assert result.baseline_status == 0
