"""Testes do modulo sqliscan."""

import asyncio
import json
import runpy
from dataclasses import asdict
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from mytools.web.sqliscan import (
    _BLIND_BOOLEAN_PAIRS_DEFAULT,
    _BYPASS_PAYLOADS_DEFAULT,
    _ERROR_PAYLOADS_DEFAULT,
    _TIME_PAYLOADS_DEFAULT,
    _UNION_PAYLOADS_DEFAULT,
    SQLiAttempt,
    SQLiResult,
    _build_inject_url,
    _detect_db_error,
    _extract_params,
    _get_blind_boolean_pairs,
    _get_bypass_payloads,
    _get_error_payloads,
    _get_time_payloads,
    _get_union_payloads,
    _inject,
    _load_db_error_patterns,
    _test_baseline,
    _test_boolean_blind,
    _test_bypass,
    _test_error,
    _test_time_blind,
    _test_union,
    banner_art,
    build_parser,
    main,
    print_results,
    run_once,
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


# ---------------------------------------------------------------------------
# Payload loaders
# ---------------------------------------------------------------------------


class TestPayloadLoaders:
    def test_get_error_payloads(self) -> None:
        assert len(_get_error_payloads()) > 0

    def test_get_error_payloads_invalid(self) -> None:
        with patch(
            "mytools.web.sqliscan._load_payloads",
            return_value={"error_payloads": "junk"},
        ):
            assert _get_error_payloads() == _ERROR_PAYLOADS_DEFAULT

    def test_get_blind_boolean_pairs(self) -> None:
        pairs = _get_blind_boolean_pairs()
        assert len(pairs) > 0
        assert isinstance(pairs[0], list)

    def test_get_blind_boolean_pairs_invalid(self) -> None:
        with patch(
            "mytools.web.sqliscan._load_payloads",
            return_value={"blind_boolean_pairs": "junk"},
        ):
            assert _get_blind_boolean_pairs() == _BLIND_BOOLEAN_PAIRS_DEFAULT

    def test_get_time_payloads(self) -> None:
        assert len(_get_time_payloads()) > 0

    def test_get_time_payloads_invalid(self) -> None:
        with patch(
            "mytools.web.sqliscan._load_payloads",
            return_value={"time_payloads": "junk"},
        ):
            assert _get_time_payloads() == _TIME_PAYLOADS_DEFAULT

    def test_get_union_payloads(self) -> None:
        assert len(_get_union_payloads()) > 0

    def test_get_union_payloads_invalid(self) -> None:
        with patch(
            "mytools.web.sqliscan._load_payloads",
            return_value={"union_payloads": "junk"},
        ):
            assert _get_union_payloads() == _UNION_PAYLOADS_DEFAULT

    def test_get_bypass_payloads(self) -> None:
        assert len(_get_bypass_payloads()) > 0

    def test_get_bypass_payloads_invalid(self) -> None:
        with patch(
            "mytools.web.sqliscan._load_payloads",
            return_value={"bypass_payloads": "junk"},
        ):
            assert _get_bypass_payloads() == _BYPASS_PAYLOADS_DEFAULT

    def test_load_db_error_patterns_compiles(self) -> None:
        with patch(
            "mytools.data.load_payloads",
            return_value={
                "db_error_patterns": {
                    "mysql": ["plain string pattern"],
                    "postgresql": "not a list",
                    "empty": [],
                }
            },
        ):
            compiled = _load_db_error_patterns()
        assert isinstance(compiled, dict)
        assert "mysql" in compiled
        assert "postgresql" not in compiled
        assert compiled["mysql"][0].pattern == "plain string pattern"

    def test_load_db_error_patterns_not_dict(self) -> None:
        with patch(
            "mytools.data.load_payloads",
            return_value={"db_error_patterns": "junk"},
        ):
            compiled = _load_db_error_patterns()
        assert compiled["mysql"][0].pattern == "You have an error in your SQL syntax"

    def test_load_db_error_patterns_empty_compiled(self) -> None:
        with patch(
            "mytools.data.load_payloads",
            return_value={"db_error_patterns": {"mysql": "not a list"}},
        ):
            compiled = _load_db_error_patterns()
        assert compiled["mysql"][0].pattern == "You have an error in your SQL syntax"


# ---------------------------------------------------------------------------
# _test_baseline
# ---------------------------------------------------------------------------


class TestBaseline:
    @pytest.mark.asyncio
    async def test_request_error(self) -> None:
        client = MagicMock()
        client.get = AsyncMock(side_effect=httpx.RequestError("x"))
        baseline = await _test_baseline(client, "http://test.com/?id=1")
        assert baseline == (0, 0, b"", 0.0)


# ---------------------------------------------------------------------------
# _inject
# ---------------------------------------------------------------------------


class TestInject:
    @pytest.mark.asyncio
    async def test_request_error_returns_none(self) -> None:
        client = MagicMock()
        client.get = AsyncMock(side_effect=httpx.RequestError("x"))
        result = await _inject(client, "http://test.com/?id=1", "id", "'")
        assert result is None


# ---------------------------------------------------------------------------
# _test_error — branches restantes
# ---------------------------------------------------------------------------


class TestErrorBranches:
    @pytest.mark.asyncio
    async def test_all_requests_fail(self) -> None:
        client = MagicMock()
        client.get = AsyncMock(side_effect=httpx.RequestError("x"))
        client.__aenter__ = AsyncMock(return_value=client)
        client.__aexit__ = AsyncMock(return_value=False)
        async with client:
            baseline = (200, 1000, b"<html>ok</html>", 0.1)
            attempts = await _test_error(
                client, "http://test.com/?id=1", ["id"], baseline, ["'"]
            )
        assert len(attempts) == 1
        assert attempts[0].error == "Request failed"

    @pytest.mark.asyncio
    async def test_second_get_raises(self) -> None:
        client = MagicMock()
        resp = MagicMock()
        resp.status_code = 200
        resp.content = b"<html>no error</html>"
        client.get = AsyncMock(side_effect=[resp, httpx.RequestError("x")])
        client.__aenter__ = AsyncMock(return_value=client)
        client.__aexit__ = AsyncMock(return_value=False)
        async with client:
            baseline = (200, 1000, b"<html>ok</html>", 0.1)
            attempts = await _test_error(
                client, "http://test.com/?id=1", ["id"], baseline, ["'"]
            )
        assert len(attempts) == 1
        assert attempts[0].vulnerable is False

    @pytest.mark.asyncio
    async def test_second_order_failed(self) -> None:
        client = MagicMock()
        resp = MagicMock()
        resp.status_code = 500
        resp.content = b"You have an error in your SQL syntax near ''"
        client.get = AsyncMock(return_value=resp)
        client.__aenter__ = AsyncMock(return_value=client)
        client.__aexit__ = AsyncMock(return_value=False)
        with (
            patch(
                "mytools.web.sqliscan.get_verify_payload",
                return_value=("v", [b"err"]),
            ),
            patch(
                "mytools.web.sqliscan.verify_positive",
                new=AsyncMock(return_value=(False, "no match")),
            ),
        ):
            async with client:
                baseline = (200, 1000, b"<html>ok</html>", 0.1)
                attempts = await _test_error(
                    client, "http://test.com/?id=1", ["id"], baseline, ["'"]
                )
        assert len(attempts) == 1
        assert attempts[0].vulnerable is False
        assert "2nd-order failed" in attempts[0].details

    @pytest.mark.asyncio
    async def test_second_order_confirmed(self) -> None:
        client = MagicMock()
        resp = MagicMock()
        resp.status_code = 500
        resp.content = b"You have an error in your SQL syntax near ''"
        client.get = AsyncMock(return_value=resp)
        client.__aenter__ = AsyncMock(return_value=client)
        client.__aexit__ = AsyncMock(return_value=False)
        with (
            patch(
                "mytools.web.sqliscan.get_verify_payload",
                return_value=("v", [b"err"]),
            ),
            patch(
                "mytools.web.sqliscan.verify_positive",
                new=AsyncMock(return_value=(True, "match")),
            ),
        ):
            async with client:
                baseline = (200, 1000, b"<html>ok</html>", 0.1)
                attempts = await _test_error(
                    client, "http://test.com/?id=1", ["id"], baseline, ["'"]
                )
        assert len(attempts) == 1
        assert attempts[0].vulnerable is True
        assert "2nd-order confirmed" in attempts[0].details

    @pytest.mark.asyncio
    async def test_second_order_skipped_when_no_verify(self) -> None:
        client = MagicMock()
        resp = MagicMock()
        resp.status_code = 500
        resp.content = b"You have an error in your SQL syntax near ''"
        client.get = AsyncMock(return_value=resp)
        client.__aenter__ = AsyncMock(return_value=client)
        client.__aexit__ = AsyncMock(return_value=False)
        with patch(
            "mytools.web.sqliscan.get_verify_payload",
            return_value=None,
        ):
            async with client:
                baseline = (200, 1000, b"<html>ok</html>", 0.1)
                attempts = await _test_error(
                    client, "http://test.com/?id=1", ["id"], baseline, ["'"]
                )
        assert len(attempts) == 1
        assert attempts[0].vulnerable is True
        assert attempts[0].db_detected == "mysql"
        assert "2nd-order" not in attempts[0].details


# ---------------------------------------------------------------------------
# _test_boolean_blind — brancos restantes
# ---------------------------------------------------------------------------


class TestBooleanBlindBranches:
    @pytest.mark.asyncio
    async def test_all_requests_fail(self) -> None:
        client = MagicMock()
        client.get = AsyncMock(side_effect=httpx.RequestError("x"))
        client.__aenter__ = AsyncMock(return_value=client)
        client.__aexit__ = AsyncMock(return_value=False)
        async with client:
            baseline = (200, 1000, b"<html>ok</html>", 0.1)
            attempts = await _test_boolean_blind(
                client,
                "http://test.com/?id=1",
                ["id"],
                baseline,
                pairs=[["' AND 1=1--", "' AND 1=2--"]],
            )
        assert len(attempts) == 1
        assert attempts[0].vulnerable is False


# ---------------------------------------------------------------------------
# _test_time_blind — request fail
# ---------------------------------------------------------------------------


class TestTimeBlindBranches:
    @pytest.mark.asyncio
    async def test_request_failed(self) -> None:
        client = MagicMock()
        client.get = AsyncMock(side_effect=httpx.RequestError("x"))
        client.__aenter__ = AsyncMock(return_value=client)
        client.__aexit__ = AsyncMock(return_value=False)
        async with client:
            baseline = (200, 1000, b"<html>ok</html>", 0.1)
            attempts = await _test_time_blind(
                client,
                "http://test.com/?id=1",
                ["id"],
                baseline,
                payloads=["' AND SLEEP(3)--"],
            )
        assert len(attempts) == 1
        assert attempts[0].error == "Request failed"


# ---------------------------------------------------------------------------
# _test_union — branches restantes
# ---------------------------------------------------------------------------


class TestUnionBranches:
    @pytest.mark.asyncio
    async def test_request_failed(self) -> None:
        client = MagicMock()
        client.get = AsyncMock(side_effect=httpx.RequestError("x"))
        client.__aenter__ = AsyncMock(return_value=client)
        client.__aexit__ = AsyncMock(return_value=False)
        async with client:
            baseline = (200, 1000, b"<html>ok</html>", 0.1)
            attempts = await _test_union(
                client,
                "http://test.com/?id=1",
                ["id"],
                baseline,
                payloads=["' UNION SELECT NULL--"],
            )
        assert len(attempts) == 1
        assert attempts[0].error == "Request failed"

    @pytest.mark.asyncio
    async def test_second_get_raises(self) -> None:
        client = MagicMock()
        resp = MagicMock()
        resp.status_code = 200
        resp.content = b"<html>normal body</html>"
        client.get = AsyncMock(side_effect=[resp, httpx.RequestError("x")])
        client.__aenter__ = AsyncMock(return_value=client)
        client.__aexit__ = AsyncMock(return_value=False)
        async with client:
            baseline = (200, 1000, b"<html>ok</html>", 0.1)
            attempts = await _test_union(
                client,
                "http://test.com/?id=1",
                ["id"],
                baseline,
                payloads=["' UNION SELECT NULL--"],
            )
        assert len(attempts) == 1
        assert attempts[0].vulnerable is False

    @pytest.mark.asyncio
    async def test_vulnerable_db_detected(self) -> None:
        client = MagicMock()
        resp = MagicMock()
        resp.status_code = 200
        resp.content = b"You have an error in your SQL syntax" + b"x" * 600
        client.get = AsyncMock(return_value=resp)
        client.__aenter__ = AsyncMock(return_value=client)
        client.__aexit__ = AsyncMock(return_value=False)
        async with client:
            baseline = (200, 1000, b"<html>ok</html>", 0.1)
            attempts = await _test_union(
                client,
                "http://test.com/?id=1",
                ["id"],
                baseline,
                payloads=["' UNION SELECT NULL--"],
            )
        assert len(attempts) == 1
        assert attempts[0].vulnerable is True
        assert attempts[0].db_detected == "mysql"


# ---------------------------------------------------------------------------
# _test_bypass
# ---------------------------------------------------------------------------


class TestBypass:
    @pytest.mark.asyncio
    async def test_db_detected(self) -> None:
        client = MagicMock()
        resp = MagicMock()
        resp.status_code = 200
        resp.content = b"PG::SyntaxError near line 1"
        client.get = AsyncMock(return_value=resp)
        client.__aenter__ = AsyncMock(return_value=client)
        client.__aexit__ = AsyncMock(return_value=False)
        async with client:
            baseline = (200, 1000, b"<html>ok</html>", 0.1)
            attempts = await _test_bypass(
                client,
                "http://test.com/?id=1",
                ["id"],
                baseline,
                payloads=["' /*!50000OR*/ 1=1--"],
            )
        assert len(attempts) == 1
        assert attempts[0].vulnerable is True
        assert attempts[0].db_detected == "postgresql"

    @pytest.mark.asyncio
    async def test_no_db(self) -> None:
        client = MagicMock()
        resp = MagicMock()
        resp.status_code = 200
        resp.content = b"<html>safe</html>"
        client.get = AsyncMock(return_value=resp)
        client.__aenter__ = AsyncMock(return_value=client)
        client.__aexit__ = AsyncMock(return_value=False)
        async with client:
            baseline = (200, 1000, b"<html>ok</html>", 0.1)
            attempts = await _test_bypass(
                client,
                "http://test.com/?id=1",
                ["id"],
                baseline,
                payloads=["' /*!50000OR*/ 1=1--"],
            )
        assert len(attempts) == 1
        assert attempts[0].vulnerable is False

    @pytest.mark.asyncio
    async def test_request_failed(self) -> None:
        client = MagicMock()
        client.get = AsyncMock(side_effect=httpx.RequestError("x"))
        client.__aenter__ = AsyncMock(return_value=client)
        client.__aexit__ = AsyncMock(return_value=False)
        async with client:
            baseline = (200, 1000, b"<html>ok</html>", 0.1)
            attempts = await _test_bypass(
                client,
                "http://test.com/?id=1",
                ["id"],
                baseline,
                payloads=["' /*!50000OR*/ 1=1--"],
            )
        assert len(attempts) == 1
        assert attempts[0].error == "Request failed"


# ---------------------------------------------------------------------------
# run_scan — fluxo completo
# ---------------------------------------------------------------------------


def _make_client(get_impl: object) -> MagicMock:
    client = MagicMock()
    client.get = get_impl
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=False)
    return client


class TestRunScanFull:
    @pytest.mark.asyncio
    async def test_no_scheme(self) -> None:
        client = _make_client(
            AsyncMock(
                return_value=MagicMock(
                    status_code=200, content=b"<html>ok</html>", cookies={}
                )
            )
        )
        with patch("mytools.web.sqliscan.create_async_client") as mock:
            mock.return_value.__aenter__ = AsyncMock(return_value=client)
            mock.return_value.__aexit__ = AsyncMock(return_value=False)
            result = await run_scan(url="test.com/?id=1", category="invalid")
        assert result.overall_status == "error"
        assert result.target == "http://test.com/?id=1"

    @pytest.mark.asyncio
    async def test_scan_all_secure(self) -> None:
        async def mock_get(url: str, **kwargs: object) -> MagicMock:
            resp = MagicMock()
            resp.status_code = 200
            resp.content = b"<html>safe</html>"
            resp.cookies = {}
            return resp

        client = _make_client(mock_get)
        with patch("mytools.web.sqliscan.create_async_client") as mock:
            mock.return_value.__aenter__ = AsyncMock(return_value=client)
            mock.return_value.__aexit__ = AsyncMock(return_value=False)
            result = await run_scan(url="http://test.com/?id=1", category="all")
        assert result.overall_status == "secure"
        assert "Nenhuma SQL injection detectada" in result.issues

    @pytest.mark.asyncio
    async def test_scan_blind_vulnerable(self) -> None:
        async def mock_get(url: str, **kwargs: object) -> MagicMock:
            resp = MagicMock()
            resp.status_code = 200
            if "1=1" in url:
                resp.content = b"<html>" + b"x" * 2000 + b"</html>"
            else:
                resp.content = b"<html>" + b"x" * 100 + b"</html>"
            resp.cookies = {}
            return resp

        client = _make_client(mock_get)
        with patch("mytools.web.sqliscan.create_async_client") as mock:
            mock.return_value.__aenter__ = AsyncMock(return_value=client)
            mock.return_value.__aexit__ = AsyncMock(return_value=False)
            result = await run_scan(url="http://test.com/?id=1", category="blind")
        assert result.overall_status == "vulnerable"
        assert "boolean_blind" in result.vulnerable_techniques

    @pytest.mark.asyncio
    async def test_scan_error_category_ignores_exception(self) -> None:
        client = _make_client(
            AsyncMock(
                return_value=MagicMock(
                    status_code=200, content=b"<html>ok</html>", cookies={}
                )
            )
        )
        with (
            patch("mytools.web.sqliscan.create_async_client") as mock,
            patch(
                "mytools.web.sqliscan._test_error",
                new=AsyncMock(side_effect=RuntimeError("boom")),
            ),
        ):
            mock.return_value.__aenter__ = AsyncMock(return_value=client)
            mock.return_value.__aexit__ = AsyncMock(return_value=False)
            result = await run_scan(url="http://test.com/?id=1", category="error")
        assert result.overall_status == "secure"
        assert result.attempts == []


# ---------------------------------------------------------------------------
# print_results — attempts vulneraveis
# ---------------------------------------------------------------------------


def _vuln_attempt(
    *,
    technique: str,
    db: str = "",
    exploit: str = "",
    tool: str = "",
) -> SQLiAttempt:
    return SQLiAttempt(
        technique=technique,
        category="error",
        injection_point="id",
        url="http://x.com",
        payload="'",
        status_baseline=200,
        status_test=500,
        size_baseline=100,
        size_test=500,
        time_baseline=0.1,
        time_test=0.1,
        db_detected=db,
        content_match=bool(db),
        timing_match=False,
        vulnerable=True,
        details="DB detectado: x",
        error="",
        exploit=exploit,
        tool=tool,
    )


class TestPrintResultsVuln:
    def test_vulnerable_attempts(self, capsys: pytest.CaptureFixture[str]) -> None:
        att1 = _vuln_attempt(
            technique="error", db="mysql", exploit="curl 'x'", tool="curl"
        )
        att2 = _vuln_attempt(technique="error", db="mysql")
        att3 = _vuln_attempt(technique="boolean_blind")
        r = SQLiResult(
            target="http://test.com",
            baseline_status=200,
            baseline_size=100,
            tls=False,
            attempts=[att1, att2, att3],
            vulnerable_techniques=["error", "boolean_blind"],
            blocked_techniques=[],
            issues=[],
            overall_status="vulnerable",
        )
        print_results(r)
        out = capsys.readouterr().out
        assert "VULNERAVEL" in out
        assert "mysql" in out
        assert "boolean_blind" in out


# ---------------------------------------------------------------------------
# run_once
# ---------------------------------------------------------------------------


def _result(overall: str = "secure") -> SQLiResult:
    return SQLiResult(
        target="http://test.com",
        baseline_status=200 if overall != "error" else 0,
        baseline_size=100,
        tls=False,
        attempts=[],
        vulnerable_techniques=[],
        blocked_techniques=[],
        issues=[],
        overall_status=overall,
    )


class TestRunOnce:
    def test_returns_zero_secure(self, capsys: pytest.CaptureFixture[str]) -> None:
        args = build_parser().parse_args(["http://test.com"])
        with patch(
            "mytools.web.sqliscan.run_scan", new=AsyncMock(return_value=_result())
        ):
            assert run_once(args) == 0
        assert "SECURE" in capsys.readouterr().out

    def test_json_output(self, capsys: pytest.CaptureFixture[str]) -> None:
        args = build_parser().parse_args(["--json", "http://test.com"])
        with patch(
            "mytools.web.sqliscan.run_scan", new=AsyncMock(return_value=_result())
        ):
            assert run_once(args) == 0
        decoder = json.JSONDecoder()
        data, _ = decoder.raw_decode(capsys.readouterr().out)
        assert data["target"] == "http://test.com"

    def test_output_file(self, tmp_path) -> None:
        out_file = tmp_path / "out.json"
        args = build_parser().parse_args(["-o", str(out_file), "http://test.com"])
        with patch(
            "mytools.web.sqliscan.run_scan", new=AsyncMock(return_value=_result())
        ):
            assert run_once(args) == 0
        assert out_file.exists()

    def test_returns_one_on_error(self) -> None:
        args = build_parser().parse_args(["http://test.com"])
        with patch(
            "mytools.web.sqliscan.run_scan",
            new=AsyncMock(return_value=_result("error")),
        ):
            assert run_once(args) == 1


# ---------------------------------------------------------------------------
# main guard
# ---------------------------------------------------------------------------


class TestMainGuard:
    def test_guard_runs(self) -> None:
        with (
            patch("mytools.core.utils.run_main_loop", side_effect=SystemExit(0)),
            pytest.raises(SystemExit),
        ):
            runpy.run_module("mytools.web.sqliscan", run_name="__main__")
