import argparse
import json
import runpy
from unittest.mock import AsyncMock, patch

import httpx
import pytest
import respx

from mytools.osint.ipasninfo import (
    BANNER_ART,
    DEFAULT_TIMEOUT,
    IpAsnInfo,
    _load_ips_from_args,
    _parse_ipapi,
    _parse_ipapi_batch,
    _parse_ipwhois,
    _print_results,
    _query_batch,
    _query_single,
    build_parser,
    lookup_ip_asn,
    main,
    run_once,
)


class TestIpAsnInfo:
    def test_frozen(self):
        r = IpAsnInfo(ip="8.8.8.8", asn="AS15169")
        with pytest.raises(AttributeError):
            r.asn = "AS0000"  # type: ignore[reportAttributeAccessIssue]

    def test_defaults(self):
        r = IpAsnInfo(ip="1.1.1.1")
        assert r.asn == ""
        assert r.org == ""
        assert r.isp == ""
        assert r.country == ""
        assert r.country_code == ""
        assert r.city == ""
        assert r.is_hosting is False
        assert r.is_proxy is False
        assert r.source == ""

    def test_all_fields(self):
        r = IpAsnInfo(
            ip="8.8.8.8",
            asn="AS15169",
            org="Google LLC",
            isp="Google LLC",
            country="United States",
            country_code="US",
            city="Mountain View",
            is_hosting=True,
            is_proxy=False,
            source="ipwhois",
        )
        assert r.asn == "AS15169"
        assert r.is_hosting is True


class TestParseIpwhois:
    def test_extracts_fields(self):
        data = {
            "ip": "8.8.8.8",
            "success": True,
            "country": "United States",
            "country_code": "US",
            "city": "Mountain View",
            "connection": {
                "asn": 15169,
                "org": "Google LLC",
                "isp": "Google LLC",
            },
        }
        result = _parse_ipwhois(json.dumps(data).encode())
        assert result is not None
        assert result.ip == "8.8.8.8"
        assert result.asn == "AS15169"
        assert result.org == "Google LLC"
        assert result.isp == "Google LLC"
        assert result.country == "United States"
        assert result.city == "Mountain View"
        assert result.source == "ipwhois"

    def test_failure_returns_none(self):
        data = {"ip": "1.2.3.4", "success": False}
        result = _parse_ipwhois(json.dumps(data).encode())
        assert result is None

    def test_invalid_json(self):
        result = _parse_ipwhois(b"not json")
        assert result is None

    def test_missing_connection(self):
        data = {"ip": "8.8.8.8", "success": True}
        result = _parse_ipwhois(json.dumps(data).encode())
        assert result is not None
        assert result.asn == ""

    def test_asn_string(self):
        data = {
            "ip": "8.8.8.8",
            "success": True,
            "connection": {"asn": "AS15169"},
        }
        result = _parse_ipwhois(json.dumps(data).encode())
        assert result is not None
        assert result.asn == "AS15169"


class TestParseIpapi:
    def test_extracts_fields(self):
        data = {
            "query": "8.8.8.8",
            "status": "success",
            "as": "AS15169 Google LLC",
            "org": "Google LLC",
            "isp": "Google LLC",
            "country": "United States",
            "countryCode": "US",
            "city": "Mountain View",
            "hosting": True,
            "proxy": False,
        }
        result = _parse_ipapi(json.dumps(data).encode())
        assert result is not None
        assert result.ip == "8.8.8.8"
        assert result.asn == "AS15169"
        assert result.is_hosting is True
        assert result.source == "ipapi"

    def test_failure_returns_none(self):
        data = {"query": "1.2.3.4", "status": "fail"}
        result = _parse_ipapi(json.dumps(data).encode())
        assert result is None

    def test_invalid_json(self):
        result = _parse_ipapi(b"bad")
        assert result is None


class TestParseIpapiBatch:
    def test_extracts_multiple(self):
        items = [
            {
                "query": "8.8.8.8",
                "status": "success",
                "as": "AS15169 Google LLC",
                "isp": "Google LLC",
                "country": "United States",
                "countryCode": "US",
            },
            {
                "query": "1.1.1.1",
                "status": "success",
                "as": "AS13335 Cloudflare Inc.",
                "isp": "Cloudflare Inc.",
                "country": "Australia",
                "countryCode": "AU",
            },
        ]
        result = _parse_ipapi_batch(json.dumps(items).encode())
        assert len(result) == 2
        assert result[0].ip == "8.8.8.8"
        assert result[1].ip == "1.1.1.1"

    def test_filters_failed(self):
        items = [
            {"query": "8.8.8.8", "status": "success", "as": "AS15169"},
            {"query": "9.9.9.9", "status": "fail"},
        ]
        result = _parse_ipapi_batch(json.dumps(items).encode())
        assert len(result) == 1

    def test_empty_array(self):
        result = _parse_ipapi_batch(json.dumps([]).encode())
        assert result == []

    def test_invalid_json(self):
        result = _parse_ipapi_batch(b"bad")
        assert result == []

    def test_non_list(self):
        result = _parse_ipapi_batch(json.dumps({"status": "success"}).encode())
        assert result == []


class TestLookupIpAsn:
    def test_empty_returns_empty(self):
        result = lookup_ip_asn([])
        assert result == []

    def test_single_ip_calls_async(self):
        mock_result = IpAsnInfo(ip="8.8.8.8", asn="AS15169", source="ipwhois")
        with patch(
            "mytools.osint.ipasninfo._query_single",
            new_callable=AsyncMock,
            return_value=mock_result,
        ):
            result = lookup_ip_asn(["8.8.8.8"])
            assert len(result) == 1
            assert result[0].ip == "8.8.8.8"


@pytest.mark.smoke
class TestBuildParser:
    def test_has_ips(self):
        parser = build_parser()
        args = parser.parse_args(["8.8.8.8"])
        assert args.ips == ["8.8.8.8"]

    def test_has_multiple_ips(self):
        parser = build_parser()
        args = parser.parse_args(["8.8.8.8", "1.1.1.1"])
        assert args.ips == ["8.8.8.8", "1.1.1.1"]

    def test_has_file(self):
        parser = build_parser()
        args = parser.parse_args(["-f", "ips.txt"])
        assert args.ip_file == "ips.txt"

    def test_has_batch_flag(self):
        parser = build_parser()
        args = parser.parse_args(["8.8.8.8", "--batch"])
        assert args.batch is True

    def test_ips_optional(self):
        parser = build_parser()
        args = parser.parse_args([])
        assert args.ips == []

    def test_timeout_default(self):
        parser = build_parser()
        args = parser.parse_args(["8.8.8.8"])
        assert args.timeout == DEFAULT_TIMEOUT


class TestRunOnce:
    def _make_args(self, **overrides):
        parser = build_parser()
        defaults = vars(parser.parse_args(["8.8.8.8"]))
        defaults.update(overrides)
        return argparse.Namespace(**defaults)

    def test_dry_run(self, capsys):
        args = self._make_args(dry_run=True)
        result = run_once(args)
        assert result == 0
        output = capsys.readouterr().out
        assert "DRY-RUN" in output

    def test_no_ips_returns_1(self, capsys):
        parser = build_parser()
        args = parser.parse_args([])
        # Force no file either
        args.ip_file = None
        result = run_once(args)
        assert result == 1

    def test_calls_lookup(self):
        args = self._make_args()
        with patch(
            "mytools.osint.ipasninfo.lookup_ip_asn", return_value=[]
        ) as mock_lookup:
            with patch("mytools.osint.ipasninfo.init_scanner"):
                run_once(args)
            mock_lookup.assert_called_once()


class TestBannerArt:
    def test_not_empty(self):
        assert len(BANNER_ART) > 0


# ── _query_single ────────────────────────────────────────────────────────────


class TestQuerySingle:
    @pytest.mark.asyncio
    @respx.mock
    async def test_ipwhois_success(self):
        respx.get(url__startswith="https://ipwho.is/").mock(
            return_value=httpx.Response(
                200,
                json={
                    "ip": "8.8.8.8",
                    "success": True,
                    "connection": {"asn": 15169, "org": "Google LLC", "isp": "Google"},
                },
            ),
        )
        result = await _query_single("8.8.8.8", 5.0)
        assert result is not None
        assert result.asn == "AS15169"
        assert result.source == "ipwhois"

    @pytest.mark.asyncio
    @respx.mock
    async def test_ipwhois_error_fallback(self):
        respx.get(url__startswith="https://ipwho.is/").mock(
            side_effect=httpx.ConnectError("refused"),
        )
        respx.get(url__startswith="http://ip-api.com/json/").mock(
            return_value=httpx.Response(
                200,
                json={
                    "query": "8.8.8.8",
                    "status": "success",
                    "as": "AS15169 Google LLC",
                },
            ),
        )
        result = await _query_single("8.8.8.8", 5.0)
        assert result is not None
        assert result.source == "ipapi"
        assert result.asn == "AS15169"

    @pytest.mark.asyncio
    @respx.mock
    async def test_ipwhois_non_200_fallback(self):
        respx.get(url__startswith="https://ipwho.is/").mock(
            return_value=httpx.Response(500),
        )
        respx.get(url__startswith="http://ip-api.com/json/").mock(
            return_value=httpx.Response(
                200, json={"query": "8.8.8.8", "status": "success"}
            ),
        )
        result = await _query_single("8.8.8.8", 5.0)
        assert result is not None
        assert result.source == "ipapi"

    @pytest.mark.asyncio
    @respx.mock
    async def test_ipwhois_invalid_json_fallback(self):
        respx.get(url__startswith="https://ipwho.is/").mock(
            return_value=httpx.Response(200, text="<not json>"),
        )
        respx.get(url__startswith="http://ip-api.com/json/").mock(
            return_value=httpx.Response(
                200, json={"query": "8.8.8.8", "status": "success"}
            ),
        )
        result = await _query_single("8.8.8.8", 5.0)
        assert result is not None
        assert result.source == "ipapi"

    @pytest.mark.asyncio
    @respx.mock
    async def test_both_fail(self):
        respx.get(url__startswith="https://ipwho.is/").mock(
            side_effect=httpx.ConnectError("refused"),
        )
        respx.get(url__startswith="http://ip-api.com/json/").mock(
            side_effect=httpx.ConnectError("refused"),
        )
        result = await _query_single("8.8.8.8", 5.0)
        assert result is None

    @pytest.mark.asyncio
    @respx.mock
    async def test_ipapi_non_200(self):
        respx.get(url__startswith="https://ipwho.is/").mock(
            side_effect=httpx.ConnectError("refused"),
        )
        respx.get(url__startswith="http://ip-api.com/json/").mock(
            return_value=httpx.Response(500),
        )
        result = await _query_single("8.8.8.8", 5.0)
        assert result is None


# ── _query_batch ─────────────────────────────────────────────────────────────


class TestQueryBatch:
    @pytest.mark.asyncio
    @respx.mock
    async def test_empty(self):
        result = await _query_batch([], 5.0)
        assert result == []

    @pytest.mark.asyncio
    @respx.mock
    async def test_success(self):
        respx.post(url__startswith="http://ip-api.com/batch").mock(
            return_value=httpx.Response(
                200,
                json=[{"query": "8.8.8.8", "status": "success", "as": "AS15169"}],
            ),
        )
        result = await _query_batch(["8.8.8.8", "1.1.1.1"], 5.0)
        assert len(result) == 1
        assert result[0].asn == "AS15169"

    @pytest.mark.asyncio
    @respx.mock
    async def test_request_error(self):
        respx.post(url__startswith="http://ip-api.com/batch").mock(
            side_effect=httpx.ConnectError("refused"),
        )
        result = await _query_batch(["8.8.8.8"], 5.0)
        assert result == []

    @pytest.mark.asyncio
    @respx.mock
    async def test_non_200(self):
        respx.post(url__startswith="http://ip-api.com/batch").mock(
            return_value=httpx.Response(500),
        )
        result = await _query_batch(["8.8.8.8"], 5.0)
        assert result == []

    @pytest.mark.asyncio
    @respx.mock
    async def test_rate_limit_sleep(self):
        respx.post(url__startswith="http://ip-api.com/batch").mock(
            return_value=httpx.Response(
                200,
                json=[
                    {"query": f"1.2.3.{i % 255}", "status": "success"} for i in range(2)
                ],
            ),
        )
        ips = [f"10.0.0.{i % 250}" for i in range(105)]
        result = await _query_batch(ips, 5.0)
        assert len(result) == 4


# ── lookup_ip_asn batch path ─────────────────────────────────────────────────


class TestLookupBatch:
    def test_batch_returns(self):
        info = IpAsnInfo(ip="8.8.8.8", asn="AS15169", source="ipapi")
        with patch(
            "mytools.osint.ipasninfo._query_batch",
            new_callable=AsyncMock,
            return_value=[info],
        ):
            result = lookup_ip_asn(
                ["8.8.8.8", "1.1.1.1", "1.1.1.2", "1.1.1.3", "1.1.1.4"]
            )
            assert len(result) == 1
            assert result[0].ip == "8.8.8.8"


# ── _print_results / _load_ips_from_args / run_once output / main ────────────


class TestPrintResultsPriv:
    def test_empty(self, capsys):
        _print_results([])
        out = capsys.readouterr().out
        assert "Nenhuma informacao ASN" in out

    def test_with_data(self, capsys):
        results = [
            IpAsnInfo(
                ip="8.8.8.8",
                asn="AS15169",
                org="Google LLC",
                isp="Google LLC",
                country="United States",
                country_code="US",
                city="Mountain View",
                is_hosting=True,
                exploit="https://bgp.he.net/ip/8.8.8.8",
                tool="bgp.he.net",
            ),
        ]
        _print_results(results)
        out = capsys.readouterr().out
        assert "8.8.8.8" in out
        assert "AS15169" in out


class TestLoadIpsFromArgs:
    def test_from_file(self, tmp_path):
        ip_file = tmp_path / "ips.txt"
        ip_file.write_text("8.8.8.8\n#comment\n1.1.1.1\n\n", encoding="utf-8")
        args = argparse.Namespace(ips=[], ip_file=str(ip_file))
        assert _load_ips_from_args(args) == ["8.8.8.8", "1.1.1.1"]

    def test_from_args_and_file(self, tmp_path):
        ip_file = tmp_path / "ips.txt"
        ip_file.write_text("1.1.1.1\n", encoding="utf-8")
        args = argparse.Namespace(ips=["8.8.8.8"], ip_file=str(ip_file))
        assert _load_ips_from_args(args) == ["8.8.8.8", "1.1.1.1"]

    def test_file_not_found(self, capsys):
        args = argparse.Namespace(ips=[], ip_file="definitely_missing_12345.txt")
        assert _load_ips_from_args(args) == []


class TestRunOnceOutput:
    def test_with_output(self, tmp_path):
        parser = build_parser()
        args = parser.parse_args(["8.8.8.8", "-o", str(tmp_path / "out.json")])
        with (
            patch("mytools.osint.ipasninfo.init_scanner"),
            patch(
                "mytools.osint.ipasninfo.lookup_ip_asn",
                return_value=[IpAsnInfo(ip="8.8.8.8", asn="AS15169")],
            ),
            patch("mytools.osint.ipasninfo.write_output") as mock_write,
        ):
            result = run_once(args)
        assert result == 0
        mock_write.assert_called_once()


class TestMain:
    def test_main_with_ips(self):
        with (
            patch("sys.argv", ["mytools-ipasn", "8.8.8.8"]),
            patch("mytools.osint.ipasninfo.run_once", return_value=0) as mock_run,
        ):
            assert main() == 0
        mock_run.assert_called_once()

    def test_main_interactive(self):
        with (
            patch("sys.argv", ["mytools-ipasn"]),
            patch("mytools.osint.ipasninfo.run_main_loop", return_value=0) as mock_loop,
        ):
            assert main() == 0
        mock_loop.assert_called_once()

    def test_main_guard(self):
        with (
            patch("mytools.core.utils.run_main_loop", side_effect=SystemExit(0)),
            patch("sys.argv", ["mytools-ipasn", "8.8.8.8"]),
            pytest.raises(SystemExit),
        ):
            runpy.run_module("mytools.osint.ipasninfo", run_name="__main__")
