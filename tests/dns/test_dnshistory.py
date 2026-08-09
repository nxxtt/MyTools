import argparse
import json
import runpy
from unittest.mock import AsyncMock, patch

import httpx
import pytest
import respx

from mytools.dns.dnshistory import (
    BANNER_ART,
    DEFAULT_TIMEOUT,
    RECORD_TYPES,
    DnsHistoryRecord,
    _parse_dnslytics,
    _parse_securitytrails,
    _parse_viewdns,
    _query_all_sources,
    _query_source,
    build_parser,
    run_history,
    run_once,
)


class TestDnsHistoryRecord:
    def test_frozen(self):
        r = DnsHistoryRecord(record_type="a", value="1.2.3.4", source="dnslytics")
        with pytest.raises(AttributeError):
            r.value = "5.6.7.8"  # type: ignore[reportAttributeAccessIssue]

    def test_defaults(self):
        r = DnsHistoryRecord(record_type="a", value="1.2.3.4")
        assert r.first_seen is None
        assert r.last_seen is None
        assert r.location is None
        assert r.owner is None
        assert r.source == ""

    def test_all_fields(self):
        r = DnsHistoryRecord(
            record_type="mx",
            value="mail.example.com",
            first_seen="2020-01-01",
            last_seen="2024-12-31",
            location="US",
            owner="Cloudflare",
            source="viewdns",
        )
        assert r.first_seen == "2020-01-01"
        assert r.last_seen == "2024-12-31"


class TestParseDnslytics:
    def test_extracts_ipv4(self):
        data = {
            "status": "succeed",
            "data": {
                "ipv4": [{"ip": "1.2.3.4", "updatedate": "2023-06-15"}],
            },
        }
        result = _parse_dnslytics(json.dumps(data).encode(), "example.com")
        assert len(result) == 1
        assert result[0].record_type == "a"
        assert result[0].value == "1.2.3.4"
        assert result[0].last_seen == "2023-06-15"

    def test_extracts_ipv6(self):
        data = {
            "status": "succeed",
            "data": {
                "ipv6": [{"ip": "2001:db8::1", "updatedate": "2023-01-01"}],
            },
        }
        result = _parse_dnslytics(json.dumps(data).encode(), "example.com")
        assert len(result) == 1
        assert result[0].record_type == "aaaa"

    def test_extracts_ns(self):
        data = {
            "status": "succeed",
            "data": {
                "dns": [{"dns": "ns1.example.com", "updatedate": "2022-05-10"}],
            },
        }
        result = _parse_dnslytics(json.dumps(data).encode(), "example.com")
        assert len(result) == 1
        assert result[0].record_type == "ns"
        assert result[0].value == "ns1.example.com"

    def test_extracts_mx(self):
        data = {
            "status": "succeed",
            "data": {
                "mx": [{"mx": "mx1.example.com", "updatedate": "2023-03-01"}],
            },
        }
        result = _parse_dnslytics(json.dumps(data).encode(), "example.com")
        assert len(result) == 1
        assert result[0].record_type == "mx"

    def test_extracts_spf(self):
        data = {
            "status": "succeed",
            "data": {
                "spf": [
                    {
                        "record": "v=spf1 include:_spf.example.com ~all",
                        "updatedate": "2023-07-01",
                    }
                ],
            },
        }
        result = _parse_dnslytics(json.dumps(data).encode(), "example.com")
        assert len(result) == 1
        assert result[0].record_type == "txt"

    def test_failed_status_returns_empty(self):
        data = {"status": "failed", "data": {}}
        result = _parse_dnslytics(json.dumps(data).encode(), "example.com")
        assert result == []

    def test_invalid_json_returns_empty(self):
        result = _parse_dnslytics(b"not json", "example.com")
        assert result == []

    def test_empty_data_returns_empty(self):
        data = {"status": "succeed", "data": {}}
        result = _parse_dnslytics(json.dumps(data).encode(), "example.com")
        assert result == []


class TestParseSecuritytrails:
    def test_extracts_records(self):
        data = {
            "type": "a/ipv4",
            "records": [
                {
                    "first_seen": "2020-01-01",
                    "last_seen": "2024-06-01",
                    "organizations": ["Amazon"],
                    "values": [{"ip": "52.1.2.3"}],
                },
            ],
        }
        result = _parse_securitytrails(json.dumps(data).encode(), "example.com")
        assert len(result) == 1
        assert result[0].record_type == "a"
        assert result[0].value == "52.1.2.3"
        assert result[0].first_seen == "2020-01-01"
        assert result[0].owner == "Amazon"

    def test_multiple_values(self):
        data = {
            "type": "ns",
            "records": [
                {
                    "first_seen": "2021-01-01",
                    "last_seen": None,
                    "organizations": [],
                    "values": [
                        {"host": "ns1.example.com"},
                        {"host": "ns2.example.com"},
                    ],
                },
            ],
        }
        result = _parse_securitytrails(json.dumps(data).encode(), "example.com")
        assert len(result) == 2
        assert result[0].value == "ns1.example.com"
        assert result[1].value == "ns2.example.com"

    def test_invalid_json_returns_empty(self):
        result = _parse_securitytrails(b"bad", "example.com")
        assert result == []

    def test_empty_records(self):
        data = {"type": "a/ipv4", "records": []}
        result = _parse_securitytrails(json.dumps(data).encode(), "example.com")
        assert result == []


class TestParseViewdns:
    def test_extracts_records(self):
        data = {
            "response": {
                "records": [
                    {
                        "ip": "104.18.42.197",
                        "lastseen": "2024-09-20",
                        "owner": "Cloudflare",
                        "location": "US",
                    },
                ],
            },
        }
        result = _parse_viewdns(json.dumps(data).encode(), "example.com")
        assert len(result) == 1
        assert result[0].record_type == "a"
        assert result[0].value == "104.18.42.197"
        assert result[0].owner == "Cloudflare"
        assert result[0].location == "US"

    def test_invalid_json_returns_empty(self):
        result = _parse_viewdns(b"bad", "example.com")
        assert result == []

    def test_empty_records(self):
        data = {"response": {"records": []}}
        result = _parse_viewdns(json.dumps(data).encode(), "example.com")
        assert result == []


@pytest.mark.smoke
class TestBuildParser:
    def test_returns_parser(self):
        parser = build_parser()
        assert isinstance(parser, argparse.ArgumentParser)

    def test_has_domain_positional(self):
        parser = build_parser()
        args = parser.parse_args(["example.com"])
        assert args.domain == "example.com"

    def test_has_source_flag(self):
        parser = build_parser()
        args = parser.parse_args(["example.com", "--source", "dnslytics"])
        assert args.source == ["dnslytics"]

    def test_has_source_multiple(self):
        parser = build_parser()
        args = parser.parse_args(
            ["example.com", "--source", "dnslytics", "--source", "securitytrails"]
        )
        assert args.source == ["dnslytics", "securitytrails"]

    def test_has_st_api_key(self):
        parser = build_parser()
        args = parser.parse_args(["example.com", "--st-api-key", "abc123"])
        assert args.st_api_key == "abc123"

    def test_has_viewdns_api_key(self):
        parser = build_parser()
        args = parser.parse_args(["example.com", "--viewdns-api-key", "xyz789"])
        assert args.viewdns_key == "xyz789"

    def test_has_record_types(self):
        parser = build_parser()
        args = parser.parse_args(["example.com", "--record-types", "a,mx,ns"])
        assert args.record_types == "a,mx,ns"

    def test_default_timeout(self):
        parser = build_parser()
        args = parser.parse_args(["example.com"])
        assert args.timeout == DEFAULT_TIMEOUT


class TestQuerySource:
    """Testes da funcao _query_source com respx."""

    @pytest.mark.asyncio
    @respx.mock
    async def test_dnslytics_success(self):
        respx.get("https://api.dnslytics.net/v1/hostinghistory/example.com").mock(
            return_value=httpx.Response(
                200,
                json={
                    "status": "succeed",
                    "data": {"ipv4": [{"ip": "1.2.3.4"}]},
                },
            )
        )
        records = await _query_source("dnslytics", "example.com", None, ["a"], 5.0)
        assert len(records) == 1
        assert records[0].source == "dnslytics"

    @pytest.mark.asyncio
    @respx.mock
    async def test_dnslytics_with_api_key(self):
        respx.get(
            "https://api.dnslytics.net/v1/hostinghistory/example.com?apikey=KEY123"
        ).mock(return_value=httpx.Response(200, json={"status": "succeed", "data": {}}))
        records = await _query_source("dnslytics", "example.com", "KEY123", ["a"], 5.0)
        assert records == []

    @pytest.mark.asyncio
    @respx.mock
    async def test_dnslytics_non_200(self):
        respx.get("https://api.dnslytics.net/v1/hostinghistory/example.com").mock(
            return_value=httpx.Response(500)
        )
        records = await _query_source("dnslytics", "example.com", None, ["a"], 5.0)
        assert records == []

    @pytest.mark.asyncio
    @respx.mock
    async def test_securitytrails_without_key(self):
        records = await _query_source("securitytrails", "example.com", None, ["a"], 5.0)
        assert records == []

    @pytest.mark.asyncio
    @respx.mock
    async def test_securitytrails_success(self):
        for rtype in ("a", "mx"):
            respx.get(
                f"https://api.securitytrails.com/v1/history/example.com/dns/{rtype}"
            ).mock(
                return_value=httpx.Response(
                    200,
                    json={
                        "type": f"{rtype}/ipv4",
                        "records": [{"values": [{"ip": "1.2.3.4"}]}],
                    },
                )
            )
        records = await _query_source(
            "securitytrails", "example.com", "KEY", ["a", "mx"], 5.0
        )
        assert len(records) == 2

    @pytest.mark.asyncio
    @respx.mock
    async def test_securitytrails_rate_limited(self):
        respx.get("https://api.securitytrails.com/v1/history/example.com/dns/a").mock(
            return_value=httpx.Response(429)
        )
        records = await _query_source(
            "securitytrails", "example.com", "KEY", ["a", "mx"], 5.0
        )
        assert records == []

    @pytest.mark.asyncio
    @respx.mock
    async def test_securitytrails_other_error(self):
        for rtype in ("a", "mx"):
            respx.get(
                f"https://api.securitytrails.com/v1/history/example.com/dns/{rtype}"
            ).mock(return_value=httpx.Response(403))
        records = await _query_source(
            "securitytrails", "example.com", "KEY", ["a", "mx"], 5.0
        )
        assert records == []

    @pytest.mark.asyncio
    @respx.mock
    async def test_viewdns_without_key(self):
        records = await _query_source("viewdns", "example.com", None, ["a"], 5.0)
        assert records == []

    @pytest.mark.asyncio
    @respx.mock
    async def test_viewdns_success(self):
        respx.get(
            "https://api.viewdns.info/iphistory/?domain=example.com&apikey=KEY&output=json"
        ).mock(
            return_value=httpx.Response(
                200,
                json={
                    "response": {"records": [{"ip": "1.2.3.4", "owner": "Cloudflare"}]}
                },
            )
        )
        records = await _query_source("viewdns", "example.com", "KEY", ["a"], 5.0)
        assert len(records) == 1
        assert records[0].owner == "Cloudflare"

    @pytest.mark.asyncio
    @respx.mock
    async def test_viewdns_non_200(self):
        respx.get(
            "https://api.viewdns.info/iphistory/?domain=example.com&apikey=KEY&output=json"
        ).mock(return_value=httpx.Response(500))
        records = await _query_source("viewdns", "example.com", "KEY", ["a"], 5.0)
        assert records == []

    @pytest.mark.asyncio
    @respx.mock
    async def test_unknown_source(self):
        records = await _query_source("unknown", "example.com", None, ["a"], 5.0)
        assert records == []

    @pytest.mark.asyncio
    @respx.mock
    async def test_fetch_error_returns_empty(self):
        respx.get("https://api.dnslytics.net/v1/hostinghistory/example.com").mock(
            side_effect=httpx.ConnectError("boom")
        )
        records = await _query_source("dnslytics", "example.com", None, ["a"], 5.0)
        assert records == []


class TestQueryAllSources:
    """Testes da funcao _query_all_sources."""

    @pytest.mark.asyncio
    async def test_consolidates_and_dedupes(self):
        rec = DnsHistoryRecord(
            record_type="a", value="1.2.3.4", last_seen="2024-01-01", source="x"
        )
        with patch(
            "mytools.dns.dnshistory._query_source",
            new_callable=AsyncMock,
            side_effect=[[rec], [rec]],
        ) as mock_query:
            records = await _query_all_sources(
                "example.com",
                ["dnslytics", "securitytrails"],
                {"dnslytics": None, "securitytrails": None},
                ["a"],
                5.0,
            )
        assert mock_query.await_count == 2
        assert len(records) == 1

    @pytest.mark.asyncio
    async def test_skips_non_list_results(self):
        rec = DnsHistoryRecord(
            record_type="a", value="1.2.3.4", last_seen="2024-01-01", source="x"
        )
        with patch(
            "mytools.dns.dnshistory._query_source",
            new_callable=AsyncMock,
            side_effect=[[rec], None],
        ):
            records = await _query_all_sources(
                "example.com",
                ["dnslytics", "securitytrails"],
                {"dnslytics": None, "securitytrails": None},
                ["a"],
                5.0,
            )
        assert len(records) == 1

    @pytest.mark.asyncio
    async def test_empty_sources(self):
        records = await _query_all_sources("example.com", [], {}, ["a"], 5.0)
        assert records == []


class TestRunOnce:
    def test_warns_for_missing_api_keys(self, caplog):
        args = argparse.Namespace(
            domain="example.com",
            source=["securitytrails"],
            dnslytics_key=None,
            st_api_key=None,
            viewdns_key=None,
            record_types=None,
            timeout=5.0,
            dry_run=False,
            output=None,
            verbose=False,
            quiet=False,
            color=None,
            log_file=None,
        )
        with (
            patch("mytools.dns.dnshistory.run_history", return_value=[]),
            caplog.at_level("WARNING", logger="mytools.dnshistory"),
        ):
            result = run_once(args)
        assert result == 0
        assert any("requer API key" in r.message for r in caplog.records)

    def test_returns_zero(self, capsys):
        args = argparse.Namespace(
            domain="example.com",
            source=None,
            dnslytics_key=None,
            st_api_key=None,
            viewdns_key=None,
            record_types=None,
            timeout=5.0,
            dry_run=False,
            output=None,
            verbose=False,
            quiet=False,
            color=None,
            log_file=None,
        )
        with patch("mytools.dns.dnshistory.run_history", return_value=[]):
            result = run_once(args)
        assert result == 0

    def test_dry_run(self, caplog):
        args = argparse.Namespace(
            domain="example.com",
            source=["dnslytics"],
            dnslytics_key=None,
            st_api_key=None,
            viewdns_key=None,
            record_types=None,
            timeout=5.0,
            dry_run=True,
            output=None,
            verbose=False,
            quiet=False,
            color=None,
            log_file=None,
        )
        with caplog.at_level("WARNING", logger="mytools.dnshistory"):
            result = run_once(args)
        assert result == 0
        assert any("Nenhuma consulta" in r.message for r in caplog.records)

    def test_saves_output(self, capsys, tmp_path):
        out_file = str(tmp_path / "history.json")
        args = argparse.Namespace(
            domain="example.com",
            source=None,
            dnslytics_key=None,
            st_api_key=None,
            viewdns_key=None,
            record_types=None,
            timeout=5.0,
            dry_run=False,
            output=out_file,
            verbose=False,
            quiet=False,
            color=None,
            log_file=None,
        )
        with patch(
            "mytools.dns.dnshistory.run_history",
            return_value=[
                DnsHistoryRecord(record_type="a", value="1.2.3.4", source="test"),
            ],
        ):
            result = run_once(args)
        assert result == 0

    def test_with_records_prints_table(self, capsys):
        args = argparse.Namespace(
            domain="example.com",
            source=None,
            dnslytics_key=None,
            st_api_key=None,
            viewdns_key=None,
            record_types=None,
            timeout=5.0,
            dry_run=False,
            output=None,
            verbose=False,
            quiet=False,
            color=None,
            log_file=None,
        )
        records = [
            DnsHistoryRecord(
                record_type="a",
                value="1.2.3.4",
                last_seen="2024-01-01",
                source="dnslytics",
            ),
            DnsHistoryRecord(
                record_type="ns", value="ns1.example.com", source="dnslytics"
            ),
        ]
        with patch("mytools.dns.dnshistory.run_history", return_value=records):
            result = run_once(args)
        assert result == 0
        captured = capsys.readouterr()
        assert "1.2.3.4" in captured.out
        assert "ns1.example.com" in captured.out


class TestRunHistory:
    def test_empty_sources_returns_empty(self):
        result = run_history("example.com", sources=[])
        assert result == []

    @patch("mytools.dns.dnshistory._query_all_sources", new_callable=AsyncMock)
    def test_calls_with_correct_sources(self, mock_async):
        mock_async.return_value = [
            DnsHistoryRecord(record_type="a", value="1.2.3.4", source="test"),
        ]
        result = run_history("example.com", sources=["dnslytics"])
        assert len(result) == 1
        assert result[0].value == "1.2.3.4"


class TestConstants:
    def test_banner_not_empty(self):
        assert len(BANNER_ART) > 0

    def test_record_types(self):
        assert "a" in RECORD_TYPES
        assert "mx" in RECORD_TYPES
        assert "ns" in RECORD_TYPES

    def test_default_timeout_positive(self):
        assert DEFAULT_TIMEOUT > 0


class TestMain:
    def test_no_domain_shells_interactive(self):
        with patch("mytools.dns.dnshistory.run_main_loop", return_value=0) as mock_loop:
            from mytools.dns.dnshistory import main

            with patch("sys.argv", ["mytools-dnshistory"]):
                result = main()
            assert result == 0
            mock_loop.assert_called_once()

    def test_valid_domain_calls_run_once(self):
        with patch("mytools.dns.dnshistory.run_main_loop"):
            with patch("mytools.dns.dnshistory.run_once", return_value=0) as mock_run:
                from mytools.dns.dnshistory import main

                with patch("sys.argv", ["mytools-dnshistory", "example.com"]):
                    result = main()
            assert result == 0
            mock_run.assert_called_once()

    def test_main_guard(self):
        with (
            patch("mytools.core.utils.run_main_loop", side_effect=SystemExit(0)),
            patch("sys.argv", ["mytools-dnshistory"]),
            pytest.raises(SystemExit) as exc_info,
        ):
            runpy.run_module("mytools.dns.dnshistory", run_name="__main__")
        assert exc_info.value.code == 0
