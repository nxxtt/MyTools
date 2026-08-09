import argparse
import json
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
import respx

from mytools.whois.whoishistory import (
    BANNER_ART,
    DEFAULT_TIMEOUT,
    WhoisHistoryRecord,
    _parse_securitytrails,
    _parse_whoisxml,
    build_parser,
    main,
    run_history,
    run_once,
)


class TestWhoisHistoryRecord:
    def test_frozen(self):
        r = WhoisHistoryRecord(domain="example.com", date="2024-01-01")
        with pytest.raises(AttributeError):
            r.date = "2025-01-01"  # type: ignore[reportAttributeAccessIssue]

    def test_defaults(self):
        r = WhoisHistoryRecord(domain="example.com", date="2024-01-01")
        assert r.registrar == ""
        assert r.registrant_name == ""
        assert r.registrant_org == ""
        assert r.registrant_country == ""
        assert r.name_servers == ""
        assert r.status == ""
        assert r.created_date == ""
        assert r.expires_date == ""
        assert r.updated_date == ""
        assert r.source == ""

    def test_all_fields(self):
        r = WhoisHistoryRecord(
            domain="example.com",
            date="2024-06-15",
            registrar="GoDaddy",
            registrant_name="John Doe",
            registrant_org="Acme Corp",
            registrant_country="US",
            name_servers="ns1.example.com, ns2.example.com",
            status="clientDeleteProhibited",
            created_date="2010-01-01",
            expires_date="2025-12-31",
            updated_date="2024-01-15",
            source="whoisxml",
        )
        assert r.registrar == "GoDaddy"
        assert r.registrant_country == "US"


class TestParseSecurityTrails:
    def test_extracts_record(self):
        data = {
            "result": {
                "items": [
                    {
                        "ended": 1512131429698,
                        "nameServers": ["NS1.EXAMPLE.COM", "NS2.EXAMPLE.COM"],
                        "contact": [
                            {
                                "name": "John Doe",
                                "organization": "Acme Corp",
                                "country": "US",
                                "type": "registrant",
                            }
                        ],
                        "createdDate": 1193405489687,
                        "expiresDate": 1666791089687,
                    }
                ]
            }
        }
        result = _parse_securitytrails(json.dumps(data).encode(), "example.com")
        assert len(result) == 1
        r = result[0]
        assert r.domain == "example.com"
        assert r.registrant_name == "John Doe"
        assert r.registrant_org == "Acme Corp"
        assert r.registrant_country == "US"
        assert "NS1.EXAMPLE.COM" in r.name_servers

    def test_empty_items(self):
        data = {"result": {"items": []}}
        result = _parse_securitytrails(json.dumps(data).encode(), "example.com")
        assert result == []

    def test_invalid_json(self):
        result = _parse_securitytrails(b"not json", "example.com")
        assert result == []

    def test_missing_fields(self):
        data = {"result": {"items": [{}]}}
        result = _parse_securitytrails(json.dumps(data).encode(), "example.com")
        assert len(result) == 1
        assert result[0].registrant_name == ""

    def test_ended_bad_timestamp(self):
        data = {"result": {"items": [{"ended": -62135596801000}]}}
        result = _parse_securitytrails(json.dumps(data).encode(), "example.com")
        assert result[0].date == "-62135596801000"

    def test_registrar_type_contact(self):
        data = {
            "result": {
                "items": [
                    {
                        "ended": 1512131429698,
                        "contact": [{"type": "registrar", "organization": "GoDaddy"}],
                    }
                ]
            }
        }
        result = _parse_securitytrails(json.dumps(data).encode(), "example.com")
        assert result[0].registrar == "GoDaddy"


class TestParseWhoisxml:
    def test_extracts_record(self):
        data = {
            "records": [
                {
                    "createdDateISO8601": "1997-09-15T00:00:00-07:00",
                    "registrarName": "MarkMonitor Inc.",
                    "registrantContact": {
                        "name": "Domain Administrator",
                        "organization": "Google LLC",
                        "country": "US",
                    },
                    "nameServers": ["NS1.GOOGLE.COM", "NS2.GOOGLE.COM"],
                    "status": ["clientDeleteProhibited"],
                    "expiresDateISO8601": "2025-09-13T21:00:00-07:00",
                }
            ]
        }
        result = _parse_whoisxml(json.dumps(data).encode(), "google.com")
        assert len(result) == 1
        r = result[0]
        assert r.domain == "google.com"
        assert r.registrar == "MarkMonitor Inc."
        assert r.registrant_name == "Domain Administrator"
        assert r.registrant_org == "Google LLC"
        assert r.registrant_country == "US"
        assert "NS1.GOOGLE.COM" in r.name_servers
        assert r.date == "1997-09-15"

    def test_empty_records(self):
        data = {"records": []}
        result = _parse_whoisxml(json.dumps(data).encode(), "example.com")
        assert result == []

    def test_invalid_json(self):
        result = _parse_whoisxml(b"bad", "example.com")
        assert result == []

    def test_no_created_date(self):
        data = {"records": [{"registrarName": "MarkMonitor Inc."}]}
        result = _parse_whoisxml(json.dumps(data).encode(), "example.com")
        assert result[0].date == ""


class TestQuerySource:
    @pytest.mark.asyncio
    async def test_securitytrails_needs_key(self):
        from mytools.whois.whoishistory import _query_source

        result = await _query_source("securitytrails", "example.com", None, 10.0)
        assert result == []

    @pytest.mark.asyncio
    async def test_whoisxml_needs_key(self):
        from mytools.whois.whoishistory import _query_source

        result = await _query_source("whoisxml", "example.com", None, 10.0)
        assert result == []

    @pytest.mark.asyncio
    async def test_unknown_source(self):
        from mytools.whois.whoishistory import _query_source

        result = await _query_source("unknown", "example.com", "key", 10.0)
        assert result == []

    @pytest.mark.asyncio
    async def test_securitytrails_success(self):
        from mytools.whois.whoishistory import _query_source

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = json.dumps(
            {
                "result": {
                    "items": [
                        {
                            "ended": 1512131429698,
                            "nameServers": ["NS1.EXAMPLE.COM"],
                            "contact": [{"name": "Admin", "type": "registrant"}],
                        }
                    ]
                }
            }
        ).encode()
        mock_resp.headers = {}

        with patch("mytools.whois.whoishistory.create_async_client") as mock_client_fn:
            mock_client = MagicMock()
            mock_client.get = MagicMock(return_value=mock_resp)
            mock_client.aclose = AsyncMock()
            mock_client_fn.return_value = mock_client

            with patch(
                "mytools.whois.whoishistory.fetch", new_callable=AsyncMock
            ) as mock_fetch:
                mock_fetch.return_value = (200, {}, mock_resp.content, {})
                result = await _query_source(
                    "securitytrails", "example.com", "test_key", 10.0
                )
                assert len(result) == 1
                assert result[0].domain == "example.com"

    @pytest.mark.asyncio
    async def test_fetch_error_returns_empty(self):
        from mytools.core.utils import FetchError
        from mytools.whois.whoishistory import _query_source

        with patch("mytools.whois.whoishistory.create_async_client") as mock_client_fn:
            mock_client = MagicMock()
            mock_client.aclose = AsyncMock()
            mock_client_fn.return_value = mock_client

            with patch(
                "mytools.whois.whoishistory.fetch", new_callable=AsyncMock
            ) as mock_fetch:
                mock_fetch.side_effect = FetchError("url", 1, Exception("fail"))
                result = await _query_source(
                    "securitytrails", "example.com", "key", 10.0
                )
                assert result == []

    @pytest.mark.asyncio
    async def test_securitytrails_429(self):
        from mytools.whois.whoishistory import _query_source

        with respx.mock:
            respx.route(
                method="GET",
                url="https://api.securitytrails.com/v1/history/example.com/whois",
            ).mock(return_value=httpx.Response(429))
            result = await _query_source("securitytrails", "example.com", "key", 10.0)
            assert result == []

    @pytest.mark.asyncio
    async def test_securitytrails_other_status(self):
        from mytools.whois.whoishistory import _query_source

        with respx.mock:
            respx.route(
                method="GET",
                url="https://api.securitytrails.com/v1/history/example.com/whois",
            ).mock(return_value=httpx.Response(403))
            result = await _query_source("securitytrails", "example.com", "key", 10.0)
            assert result == []

    @pytest.mark.asyncio
    async def test_whoisxml_success(self):
        from mytools.whois.whoishistory import _query_source

        body = json.dumps(
            {
                "records": [
                    {
                        "createdDateISO8601": "1997-09-15T00:00:00-07:00",
                        "registrarName": "MarkMonitor Inc.",
                    }
                ]
            }
        ).encode()
        with respx.mock:
            respx.route(
                method="GET",
                url__startswith="https://whois-history.whoisxmlapi.com/api/v1",
            ).mock(return_value=httpx.Response(200, content=body))
            result = await _query_source("whoisxml", "example.com", "key", 10.0)
            assert len(result) == 1
            assert result[0].registrar == "MarkMonitor Inc."

    @pytest.mark.asyncio
    async def test_whoisxml_other_status(self):
        from mytools.whois.whoishistory import _query_source

        with respx.mock:
            respx.route(
                method="GET",
                url__startswith="https://whois-history.whoisxmlapi.com/api/v1",
            ).mock(return_value=httpx.Response(403))
            result = await _query_source("whoisxml", "example.com", "key", 10.0)
            assert result == []

    @pytest.mark.asyncio
    async def test_query_all_sources_dedup_and_sort(self):
        from mytools.whois.whoishistory import _query_all_sources

        rec1 = WhoisHistoryRecord(
            domain="example.com",
            date="2024-01-01",
            registrar="A",
            source="securitytrails",
        )
        rec_dup = WhoisHistoryRecord(
            domain="example.com",
            date="2024-01-01",
            registrar="A",
            source="securitytrails",
        )
        rec2 = WhoisHistoryRecord(
            domain="example.com",
            date="2023-01-01",
            registrar="B",
            source="whoisxml",
        )
        with patch(
            "mytools.whois.whoishistory._query_source",
            new_callable=AsyncMock,
        ) as mock_q:
            mock_q.side_effect = [[rec1, rec_dup], [rec2], None]
            result = await _query_all_sources(
                "example.com",
                ["securitytrails", "whoisxml", "third"],
                {"securitytrails": "k1", "whoisxml": "k2"},
                10.0,
            )
        assert len(result) == 2
        assert result[0].date == "2023-01-01"


class TestRunHistory:
    def test_returns_empty_with_no_sources(self):
        result = run_history("example.com", sources=[])
        assert result == []

    def test_calls_with_sources(self):
        mock_records = [
            WhoisHistoryRecord(
                domain="example.com", date="2024-01-01", source="securitytrails"
            )
        ]
        with patch(
            "mytools.whois.whoishistory._query_all_sources",
            new_callable=AsyncMock,
            return_value=mock_records,
        ) as mock_query:
            result = run_history(
                "example.com",
                sources=["securitytrails"],
                api_keys={"securitytrails": "key"},
            )
            assert len(result) == 1
            mock_query.assert_called_once()


@pytest.mark.smoke
class TestBuildParser:
    def test_has_domain(self):
        parser = build_parser()
        args = parser.parse_args(["example.com"])
        assert args.domain == "example.com"

    def test_has_source(self):
        parser = build_parser()
        args = parser.parse_args(["example.com", "--source", "securitytrails"])
        assert args.source == ["securitytrails"]

    def test_has_st_api_key(self):
        parser = build_parser()
        args = parser.parse_args(["example.com", "--st-api-key", "abc123"])
        assert args.st_api_key == "abc123"

    def test_has_whoisxml_api_key(self):
        parser = build_parser()
        args = parser.parse_args(["example.com", "--whoisxml-api-key", "xyz789"])
        assert args.whoisxml_key == "xyz789"

    def test_source_multiple(self):
        parser = build_parser()
        args = parser.parse_args(
            ["example.com", "--source", "securitytrails", "--source", "whoisxml"]
        )
        assert args.source == ["securitytrails", "whoisxml"]

    def test_domain_optional(self):
        parser = build_parser()
        args = parser.parse_args([])
        assert args.domain is None

    def test_timeout_default(self):
        parser = build_parser()
        args = parser.parse_args(["example.com"])
        assert args.timeout == DEFAULT_TIMEOUT


class TestRunOnce:
    def _make_args(self, **overrides):
        parser = build_parser()
        defaults = vars(parser.parse_args(["example.com"]))
        defaults.update(overrides)
        return argparse.Namespace(**defaults)

    def test_dry_run(self, caplog):
        args = self._make_args(dry_run=True)
        with caplog.at_level("WARNING", logger="mytools.whoishistory"):
            result = run_once(args)
        assert result == 0
        assert any("Nenhuma consulta" in r.message for r in caplog.records)

    def test_calls_run_history(self):
        args = self._make_args()
        with patch(
            "mytools.whois.whoishistory.run_history", return_value=[]
        ) as mock_hist:
            with patch("mytools.whois.whoishistory.init_scanner"):
                run_once(args)
            mock_hist.assert_called_once()

    def test_calls_run_history_with_keys(self):
        args = self._make_args(
            st_api_key="key123",
            whoisxml_key="k2",
            source=["securitytrails", "whoisxml"],
        )
        with patch(
            "mytools.whois.whoishistory.run_history", return_value=[]
        ) as mock_hist:
            with patch("mytools.whois.whoishistory.init_scanner"):
                run_once(args)
            mock_hist.assert_called_once()

    def test_output_writes(self, tmp_path):
        out = str(tmp_path / "whois.json")
        args = self._make_args(output=out)
        with (
            patch("mytools.whois.whoishistory.run_history", return_value=[]),
            patch("mytools.whois.whoishistory.init_scanner"),
            patch("mytools.whois.whoishistory.write_output") as mock_write,
        ):
            run_once(args)
        mock_write.assert_called_once()


class TestPrintHistory:
    def test_empty(self, caplog):
        from mytools.whois.whoishistory import _print_history

        with caplog.at_level("INFO", logger="mytools.whoishistory"):
            _print_history([])
        assert any("Nenhum registro" in r.message for r in caplog.records)

    def test_with_records(self, capsys):
        from mytools.whois.whoishistory import _print_history

        records = [
            WhoisHistoryRecord(
                domain="example.com",
                date="2024-01-01",
                registrar="GoDaddy",
                source="securitytrails",
            ),
        ]
        _print_history(records)
        out = capsys.readouterr().out
        assert "GoDaddy" in out


class TestMainAndGuard:
    def test_main_with_domain(self):
        with (
            patch("mytools.whois.whoishistory.run_once", return_value=0) as mock_run,
            patch("sys.argv", ["mytools-whoishistory", "example.com"]),
        ):
            assert main() == 0
        mock_run.assert_called_once()

    def test_main_guard(self):
        import runpy

        with (
            patch("mytools.core.utils.run_main_loop", side_effect=SystemExit(0)),
            patch("sys.argv", ["mytools-whoishistory"]),
            pytest.raises(SystemExit),
        ):
            runpy.run_module("mytools.whois.whoishistory", run_name="__main__")


class TestBannerArt:
    def test_not_empty(self):
        assert len(BANNER_ART) > 0
