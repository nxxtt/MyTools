import argparse
import asyncio
import json
import runpy
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
import respx

from mytools.core.utils import RateLimiter
from mytools.web.openapidiscovery import (
    DEFAULT_PATHS,
    ApiSpecInfo,
    EndpointInfo,
    _async_run_once,
    _load_paths_from_args,
    _parse_openapi_v2,
    _parse_openapi_v3,
    build_parser,
    main,
    parse_spec,
    print_api_endpoints,
    print_api_summary,
    probe_spec,
    run_once,
    scan_specs,
)


class TestEndpointInfo:
    def test_frozen(self):
        ep = EndpointInfo(method="GET", path="/users")
        with pytest.raises(AttributeError):
            ep.method = "POST"  # type: ignore[reportAttributeAccessIssue]

    def test_defaults(self):
        ep = EndpointInfo(method="GET", path="/users")
        assert ep.summary == ""
        assert ep.tags == []
        assert ep.parameters == []

    def test_all_fields(self):
        ep = EndpointInfo(
            method="POST",
            path="/users",
            summary="Create user",
            tags=["admin"],
            parameters=["name (query)"],
        )
        assert ep.method == "POST"
        assert ep.summary == "Create user"
        assert len(ep.tags) == 1
        assert len(ep.parameters) == 1


class TestApiSpecInfo:
    def test_frozen(self):
        spec = ApiSpecInfo(url="http://x.com/o.json", format="json")
        with pytest.raises(AttributeError):
            spec.title = "nope"  # type: ignore[reportAttributeAccessIssue]

    def test_defaults(self):
        spec = ApiSpecInfo(url="http://x.com/o.json", format="json")
        assert spec.title == ""
        assert spec.version == ""
        assert spec.description == ""
        assert spec.servers == []
        assert spec.endpoints == []
        assert spec.schemas == []
        assert spec.raw_size == 0
        assert spec.status == 0

    def test_all_fields(self):
        spec = ApiSpecInfo(
            url="http://x.com/o.json",
            format="json",
            title="My API",
            version="1.0",
            description="Test",
            servers=["http://localhost"],
            endpoints=[EndpointInfo(method="GET", path="/a")],
            schemas=["User"],
            raw_size=512,
            status=200,
        )
        assert spec.title == "My API"
        assert len(spec.endpoints) == 1
        assert spec.raw_size == 512


class TestParseOpenapiV3:
    def test_basic_v3(self):
        spec = {
            "openapi": "3.0.0",
            "info": {"title": "Test API", "version": "1.0.0"},
            "servers": [{"url": "http://localhost:8080"}],
            "paths": {
                "/users": {
                    "get": {"summary": "List users", "tags": ["users"]},
                    "post": {"summary": "Create user", "tags": ["users"]},
                },
                "/health": {
                    "get": {"summary": "Health check"},
                },
            },
            "components": {
                "schemas": {"User": {"type": "object"}, "Error": {"type": "object"}},
            },
        }
        title, version, _desc, servers, endpoints, schemas = _parse_openapi_v3(spec)
        assert title == "Test API"
        assert version == "1.0.0"
        assert len(servers) == 1
        assert len(endpoints) == 3
        assert len(schemas) == 2
        assert endpoints[0].method == "GET"
        assert endpoints[0].path == "/users"
        assert endpoints[1].method == "POST"

    def test_empty_v3(self):
        title, version, _desc, servers, endpoints, schemas = _parse_openapi_v3({})
        assert title == ""
        assert version == ""
        assert servers == []
        assert endpoints == []
        assert schemas == []

    def test_with_parameters(self):
        spec = {
            "paths": {
                "/items": {
                    "get": {
                        "summary": "List items",
                        "tags": ["items"],
                        "parameters": [
                            {"name": "page", "in": "query"},
                            {"name": "id", "in": "path"},
                        ],
                    }
                }
            }
        }
        _, _, _, _, endpoints, _ = _parse_openapi_v3(spec)  # type: ignore[reportArgumentType]
        assert len(endpoints) == 1
        assert len(endpoints[0].parameters) == 2
        assert endpoints[0].parameters[0] == "page (query)"

    def test_non_dict_methods(self):
        spec = {"paths": {"/x": "not a dict"}}
        _, _, _, _, endpoints, _ = _parse_openapi_v3(spec)  # type: ignore[reportArgumentType]
        assert endpoints == []

    def test_paths_not_dict(self):
        _, _, _, _, endpoints, _ = _parse_openapi_v3({"paths": "oops"})  # type: ignore[reportArgumentType]
        assert endpoints == []

    def test_parameter_not_dict(self):
        spec = {
            "paths": {
                "/x": {"get": {"parameters": [{"name": "page", "in": "query"}, "junk"]}}
            }
        }
        _, _, _, _, endpoints, _ = _parse_openapi_v3(spec)  # type: ignore[reportArgumentType]
        assert endpoints[0].parameters == ["page (query)"]

    def test_parameter_without_name(self):
        spec = {
            "paths": {
                "/x": {
                    "get": {
                        "parameters": [{"in": "query"}, {"name": "id", "in": "path"}]
                    }
                }
            }
        }
        _, _, _, _, endpoints, _ = _parse_openapi_v3(spec)  # type: ignore[reportArgumentType]
        assert endpoints[0].parameters == ["id (path)"]

    def test_components_not_dict(self):
        _, _, _, _, _, schemas = _parse_openapi_v3({"components": "oops"})  # type: ignore[reportArgumentType]
        assert schemas == []

    def test_schemas_not_dict(self):
        _, _, _, _, _, schemas = _parse_openapi_v3({"components": {"schemas": "oops"}})  # type: ignore[reportArgumentType]
        assert schemas == []


class TestParseOpenapiV2:
    def test_basic_v2(self):
        spec = {
            "swagger": "2.0",
            "info": {"title": "Swagger 2", "version": "2.0"},
            "host": "api.example.com",
            "basePath": "/v1",
            "schemes": ["https"],
            "paths": {
                "/pets": {
                    "get": {"summary": "List pets"},
                },
            },
            "definitions": {"Pet": {"type": "object"}},
        }
        title, version, _desc, servers, endpoints, schemas = _parse_openapi_v2(spec)
        assert title == "Swagger 2"
        assert version == "2.0"
        assert len(servers) == 1
        assert "https://api.example.com/v1" in servers[0]
        assert len(endpoints) == 1
        assert len(schemas) == 1

    def test_empty_v2(self):
        title, _version, _desc, _servers, endpoints, schemas = _parse_openapi_v2({})
        assert title == ""
        assert endpoints == []
        assert schemas == []


class TestParseSpec:
    def test_valid_openapi3_json(self):
        data = json.dumps(
            {
                "openapi": "3.0.0",
                "info": {"title": "Test", "version": "1.0"},
                "paths": {},
            }
        ).encode()
        result = parse_spec(data, "application/json")
        assert result is not None
        assert result.format == "json"
        assert result.title == "Test"

    def test_valid_swagger2_json(self):
        data = json.dumps(
            {
                "swagger": "2.0",
                "info": {"title": "S2", "version": "2.0"},
                "paths": {},
            }
        ).encode()
        result = parse_spec(data, "application/json")
        assert result is not None
        assert result.format == "json"

    def test_valid_yaml(self):
        data = (
            b"openapi: '3.0.0'\ninfo:\n  title: YAML API\n  version: '1.0'\npaths: {}"
        )
        result = parse_spec(data, "application/x-yaml")
        assert result is not None
        assert result.format == "yaml"
        assert result.title == "YAML API"

    def test_invalid_content(self):
        assert parse_spec(b"not json or yaml", "text/html") is None

    def test_empty_content(self):
        assert parse_spec(b"", "application/json") is None

    def test_not_openapi(self):
        data = json.dumps({"random": "object"}).encode()
        assert parse_spec(data, "application/json") is None

    def test_guesses_json_from_content(self):
        data = json.dumps(
            {
                "openapi": "3.0.0",
                "info": {"title": "Guess", "version": "1"},
                "paths": {},
            }
        ).encode()
        result = parse_spec(data, "text/plain")
        assert result is not None
        assert result.title == "Guess"

    def test_description_truncated(self):
        data = json.dumps(
            {
                "openapi": "3.0.0",
                "info": {"title": "X", "version": "1", "description": "x" * 500},
                "paths": {},
            }
        ).encode()
        result = parse_spec(data, "application/json")
        assert result is not None
        assert len(result.description) == 200


class TestDefaultPaths:
    def test_paths_are_strings(self):
        assert all(isinstance(p, str) for p in DEFAULT_PATHS)

    def test_common_swagger_paths(self):
        assert "swagger.json" in DEFAULT_PATHS
        assert "openapi.json" in DEFAULT_PATHS
        assert "openapi.yaml" in DEFAULT_PATHS
        assert "api-docs" in DEFAULT_PATHS
        assert "swagger-ui.html" in DEFAULT_PATHS

    def test_minimum_count(self):
        assert len(DEFAULT_PATHS) >= 15


class TestLoadPaths:
    def test_default(self):
        args = argparse.Namespace(paths=0)
        result = _load_paths_from_args(args)
        assert result == DEFAULT_PATHS

    def test_limited(self):
        args = argparse.Namespace(paths=5)
        result = _load_paths_from_args(args)
        assert len(result) == 5

    def test_zero_means_all(self):
        args = argparse.Namespace(paths=0)
        result = _load_paths_from_args(args)
        assert len(result) == len(DEFAULT_PATHS)


@pytest.mark.smoke
class TestBuildParser:
    def test_has_url(self):
        parser = build_parser()
        args = parser.parse_args(["http://example.com"])
        assert args.url == "http://example.com"

    def test_has_list(self):
        parser = build_parser()
        args = parser.parse_args(["-l", "urls.txt"])
        assert args.target_list == "urls.txt"

    def test_has_concurrency(self):
        parser = build_parser()
        args = parser.parse_args(["--concurrency", "50"])
        assert args.concurrency == 50

    def test_default_concurrency(self):
        parser = build_parser()
        args = parser.parse_args(["http://x.com"])
        assert args.concurrency == 30

    def test_has_endpoints_flag(self):
        parser = build_parser()
        args = parser.parse_args(["--endpoints", "http://x.com"])
        assert args.show_endpoints is True

    def test_has_paths_arg(self):
        parser = build_parser()
        args = parser.parse_args(["--paths", "10", "http://x.com"])
        assert args.paths == 10

    def test_has_timeout(self):
        parser = build_parser()
        args = parser.parse_args(["-t", "15", "http://x.com"])
        assert args.timeout == 15

    def test_has_output(self):
        parser = build_parser()
        args = parser.parse_args(["-o", "out.json", "http://x.com"])
        assert args.output == "out.json"

    def test_has_proxy(self):
        parser = build_parser()
        args = parser.parse_args(["--proxy", "http://p:8080", "http://x.com"])
        assert args.proxy == "http://p:8080"

    def test_has_user_agent(self):
        parser = build_parser()
        args = parser.parse_args(["-A", "Bot/1.0", "http://x.com"])
        assert args.user_agent == "Bot/1.0"

    def test_has_dry_run(self):
        parser = build_parser()
        args = parser.parse_args(["--dry-run", "http://x.com"])
        assert args.dry_run is True

    def test_has_retries(self):
        parser = build_parser()
        args = parser.parse_args(["--retries", "5", "http://x.com"])
        assert args.retries == 5

    def test_has_delay(self):
        parser = build_parser()
        args = parser.parse_args(["--delay", "2", "http://x.com"])
        assert args.delay == 2

    def test_has_cookie(self):
        parser = build_parser()
        args = parser.parse_args(["--cookie", "session=abc", "http://x.com"])
        assert args.cookie == "session=abc"

    def test_has_header(self):
        parser = build_parser()
        args = parser.parse_args(["--header", "X-Custom: yes", "http://x.com"])
        assert args.header == ["X-Custom: yes"]


# ── Flags comuns (add_common_args) ───────────────────────────────────────────


@pytest.mark.smoke
class TestCommonFlags:
    def test_has_json(self):
        parser = build_parser()
        args = parser.parse_args(["--json", "http://x.com"])
        assert args.json_output is True

    def test_has_quiet(self):
        parser = build_parser()
        args = parser.parse_args(["--quiet", "http://x.com"])
        assert args.quiet is True

    def test_has_theme(self):
        parser = build_parser()
        args = parser.parse_args(["--theme", "solarized", "http://x.com"])
        assert args.theme == "solarized"

    def test_has_random_delay(self):
        parser = build_parser()
        args = parser.parse_args(["--random-delay", "http://x.com"])
        assert args.random_delay is True


# ── Saida --json ─────────────────────────────────────────────────────────────


class TestJsonOutput:
    def test_json_output_is_valid(self, capsys):
        spec = ApiSpecInfo(
            url="http://x.com/openapi.json",
            format="openapi",
            title="Test API",
            version="1.0",
        )
        args = build_parser().parse_args(["--json", "http://x.com"])
        with patch(
            "mytools.web.openapidiscovery.scan_specs",
            new=AsyncMock(return_value=[spec]),
        ):
            result = asyncio.run(_async_run_once(args))
        assert result == 0
        decoder = json.JSONDecoder()
        data, _ = decoder.raw_decode(capsys.readouterr().out)
        assert isinstance(data, list)
        assert data[0]["title"] == "Test API"

    def test_json_output_single_target_printed_once(self, capsys):
        spec = ApiSpecInfo(
            url="http://x.com/openapi.json",
            format="openapi",
            title="Test API",
            version="1.0",
        )
        args = build_parser().parse_args(["--json", "http://x.com"])
        with patch(
            "mytools.web.openapidiscovery.scan_specs",
            new=AsyncMock(return_value=[spec]),
        ):
            result = asyncio.run(_async_run_once(args))
        assert result == 0
        assert capsys.readouterr().out.count('"title"') == 1

    def test_json_output_quiet_suppresses_stdout(self, capsys):
        spec = ApiSpecInfo(
            url="http://x.com/openapi.json",
            format="openapi",
            title="Test API",
            version="1.0",
        )
        args = build_parser().parse_args(["--json", "-q", "http://x.com"])
        with patch(
            "mytools.web.openapidiscovery.scan_specs",
            new=AsyncMock(return_value=[spec]),
        ):
            result = asyncio.run(_async_run_once(args))
        assert result == 0
        assert capsys.readouterr().out == ""

    def test_json_output_multiple_targets(self, capsys, tmp_path):
        spec = ApiSpecInfo(
            url="http://x.com/openapi.json",
            format="openapi",
            title="Test API",
            version="1.0",
        )
        target_file = tmp_path / "targets.txt"
        target_file.write_text("http://x.com\nhttp://y.com\n", encoding="utf-8")
        args = build_parser().parse_args(["--json", "-l", str(target_file)])
        with patch(
            "mytools.web.openapidiscovery.scan_specs",
            new=AsyncMock(return_value=[spec]),
        ):
            result = asyncio.run(_async_run_once(args))
        assert result == 0
        decoder = json.JSONDecoder()
        data, _ = decoder.raw_decode(capsys.readouterr().out)
        assert isinstance(data, list)


class TestParseSpecEdgeCases:
    def test_v3_with_empty_info(self):
        spec = {"openapi": "3.0.0", "info": {}, "paths": {}}
        title, version, _desc, _servers, _endpoints, _schemas = _parse_openapi_v3(spec)
        assert title == ""
        assert version == ""

    def test_v2_without_host(self):
        spec = {
            "swagger": "2.0",
            "info": {"title": "NoHost", "version": "1"},
            "paths": {},
        }
        _title, _version, _desc, servers, _endpoints, _schemas = _parse_openapi_v2(spec)
        assert servers == []

    def test_v3_with_malformed_parameters(self):
        spec = {"paths": {"/x": {"get": {"parameters": "not a list"}}}}
        _, _, _, _, endpoints, _ = _parse_openapi_v3(spec)  # type: ignore[reportArgumentType]
        assert endpoints[0].parameters == []

    def test_parse_spec_dict_not_dict(self):
        assert parse_spec(b"[1,2,3]", "application/json") is None

    def test_v2_with_no_schemes(self):
        spec = {
            "swagger": "2.0",
            "host": "x.com",
            "basePath": "/api",
            "info": {"title": "", "version": ""},
            "paths": {},
        }
        _, _, _, servers, _, _ = _parse_openapi_v2(spec)
        assert len(servers) == 1
        assert "https://" in servers[0]


# ── Parse OpenAPI v2 extra branches ─────────────────────────────────────────


class TestParseOpenapiV2Extra:
    def test_non_dict_methods_and_parameters(self):
        spec = {
            "swagger": "2.0",
            "info": {"title": "S2", "version": "2.0"},
            "paths": {
                "/x": "not a dict",
                "/y": {"get": {"parameters": [{"name": "page", "in": "query"}]}},
            },
        }
        _title, _version, _desc, _servers, endpoints, _schemas = _parse_openapi_v2(spec)
        assert len(endpoints) == 1
        assert endpoints[0].parameters == ["page (query)"]

    def test_paths_not_dict(self):
        _, _, _, _, endpoints, _ = _parse_openapi_v2({"paths": "oops"})  # type: ignore[reportArgumentType]
        assert endpoints == []

    def test_parameters_not_list(self):
        spec = {"paths": {"/x": {"get": {"parameters": "oops"}}}}
        _, _, _, _, endpoints, _ = _parse_openapi_v2(spec)  # type: ignore[reportArgumentType]
        assert endpoints[0].parameters == []

    def test_parameter_not_dict(self):
        spec = {
            "paths": {
                "/x": {"get": {"parameters": [{"name": "page", "in": "query"}, "junk"]}}
            }
        }
        _, _, _, _, endpoints, _ = _parse_openapi_v2(spec)  # type: ignore[reportArgumentType]
        assert endpoints[0].parameters == ["page (query)"]

    def test_parameter_without_name(self):
        spec = {
            "paths": {
                "/x": {
                    "get": {
                        "parameters": [{"in": "query"}, {"name": "id", "in": "path"}]
                    }
                }
            }
        }
        _, _, _, _, endpoints, _ = _parse_openapi_v2(spec)  # type: ignore[reportArgumentType]
        assert endpoints[0].parameters == ["id (path)"]

    def test_definitions_not_dict(self):
        _, _, _, _, _, schemas = _parse_openapi_v2({"definitions": "oops"})  # type: ignore[reportArgumentType]
        assert schemas == []


# ── Parse Spec extra branches ────────────────────────────────────────────────


class TestParseSpecExtra:
    def test_json_fails_then_yaml_parses(self):
        data = (
            b"openapi: '3.0.0'\ninfo:\n  title: YAML API\n  version: '1.0'\npaths: {}"
        )
        result = parse_spec(data, "application/json")
        assert result is not None
        assert result.format == "yaml"
        assert result.title == "YAML API"

    def test_yaml_invalid(self):
        assert parse_spec(b"key: [", "text/plain") is None

    def test_unsupported_version(self):
        data = json.dumps({"swagger": "1.2", "info": {}, "paths": {}}).encode()
        assert parse_spec(data, "application/json") is None


# ── probe_spec ───────────────────────────────────────────────────────────────


class TestProbeSpec:
    @pytest.mark.asyncio
    @respx.mock
    async def test_found(self, async_client):
        respx.get("http://x.com/openapi.json").mock(
            return_value=httpx.Response(
                200,
                json={
                    "openapi": "3.0.0",
                    "info": {"title": "API", "version": "1.0"},
                    "paths": {},
                },
                headers={"content-type": "application/json"},
            )
        )
        spec = await probe_spec(
            async_client, RateLimiter(0), "http://x.com", "openapi.json", 5.0, retries=1
        )
        assert spec is not None
        assert spec.url == "http://x.com/openapi.json"
        assert spec.status == 200
        assert spec.title == "API"

    @pytest.mark.asyncio
    @respx.mock
    async def test_fetch_error_returns_none(self, async_client):
        respx.get("http://x.com/openapi.json").mock(
            side_effect=httpx.ConnectError("refused")
        )
        spec = await probe_spec(
            async_client, RateLimiter(0), "http://x.com", "openapi.json", 5.0, retries=1
        )
        assert spec is None

    @pytest.mark.asyncio
    @respx.mock
    async def test_bad_status_returns_none(self, async_client):
        respx.get("http://x.com/openapi.json").mock(
            return_value=httpx.Response(404, text="")
        )
        spec = await probe_spec(
            async_client, RateLimiter(0), "http://x.com", "openapi.json", 5.0, retries=1
        )
        assert spec is None

    @pytest.mark.asyncio
    @respx.mock
    async def test_invalid_content_returns_none(self, async_client):
        respx.get("http://x.com/openapi.json").mock(
            return_value=httpx.Response(200, text="not a spec")
        )
        spec = await probe_spec(
            async_client, RateLimiter(0), "http://x.com", "openapi.json", 5.0, retries=1
        )
        assert spec is None


# ── scan_specs ───────────────────────────────────────────────────────────────


class TestScanSpecs:
    @pytest.mark.asyncio
    async def test_returns_specs(self, capsys):
        spec = ApiSpecInfo(
            url="http://x.com/openapi.json",
            format="json",
            title="API",
            version="1.0",
            endpoints=[EndpointInfo(method="GET", path="/users")],
            status=200,
        )
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        with (
            patch(
                "mytools.web.openapidiscovery.create_async_client",
                return_value=mock_client,
            ),
            patch(
                "mytools.web.openapidiscovery.probe_spec",
                new_callable=AsyncMock,
                return_value=spec,
            ),
        ):
            result = await scan_specs("http://x.com", ["openapi.json"], 5.0, 2, "UA")
        assert result == [spec]
        out = capsys.readouterr().out
        assert "Finalizado" in out

    @pytest.mark.asyncio
    async def test_skips_probes_when_found_event_set(self, capsys):
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        event_mock = MagicMock()
        event_mock.is_set.side_effect = [False, True, True, True]
        with (
            patch(
                "mytools.web.openapidiscovery.create_async_client",
                return_value=mock_client,
            ),
            patch(
                "mytools.web.openapidiscovery.probe_spec",
                new_callable=AsyncMock,
                return_value=None,
            ),
            patch(
                "mytools.web.openapidiscovery.asyncio.Event",
                return_value=event_mock,
            ),
        ):
            result = await scan_specs("http://x.com", ["a", "b", "c"], 5.0, 1, "UA")
        assert result == []

    @pytest.mark.asyncio
    async def test_probe_returns_none(self, capsys):
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        with (
            patch(
                "mytools.web.openapidiscovery.create_async_client",
                return_value=mock_client,
            ),
            patch(
                "mytools.web.openapidiscovery.probe_spec",
                new_callable=AsyncMock,
                return_value=None,
            ),
        ):
            result = await scan_specs("http://x.com", ["openapi.json"], 5.0, 1, "UA")
        assert result == []
        out = capsys.readouterr().out
        assert "Finalizado" in out


# ── print_api_summary / print_api_endpoints ──────────────────────────────────


class TestPrintApiSummary:
    def test_empty(self, capsys):
        print_api_summary([])
        assert "Nenhuma spec" in capsys.readouterr().out

    def test_with_specs(self, capsys):
        spec = ApiSpecInfo(
            url="http://x.com/o.json",
            format="json",
            title="T" * 50,
            version="1.0",
            endpoints=[EndpointInfo(method="GET", path="/a")],
            schemas=["User"],
            status=200,
        )
        print_api_summary([spec])
        out = capsys.readouterr().out
        assert "TITULO" in out


class TestPrintApiEndpoints:
    def test_empty(self, capsys):
        spec = ApiSpecInfo(url="http://x.com/o.json", format="json", title="API")
        print_api_endpoints(spec)
        assert "Nenhum endpoint" in capsys.readouterr().out

    def test_full(self, capsys):
        spec = ApiSpecInfo(
            url="http://x.com/o.json",
            format="json",
            title="API",
            version="1.0",
            servers=["http://srv"],
            endpoints=[
                EndpointInfo(
                    method="get",
                    path="/users",
                    summary="s" * 60,
                    tags=["a", "b", "c", "d"],
                )
            ],
            schemas=[f"schema{i}" for i in range(25)],
            status=200,
        )
        print_api_endpoints(spec)
        out = capsys.readouterr().out
        assert "Endpoints:" in out
        assert "Servidores:" in out
        assert "+5 mais" in out

    def test_few_schemas(self, capsys):
        spec = ApiSpecInfo(
            url="http://x.com/o.json",
            format="json",
            title="API",
            version="1.0",
            servers=["http://srv"],
            endpoints=[EndpointInfo(method="get", path="/users")],
            schemas=["User", "Error"],
            status=200,
        )
        print_api_endpoints(spec)
        out = capsys.readouterr().out
        assert "Endpoints:" in out
        assert "Schemas: 2" in out


# ── _async_run_once / run_once / main ────────────────────────────────────────


class TestAsyncRunOnceExtra:
    def test_dry_run(self, capsys):
        args = build_parser().parse_args(["--dry-run", "http://x.com"])
        result = asyncio.run(_async_run_once(args))
        assert result == 0
        assert "DRY-RUN" in capsys.readouterr().out

    def test_json_output_dir(self, tmp_path):
        spec = ApiSpecInfo(
            url="http://x.com/openapi.json",
            format="json",
            title="API",
            version="1.0",
            status=200,
        )
        out_dir = tmp_path / "out"
        out_dir.mkdir()
        args = build_parser().parse_args(
            ["--json", "--output-dir", str(out_dir), "-q", "http://x.com"]
        )
        with patch(
            "mytools.web.openapidiscovery.scan_specs",
            new=AsyncMock(return_value=[spec]),
        ):
            result = asyncio.run(_async_run_once(args))
        assert result == 0
        assert (out_dir / "x.com.json").exists()

    def test_show_endpoints(self, capsys):
        spec = ApiSpecInfo(
            url="http://x.com/openapi.json",
            format="json",
            title="API",
            version="1.0",
            endpoints=[EndpointInfo(method="GET", path="/users")],
            status=200,
        )
        args = build_parser().parse_args(["--endpoints", "http://x.com"])
        with patch(
            "mytools.web.openapidiscovery.scan_specs",
            new=AsyncMock(return_value=[spec]),
        ):
            result = asyncio.run(_async_run_once(args))
        assert result == 0
        out = capsys.readouterr().out
        assert "Endpoints:" in out

    def test_quiet_no_json(self, capsys):
        spec = ApiSpecInfo(
            url="http://x.com/openapi.json",
            format="json",
            title="API",
            version="1.0",
            status=200,
        )
        args = build_parser().parse_args(["--quiet", "http://x.com"])
        with patch(
            "mytools.web.openapidiscovery.scan_specs",
            new=AsyncMock(return_value=[spec]),
        ):
            result = asyncio.run(_async_run_once(args))
        assert result == 0
        assert capsys.readouterr().out == ""

    def test_output_file(self, tmp_path):
        spec = ApiSpecInfo(
            url="http://x.com/openapi.json",
            format="json",
            title="API",
            version="1.0",
            status=200,
        )
        out = tmp_path / "out.json"
        args = build_parser().parse_args(["-o", str(out), "http://x.com"])
        with patch(
            "mytools.web.openapidiscovery.scan_specs",
            new=AsyncMock(return_value=[spec]),
        ):
            result = asyncio.run(_async_run_once(args))
        assert result == 0
        assert out.exists()


class TestRunOnce:
    def test_run_once(self):
        args = build_parser().parse_args(["http://x.com"])
        with patch(
            "mytools.web.openapidiscovery._async_run_once",
            new=AsyncMock(return_value=0),
        ):
            assert run_once(args) == 0


class TestMainEntry:
    def test_main(self):
        with patch("mytools.web.openapidiscovery.run_main_loop", return_value=0):
            assert main() == 0

    def test_main_guard(self):
        with (
            patch("mytools.core.utils.run_main_loop", side_effect=SystemExit(0)),
            pytest.raises(SystemExit) as exc_info,
        ):
            runpy.run_module("mytools.web.openapidiscovery", run_name="__main__")
        assert exc_info.value.code == 0
