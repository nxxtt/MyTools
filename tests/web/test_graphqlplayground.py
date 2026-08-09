import argparse
import asyncio
import json
import runpy
from unittest.mock import AsyncMock, patch

import pytest

from mytools.core.utils import FetchError, RateLimiter
from mytools.web.graphqlplayground import (
    DEFAULT_PATHS,
    INTROSPECTION_QUERY,
    GraphqlEndpoint,
    _async_run_once,
    _load_paths_from_args,
    build_parser,
    detect_tool,
    main,
    parse_introspection,
    print_results,
    print_schema_details,
    probe_endpoint,
    run_introspection,
    run_once,
    scan_graphql,
)


def _rate_limiter() -> RateLimiter:
    return RateLimiter(0.0)


class TestGraphqlEndpoint:
    def test_frozen(self):
        ep = GraphqlEndpoint(url="http://x.com/graphql", tool="graphiql", status=200)
        with pytest.raises(AttributeError):
            ep.tool = "nope"  # type: ignore[reportAttributeAccessIssue]

    def test_defaults(self):
        ep = GraphqlEndpoint(url="http://x.com/graphql", tool="graphql", status=200)
        assert ep.supports_introspection is False
        assert ep.schema_types == []
        assert ep.query_type == ""
        assert ep.mutation_type == ""
        assert ep.subscription_type == ""
        assert ep.raw_size == 0

    def test_all_fields(self):
        ep = GraphqlEndpoint(
            url="http://x.com/graphql",
            tool="graphiql",
            status=200,
            supports_introspection=True,
            schema_types=["User (OBJECT)", "Query (OBJECT)"],
            query_type="Query",
            mutation_type="Mutation",
            subscription_type="Subscription",
            raw_size=1024,
        )
        assert ep.supports_introspection is True
        assert len(ep.schema_types) == 2
        assert ep.query_type == "Query"


class TestDetectTool:
    def test_graphiql_div_id(self):
        html = '<div id="graphiql">Loading...</div>'
        assert detect_tool(html, {}) == "graphiql"

    def test_graphiql_script(self):
        html = '<script src="graphiql.react.min.js"></script>'
        assert detect_tool(html, {}) == "graphiql"

    def test_graphiql_create(self):
        html = 'GraphiQL.create(document.getElementById("root"))'
        assert detect_tool(html, {}) == "graphiql"

    def test_playground_title(self):
        html = "<title>GraphQL Playground</title>"
        assert detect_tool(html, {}) == "playground"

    def test_playground_div(self):
        html = '<div class="playground">loading</div>'
        assert detect_tool(html, {}) == "playground"

    def test_altair_script(self):
        html = '<script src="altair-graphql/build/index.js"></script>'
        assert detect_tool(html, {}) == "altair"

    def test_altair_window(self):
        html = "window.altair = new AltairGraphQL()"
        assert detect_tool(html, {}) == "altair"

    def test_voyager_div(self):
        html = '<div class="voyager">loading</div>'
        assert detect_tool(html, {}) == "voyager"

    def test_voyager_script(self):
        html = '<script src="graphql-voyager.min.js"></script>'
        assert detect_tool(html, {}) == "voyager"

    def test_apollo_sandbox(self):
        html = '<div id="apollo-sandbox"></div>'
        assert detect_tool(html, {}) == "apollo-sandbox"

    def test_apollo_sandbox_class(self):
        html = '<div class="ApolloSandbox"></div>'
        assert detect_tool(html, {}) == "apollo-sandbox"

    def test_graphql_response_header(self):
        html = ""
        headers = {"content-type": "application/graphql-response+json"}
        assert detect_tool(html, headers) == "graphql"

    def test_unknown_returns_unknown(self):
        html = "<html><body>Hello world</body></html>"
        assert detect_tool(html, {}) == "unknown"

    def test_empty_body(self):
        assert detect_tool("", {}) == "unknown"

    def test_graphiql_case_insensitive(self):
        html = '<DIV ID="GRAPHIQL">'
        assert detect_tool(html, {}) == "graphiql"

    def test_multiple_signatures_first_wins(self):
        html = '<div id="graphiql"><title>GraphQL Playground</title></div>'
        assert detect_tool(html, {}) == "graphiql"


class TestParseIntrospection:
    def test_basic_schema(self):
        data = {
            "data": {
                "__schema": {
                    "queryType": {"name": "Query"},
                    "mutationType": {"name": "Mutation"},
                    "subscriptionType": None,
                    "types": [
                        {"name": "Query", "kind": "OBJECT"},
                        {"name": "User", "kind": "OBJECT"},
                        {"name": "__Schema", "kind": "SCALAR"},
                    ],
                }
            }
        }
        types, query, mutation, subscription = parse_introspection(data)  # type: ignore[reportArgumentType]
        assert len(types) == 2
        assert "Query (OBJECT)" in types
        assert "User (OBJECT)" in types
        assert "__Schema" not in types[0] or all("__" not in t for t in types)
        assert query == "Query"
        assert mutation == "Mutation"
        assert subscription == ""

    def test_empty_data(self):
        types, query, _mutation, _subscription = parse_introspection({})
        assert types == []
        assert query == ""

    def test_no_data_field(self):
        types, _query, _mutation, _subscription = parse_introspection({"errors": []})
        assert types == []

    def test_nested_types_filtered(self):
        data = {
            "data": {
                "__schema": {
                    "types": [
                        {"name": "__Type", "kind": "SCALAR"},
                        {"name": "__Field", "kind": "OBJECT"},
                        {"name": "Post", "kind": "OBJECT"},
                    ]
                }
            }
        }
        types, _, _, _ = parse_introspection(data)  # type: ignore[reportArgumentType]
        assert len(types) == 1
        assert types[0] == "Post (OBJECT)"

    def test_no_query_type(self):
        data = {"data": {"__schema": {"types": [{"name": "Item", "kind": "OBJECT"}]}}}
        types, query, _mutation, _subscription = parse_introspection(data)  # type: ignore[reportArgumentType]
        assert types == ["Item (OBJECT)"]
        assert query == ""

    def test_malformed_types(self):
        data = {"data": {"__schema": {"types": "not a list"}}}
        types, _, _, _ = parse_introspection(data)  # type: ignore[reportArgumentType]
        assert types == []


class TestIntrospectionQuery:
    def test_is_valid_json(self):
        parsed = json.loads(INTROSPECTION_QUERY)
        assert "query" in parsed
        assert "__schema" in parsed["query"]


class TestDefaultPaths:
    def test_paths_are_strings(self):
        assert all(isinstance(p, str) for p in DEFAULT_PATHS)

    def test_common_paths_present(self):
        assert "graphql" in DEFAULT_PATHS
        assert "graphiql" in DEFAULT_PATHS
        assert "playground" in DEFAULT_PATHS
        assert "altair" in DEFAULT_PATHS
        assert "voyager" in DEFAULT_PATHS

    def test_minimum_count(self):
        assert len(DEFAULT_PATHS) >= 10


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

    def test_has_introspect_flag(self):
        parser = build_parser()
        args = parser.parse_args(["--introspect", "http://x.com"])
        assert args.introspect is True

    def test_introspect_default_false(self):
        parser = build_parser()
        args = parser.parse_args(["http://x.com"])
        assert args.introspect is False

    def test_has_schema_flag(self):
        parser = build_parser()
        args = parser.parse_args(["--schema", "http://x.com"])
        assert args.show_schema is True

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

    def test_has_paths_arg(self):
        parser = build_parser()
        args = parser.parse_args(["--paths", "10", "http://x.com"])
        assert args.paths == 10


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
        endpoint = GraphqlEndpoint(
            url="http://x.com/graphql", tool="graphiql", status=200
        )
        args = build_parser().parse_args(["--json", "-q", "http://x.com"])
        with patch(
            "mytools.web.graphqlplayground.scan_graphql",
            new=AsyncMock(return_value=[endpoint]),
        ):
            result = asyncio.run(_async_run_once(args))
        assert result == 0
        decoder = json.JSONDecoder()
        data, _ = decoder.raw_decode(capsys.readouterr().out)
        assert isinstance(data, list)
        assert data[0]["url"] == "http://x.com/graphql"


# ── parse_introspection — branches restantes ────────────────────────────────


class TestParseIntrospectionBranches:
    def test_data_not_dict(self):
        types, query, mutation, subscription = parse_introspection({"data": "junk"})
        assert types == []
        assert query == ""
        assert mutation == ""
        assert subscription == ""

    def test_schema_not_dict(self):
        types, _q, _m, _s = parse_introspection({"data": {"__schema": "junk"}})
        assert types == []

    def test_non_dict_type_entries(self):
        data: dict[str, object] = {
            "data": {
                "__schema": {"types": ["junk", {"name": "Post", "kind": "OBJECT"}]}
            }
        }
        types, _q, _m, _s = parse_introspection(data)
        assert types == ["Post (OBJECT)"]

    def test_non_dict_query_type(self):
        data: dict[str, object] = {"data": {"__schema": {"queryType": "Query"}}}
        _t, query, _m, _s = parse_introspection(data)
        assert query == ""


# ── run_introspection ───────────────────────────────────────────────────────


class TestRunIntrospection:
    @pytest.mark.asyncio
    async def test_fetch_error(self):
        client = AsyncMock()
        with patch(
            "mytools.web.graphqlplayground.fetch",
            new=AsyncMock(side_effect=FetchError("u", 3, Exception("x"))),
        ):
            result = await run_introspection(
                client, "http://x.com", 5.0, _rate_limiter()
            )
        assert result == ([], "", "", "")

    @pytest.mark.asyncio
    async def test_non_200(self):
        client = AsyncMock()
        with patch(
            "mytools.web.graphqlplayground.fetch",
            new=AsyncMock(return_value=(500, {}, b"", {})),
        ):
            result = await run_introspection(
                client, "http://x.com", 5.0, _rate_limiter()
            )
        assert result == ([], "", "", "")

    @pytest.mark.asyncio
    async def test_invalid_json(self):
        client = AsyncMock()
        with patch(
            "mytools.web.graphqlplayground.fetch",
            new=AsyncMock(return_value=(200, {}, b"not json", {})),
        ):
            result = await run_introspection(
                client, "http://x.com", 5.0, _rate_limiter()
            )
        assert result == ([], "", "", "")

    @pytest.mark.asyncio
    async def test_errors_in_data(self):
        client = AsyncMock()
        content = json.dumps({"errors": [{"message": "x"}]}).encode()
        with patch(
            "mytools.web.graphqlplayground.fetch",
            new=AsyncMock(return_value=(200, {}, content, {})),
        ):
            result = await run_introspection(
                client, "http://x.com", 5.0, _rate_limiter()
            )
        assert result == ([], "", "", "")

    @pytest.mark.asyncio
    async def test_success(self):
        client = AsyncMock()
        content = json.dumps(
            {
                "data": {
                    "__schema": {
                        "queryType": {"name": "Query"},
                        "types": [{"name": "User", "kind": "OBJECT"}],
                    }
                }
            }
        ).encode()
        with patch(
            "mytools.web.graphqlplayground.fetch",
            new=AsyncMock(return_value=(200, {}, content, {})),
        ):
            result = await run_introspection(
                client, "http://x.com", 5.0, _rate_limiter()
            )
        assert result[0] == ["User (OBJECT)"]
        assert result[1] == "Query"


# ── probe_endpoint ──────────────────────────────────────────────────────────


class TestProbeEndpoint:
    @pytest.mark.asyncio
    async def test_fetch_error_returns_none(self):
        with patch(
            "mytools.web.graphqlplayground.fetch",
            new=AsyncMock(side_effect=FetchError("u", 3, Exception("x"))),
        ):
            result = await probe_endpoint(
                AsyncMock(), _rate_limiter(), "http://x.com/", "graphql", 5.0
            )
        assert result is None

    @pytest.mark.asyncio
    async def test_non_ok_status(self):
        with patch(
            "mytools.web.graphqlplayground.fetch",
            new=AsyncMock(return_value=(404, {}, b"", {})),
        ):
            result = await probe_endpoint(
                AsyncMock(), _rate_limiter(), "http://x.com/", "graphql", 5.0
            )
        assert result is None

    @pytest.mark.asyncio
    async def test_json_graphql_data(self):
        content = json.dumps({"data": {"__typename": "Query"}}).encode()
        headers = {"content-type": "application/json"}
        with patch(
            "mytools.web.graphqlplayground.fetch",
            new=AsyncMock(return_value=(200, headers, content, {})),
        ):
            result = await probe_endpoint(
                AsyncMock(), _rate_limiter(), "http://x.com/", "graphql", 5.0
            )
        assert result is not None
        assert result.tool == "graphql"

    @pytest.mark.asyncio
    async def test_json_graphql_errors(self):
        content = json.dumps({"errors": [{"message": "x"}]}).encode()
        headers = {"content-type": "application/json"}
        with patch(
            "mytools.web.graphqlplayground.fetch",
            new=AsyncMock(return_value=(200, headers, content, {})),
        ):
            result = await probe_endpoint(
                AsyncMock(), _rate_limiter(), "http://x.com/", "graphql", 5.0
            )
        assert result is not None
        assert result.tool == "graphql"

    @pytest.mark.asyncio
    async def test_json_invalid_returns_none(self):
        headers = {"content-type": "application/json"}
        with patch(
            "mytools.web.graphqlplayground.fetch",
            new=AsyncMock(return_value=(200, headers, b"not json", {})),
        ):
            result = await probe_endpoint(
                AsyncMock(), _rate_limiter(), "http://x.com/", "graphql", 5.0
            )
        assert result is None

    @pytest.mark.asyncio
    async def test_json_without_graphql_keys_returns_none(self):
        headers = {"content-type": "application/json"}
        content = json.dumps({"foo": "bar"}).encode()
        with patch(
            "mytools.web.graphqlplayground.fetch",
            new=AsyncMock(return_value=(200, headers, content, {})),
        ):
            result = await probe_endpoint(
                AsyncMock(), _rate_limiter(), "http://x.com/", "graphql", 5.0
            )
        assert result is None

    @pytest.mark.asyncio
    async def test_other_content_type_falls_through(self):
        headers = {"content-type": "application/octet-stream"}
        with patch(
            "mytools.web.graphqlplayground.fetch",
            new=AsyncMock(return_value=(200, headers, b"binarydata", {})),
        ):
            result = await probe_endpoint(
                AsyncMock(), _rate_limiter(), "http://x.com/", "graphql", 5.0
            )
        assert result is not None
        assert result.tool == "graphql"

    @pytest.mark.asyncio
    async def test_html_detects_tool(self):
        headers = {"content-type": "text/html"}
        body = b'<div id="graphiql"></div>'
        with patch(
            "mytools.web.graphqlplayground.fetch",
            new=AsyncMock(return_value=(200, headers, body, {})),
        ):
            result = await probe_endpoint(
                AsyncMock(), _rate_limiter(), "http://x.com/", "graphql", 5.0
            )
        assert result is not None
        assert result.tool == "graphiql"

    @pytest.mark.asyncio
    async def test_unknown_tool_non_gql_path(self):
        headers = {"content-type": "text/html"}
        body = b"<html>hello</html>"
        with patch(
            "mytools.web.graphqlplayground.fetch",
            new=AsyncMock(return_value=(200, headers, body, {})),
        ):
            result = await probe_endpoint(
                AsyncMock(), _rate_limiter(), "http://x.com/", "static", 5.0
            )
        assert result is None

    @pytest.mark.asyncio
    async def test_unknown_tool_gql_path_fallback(self):
        headers = {"content-type": "text/html"}
        body = b"<html>hello</html>"
        with patch(
            "mytools.web.graphqlplayground.fetch",
            new=AsyncMock(return_value=(200, headers, body, {})),
        ):
            result = await probe_endpoint(
                AsyncMock(), _rate_limiter(), "http://x.com/", "graphql", 5.0
            )
        assert result is not None
        assert result.tool == "graphql"

    @pytest.mark.asyncio
    async def test_introspect_success(self):
        headers = {"content-type": "text/html"}
        body = b'<div id="graphiql"></div>'
        with (
            patch(
                "mytools.web.graphqlplayground.fetch",
                new=AsyncMock(return_value=(200, headers, body, {})),
            ),
            patch(
                "mytools.web.graphqlplayground.run_introspection",
                new=AsyncMock(return_value=(["User (OBJECT)"], "Query", "", "")),
            ),
        ):
            result = await probe_endpoint(
                AsyncMock(),
                _rate_limiter(),
                "http://x.com/",
                "graphql",
                5.0,
                introspect=True,
            )
        assert result is not None
        assert result.supports_introspection is True
        assert result.schema_types == ["User (OBJECT)"]


# ── scan_graphql ────────────────────────────────────────────────────────────


class TestScanGraphql:
    @pytest.mark.asyncio
    async def test_found_endpoints(self, capsys):
        client = AsyncMock()
        ep = GraphqlEndpoint(
            url="http://x.com/graphql",
            tool="graphiql",
            status=200,
            supports_introspection=True,
            schema_types=["User (OBJECT)"],
        )
        with (
            patch(
                "mytools.web.graphqlplayground.create_async_client", return_value=client
            ),
            patch(
                "mytools.web.graphqlplayground.probe_endpoint",
                new=AsyncMock(side_effect=[None, ep]),
            ),
        ):
            endpoints = await scan_graphql(
                base_url="http://x.com/",
                paths=["static", "graphql"],
                timeout=5.0,
                concurrency=2,
                user_agent="t",
                introspect=True,
            )
        assert len(endpoints) == 1
        assert endpoints[0].url == "http://x.com/graphql"
        out = capsys.readouterr().out
        assert "GRAPHIQL" in out

    @pytest.mark.asyncio
    async def test_endpoint_without_introspection(self, capsys):
        client = AsyncMock()
        ep = GraphqlEndpoint(url="http://x.com/graphql", tool="graphiql", status=200)
        with (
            patch(
                "mytools.web.graphqlplayground.create_async_client", return_value=client
            ),
            patch(
                "mytools.web.graphqlplayground.probe_endpoint",
                new=AsyncMock(return_value=ep),
            ),
        ):
            endpoints = await scan_graphql(
                base_url="http://x.com/",
                paths=["graphql"],
                timeout=5.0,
                concurrency=1,
                user_agent="t",
                introspect=True,
            )
        assert len(endpoints) == 1
        assert endpoints[0].supports_introspection is False
        out = capsys.readouterr().out
        assert "GRAPHIQL" in out


# ── print_results / print_schema_details ────────────────────────────────────


class TestPrintResultsFull:
    def test_empty(self, capsys):
        print_results([])
        assert "Nenhum" in capsys.readouterr().out

    def test_with_endpoints(self, capsys):
        eps = [
            GraphqlEndpoint(
                url="http://x.com/graphql",
                tool="graphiql",
                status=200,
                supports_introspection=True,
                schema_types=["User (OBJECT)"],
            ),
            GraphqlEndpoint(url="http://x.com/gql", tool="unknown", status=200),
        ]
        print_results(eps)
        out = capsys.readouterr().out
        assert "GRAPHIQL" in out
        assert "UNKNOWN" in out


class TestPrintSchemaDetails:
    def test_no_introspection(self, capsys):
        ep = GraphqlEndpoint(url="http://x.com/graphql", tool="graphql", status=200)
        print_schema_details(ep)
        assert capsys.readouterr().out == ""

    def test_mutation_without_query_type(self, capsys):
        ep = GraphqlEndpoint(
            url="http://x.com/graphql",
            tool="graphiql",
            status=200,
            supports_introspection=True,
            schema_types=["User (OBJECT)"],
            mutation_type="Mutation",
        )
        print_schema_details(ep)
        out = capsys.readouterr().out
        assert "Mutation:" in out

    def test_full_details(self, capsys):
        ep = GraphqlEndpoint(
            url="http://x.com/graphql",
            tool="graphiql",
            status=200,
            supports_introspection=True,
            schema_types=[f"Type{i} (OBJECT)" for i in range(35)],
            query_type="Query",
            mutation_type="Mutation",
            subscription_type="Subscription",
        )
        print_schema_details(ep)
        out = capsys.readouterr().out
        assert "Schema:" in out
        assert "Query:" in out
        assert "Mutation:" in out
        assert "Subscription:" in out
        assert "+5 mais" in out


# ── _async_run_once — branches restantes ────────────────────────────────────


class TestAsyncRunOnceBranches:
    def test_dry_run(self, capsys):
        args = build_parser().parse_args(["--dry-run", "http://x.com"])
        result = asyncio.run(_async_run_once(args))
        assert result == 0
        assert "DRY-RUN" in capsys.readouterr().out

    def test_output_file(self, tmp_path):
        ep = GraphqlEndpoint(url="http://x.com/graphql", tool="graphiql", status=200)
        out_file = tmp_path / "out.json"
        args = build_parser().parse_args(["-o", str(out_file), "-q", "http://x.com"])
        with patch(
            "mytools.web.graphqlplayground.scan_graphql",
            new=AsyncMock(return_value=[ep]),
        ):
            result = asyncio.run(_async_run_once(args))
        assert result == 0
        assert out_file.exists()

    def test_output_dir(self, tmp_path):
        ep = GraphqlEndpoint(url="http://x.com/graphql", tool="graphiql", status=200)
        out_dir = tmp_path / "out"
        out_dir.mkdir()
        args = build_parser().parse_args(
            ["--output-dir", str(out_dir), "-q", "http://x.com"]
        )
        with patch(
            "mytools.web.graphqlplayground.scan_graphql",
            new=AsyncMock(return_value=[ep]),
        ):
            result = asyncio.run(_async_run_once(args))
        assert result == 0
        assert (out_dir / "x.com.json").exists()

    def test_no_schema_output(self, capsys):
        ep = GraphqlEndpoint(url="http://x.com/graphql", tool="graphiql", status=200)
        args = build_parser().parse_args(["http://x.com"])
        with patch(
            "mytools.web.graphqlplayground.scan_graphql",
            new=AsyncMock(return_value=[ep]),
        ):
            result = asyncio.run(_async_run_once(args))
        assert result == 0
        out = capsys.readouterr().out
        assert "GRAPHIQL" in out

    def test_show_schema(self, capsys):
        ep = GraphqlEndpoint(
            url="http://x.com/graphql",
            tool="graphiql",
            status=200,
            supports_introspection=True,
            schema_types=["User (OBJECT)"],
            query_type="Query",
        )
        args = build_parser().parse_args(["--schema", "http://x.com"])
        with patch(
            "mytools.web.graphqlplayground.scan_graphql",
            new=AsyncMock(return_value=[ep]),
        ):
            result = asyncio.run(_async_run_once(args))
        assert result == 0
        out = capsys.readouterr().out
        assert "Schema:" in out


# ── run_once / main / guard ─────────────────────────────────────────────────


class TestRunOnce:
    def test_run_once(self):
        args = build_parser().parse_args(["http://x.com"])
        with patch(
            "mytools.web.graphqlplayground._async_run_once",
            new=AsyncMock(return_value=0),
        ):
            assert run_once(args) == 0


class TestMainEntry:
    def test_main(self):
        with patch("mytools.web.graphqlplayground.run_main_loop", return_value=0):
            assert main() == 0

    def test_main_guard(self):
        with (
            patch("mytools.core.utils.run_main_loop", side_effect=SystemExit(0)),
            pytest.raises(SystemExit),
        ):
            runpy.run_module("mytools.web.graphqlplayground", run_name="__main__")
