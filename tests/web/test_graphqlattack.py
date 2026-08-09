"""Testes do modulo graphqlattack.py — GraphQL Attack Testing."""

from __future__ import annotations

import runpy
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
import respx

from mytools.web.graphqlattack import (
    _CATEGORY_DISPATCH,
    _CATEGORY_MAP,
    _DEFAULT_PATHS,
    _INTROSPECTION_QUERY,
    GraphQLAttackAttempt,
    GraphQLAttackResult,
    _build_alias_query,
    _build_batch_query,
    _build_circular_query,
    _build_fragment_spread_query,
    _build_nested_query,
    _build_persisted_query,
    _detect_tool,
    _execute_query,
    _find_endpoint,
    _introspect_schema,
    _parse_introspection,
    _parse_url,
    _test_alias_overload,
    _test_batch_abuse,
    _test_depth_abuse,
    _test_introspection,
    _test_persisted_abuse,
    _test_persisted_enum,
    _test_resolver_analysis,
    _test_schema_stitching,
    build_parser,
    main,
    print_results,
    run_once,
    run_scan,
)

# ─── Dataclass Tests ─────────────────────────────────────────────────────────


class TestGraphQLAttackAttempt:
    def test_creation(self) -> None:
        a = GraphQLAttackAttempt(
            technique="schema_discovery",
            category="introspection",
            description="desc",
            vulnerable=False,
            details="test",
            error="",
            endpoint="https://target.com/graphql",
            query_type="Query",
            schema_types=10,
            response_code=200,
        )
        assert a.technique == "schema_discovery"
        assert a.category == "introspection"
        assert a.vulnerable is False

    def test_frozen(self) -> None:
        a = GraphQLAttackAttempt(
            technique="t",
            category="c",
            description="d",
            vulnerable=False,
            details="",
            error="",
            endpoint="",
            query_type="",
            schema_types=0,
            response_code=0,
        )
        with pytest.raises(AttributeError):
            a.technique = "changed"  # type: ignore[misc]


class TestGraphQLAttackResult:
    def test_creation(self) -> None:
        r = GraphQLAttackResult(
            target="https://target.com/graphql",
            host="target.com",
            port=443,
            tls=True,
            endpoint="https://target.com/graphql",
            schema_found=True,
            types_count=10,
            queries_count=1,
            mutations_count=1,
            attempts=[],
            vulnerable_techniques=[],
            issues=[],
            overall_status="secure",
        )
        assert r.overall_status == "secure"
        assert r.schema_found is True

    def test_frozen(self) -> None:
        r = GraphQLAttackResult(
            target="t",
            host="h",
            port=443,
            tls=True,
            endpoint="",
            schema_found=False,
            types_count=0,
            queries_count=0,
            mutations_count=0,
            attempts=[],
            vulnerable_techniques=[],
            issues=[],
            overall_status="secure",
        )
        with pytest.raises(AttributeError):
            r.target = "changed"  # type: ignore[misc]


# ─── Category Map Tests ─────────────────────────────────────────────────────


class TestCategoryMap:
    def test_all_categories_present(self) -> None:
        expected = {
            "introspection",
            "depth_abuse",
            "batch_abuse",
            "alias_overload",
            "schema_stitching",
            "persisted_abuse",
            "resolver_analysis",
            "persisted_enum",
        }
        assert set(_CATEGORY_MAP.keys()) == expected

    def test_category_counts(self) -> None:
        assert len(_CATEGORY_MAP["introspection"]) == 5
        assert len(_CATEGORY_MAP["depth_abuse"]) == 5
        assert len(_CATEGORY_MAP["batch_abuse"]) == 4
        assert len(_CATEGORY_MAP["alias_overload"]) == 4
        assert len(_CATEGORY_MAP["schema_stitching"]) == 4
        assert len(_CATEGORY_MAP["persisted_abuse"]) == 4
        assert len(_CATEGORY_MAP["resolver_analysis"]) == 5
        assert len(_CATEGORY_MAP["persisted_enum"]) == 4

    def test_total_techniques(self) -> None:
        total = sum(len(v) for v in _CATEGORY_MAP.values())
        assert total == 35

    def test_dispatch_matches_map(self) -> None:
        for cat in _CATEGORY_MAP:
            assert cat in _CATEGORY_DISPATCH

    def test_all_dispatches_are_coroutines(self) -> None:
        import inspect

        for cat, fn in _CATEGORY_DISPATCH.items():
            assert inspect.iscoroutinefunction(fn), f"{cat} is not a coroutine"


# ─── Helper Tests ────────────────────────────────────────────────────────────


class TestParseUrl:
    def test_https(self) -> None:
        host, path, port, tls = _parse_url("https://example.com/graphql")
        assert host == "example.com"
        assert path == "/graphql"
        assert port == 443
        assert tls is True

    def test_http(self) -> None:
        host, path, port, tls = _parse_url("http://example.com:8080/api/graphql")
        assert host == "example.com"
        assert path == "/api/graphql"
        assert port == 8080
        assert tls is False

    def test_no_scheme(self) -> None:
        host, _path, _port, tls = _parse_url("example.com")
        assert host == "example.com"
        assert tls is True


class TestDetectTool:
    def test_graphiql(self) -> None:
        html = '<div id="graphiql">test</div>'
        assert _detect_tool(html) == "graphiql"

    def test_playground(self) -> None:
        html = "GraphQL Playground loaded"
        assert _detect_tool(html) == "playground"

    def test_unknown(self) -> None:
        html = "<html><body>test</body></html>"
        assert _detect_tool(html) == "unknown"


class TestQueryBuilders:
    def test_nested_query(self) -> None:
        q = _build_nested_query(3)
        assert q.count("__typename") == 4
        assert q.count("on Query") == 3

    def test_circular_query(self) -> None:
        q = _build_circular_query()
        assert "fragment A" in q
        assert "fragment B" in q

    def test_fragment_spread(self) -> None:
        q = _build_fragment_spread_query(5)
        assert "fragment F0" in q
        assert "fragment F5" in q

    def test_batch_query(self) -> None:
        q = _build_batch_query(["{ __typename }", "{ __schema { types { name } } }"])
        data = __import__("json").loads(q)
        assert isinstance(data, list)
        assert len(data) == 2

    def test_alias_query(self) -> None:
        q = _build_alias_query(10)
        assert "a0: __typename" in q
        assert "a9: __typename" in q

    def test_persisted_query(self) -> None:
        payload = _build_persisted_query("abc123")
        assert payload["extensions"]["persistedQuery"]["sha256Hash"] == "abc123"
        assert payload["extensions"]["persistedQuery"]["version"] == 1


class TestParseIntrospection:
    def test_valid(self) -> None:
        data = {
            "data": {
                "__schema": {
                    "queryType": {"name": "Query"},
                    "mutationType": {"name": "Mutation"},
                    "subscriptionType": {"name": "Subscription"},
                    "types": [
                        {"name": "User", "kind": "OBJECT"},
                        {"name": "Query", "kind": "OBJECT"},
                        {"name": "__Schema", "kind": "OBJECT"},
                    ],
                }
            }
        }
        types, qt, mt, st = _parse_introspection(data)
        assert len(types) == 2  # User and Query (not __Schema)
        assert qt == "Query"
        assert mt == "Mutation"
        assert st == "Subscription"

    def test_empty(self) -> None:
        types, qt, _mt, _st = _parse_introspection({})
        assert types == []
        assert qt == ""


class TestDefaultPaths:
    def test_has_common_paths(self) -> None:
        assert "graphql" in _DEFAULT_PATHS
        assert "api/graphql" in _DEFAULT_PATHS

    def test_introspection_query_is_json(self) -> None:
        import json

        data = json.loads(_INTROSPECTION_QUERY)
        assert "query" in data
        assert "__schema" in data["query"]


# ─── Print Results Tests ─────────────────────────────────────────────────────


class TestPrintResults:
    def test_secure(self, capsys: pytest.CaptureFixture[str]) -> None:
        r = GraphQLAttackResult(
            target="https://target.com/graphql",
            host="target.com",
            port=443,
            tls=True,
            endpoint="https://target.com/graphql",
            schema_found=False,
            types_count=0,
            queries_count=0,
            mutations_count=0,
            attempts=[],
            vulnerable_techniques=[],
            issues=[],
            overall_status="secure",
        )
        print_results(r)
        output = capsys.readouterr().out
        assert "GraphQL Attack Testing" in output
        assert "SECURE" in output

    def test_vulnerable(self, capsys: pytest.CaptureFixture[str]) -> None:
        r = GraphQLAttackResult(
            target="https://target.com/graphql",
            host="target.com",
            port=443,
            tls=True,
            endpoint="https://target.com/graphql",
            schema_found=True,
            types_count=10,
            queries_count=1,
            mutations_count=0,
            attempts=[],
            vulnerable_techniques=["full_introspection"],
            issues=["Errors: test_error"],
            overall_status="vulnerable",
        )
        print_results(r)
        output = capsys.readouterr().out
        assert "VULNERABLE" in output
        assert "Errors:" in output


# ─── CLI Tests ───────────────────────────────────────────────────────────────


class TestCLI:
    def test_build_parser(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["https://target.com/graphql"])
        assert args.url == "https://target.com/graphql"

    def test_build_parser_with_categories(self) -> None:
        parser = build_parser()
        args = parser.parse_args(
            ["https://target.com/graphql", "-c", "introspection", "depth_abuse"]
        )
        assert args.categories == ["introspection", "depth_abuse"]

    def test_build_parser_all_choices(self) -> None:
        parser = build_parser()
        for cat in _CATEGORY_MAP:
            args = parser.parse_args(["https://target.com/graphql", "-c", cat])
            assert args.categories == [cat]


# ─── Async Category Tests (Mocked) ──────────────────────────────────────────


@pytest.mark.asyncio
@pytest.mark.network
@respx.mock
@patch(
    "mytools.web.graphqlattack._execute_query",
    return_value=(200, {"data": {"__typename": "Query"}}),
)
async def test_category_dispatch_all_return_lists(_mock_exec: object) -> None:
    """All category dispatchers should return a list."""
    respx.route().mock(
        return_value=httpx.Response(200, json={"data": {"__typename": "Query"}})
    )
    schema_info = {
        "types": ["User (OBJECT)"],
        "query_type": "Query",
        "mutation_type": "",
        "subscription_type": "",
    }
    for cat, fn in _CATEGORY_DISPATCH.items():
        result = await fn(
            "target.com",
            443,
            "/graphql",
            5.0,
            True,
            "https://target.com/graphql",
            schema_info,
        )
        assert isinstance(result, list), f"{cat} did not return a list"
        assert len(result) > 0, f"{cat} returned empty list"
        for attempt in result:
            assert isinstance(attempt, GraphQLAttackAttempt)
            assert attempt.category == cat


def _make_attempt(
    tech: str,
    cat: str,
    *,
    vulnerable: bool = False,
    error: str = "",
) -> GraphQLAttackAttempt:
    return GraphQLAttackAttempt(
        technique=tech,
        category=cat,
        description="desc",
        vulnerable=vulnerable,
        details="detail",
        error=error,
        endpoint="https://target.com/graphql",
        query_type="Query",
        schema_types=0,
        response_code=200,
    )


def _schema_info() -> dict[str, object]:
    return {
        "types": [],
        "query_type": "",
        "mutation_type": "",
        "subscription_type": "",
    }


# ─── Endpoint Discovery / Query Execution ────────────────────────────────────


class TestFindEndpoint:
    @staticmethod
    def _mock_client(
        *,
        status: int = 200,
        ct: str = "application/json",
        payload: dict[str, object] | None = None,
        json_error: bool = False,
        side_effect: BaseException | None = None,
    ) -> AsyncMock:
        resp = MagicMock()
        resp.status_code = status
        resp.headers = {"content-type": ct}
        if json_error:
            resp.json.side_effect = ValueError("bad json")
        else:
            resp.json.return_value = payload
        client = AsyncMock()
        client.__aenter__ = AsyncMock(return_value=client)
        client.__aexit__ = AsyncMock(return_value=False)
        if side_effect is not None:
            client.post.side_effect = side_effect
        else:
            client.post.return_value = resp
        return client

    @pytest.mark.asyncio
    async def test_detects_endpoint(self) -> None:
        client = self._mock_client(payload={"data": {"__typename": "Query"}})
        with patch("httpx.AsyncClient", return_value=client):
            url = await _find_endpoint("target.com", 80, "/graphql", 5.0, False)
        assert url == "http:/target.com/graphql"

    @pytest.mark.asyncio
    async def test_custom_port(self) -> None:
        client = self._mock_client(payload={"errors": []})
        with patch("httpx.AsyncClient", return_value=client):
            url = await _find_endpoint("target.com", 8080, "/graphql", 5.0, False)
        assert url == "http:/target.com:8080/graphql"

    @pytest.mark.asyncio
    async def test_dict_without_data_skipped(self) -> None:
        client = self._mock_client(payload={"foo": "bar"})
        with patch("httpx.AsyncClient", return_value=client):
            url = await _find_endpoint("target.com", 443, "/", 5.0, True)
        assert url == "https:/target.com/"

    @pytest.mark.asyncio
    async def test_bad_json_body_skipped(self) -> None:
        client = self._mock_client(json_error=True)
        with patch("httpx.AsyncClient", return_value=client):
            url = await _find_endpoint("target.com", 443, "/", 5.0, True)
        assert url == "https:/target.com/"

    @pytest.mark.asyncio
    async def test_non_json_content_type_skipped(self) -> None:
        client = self._mock_client(status=200, ct="text/html", payload={"data": {}})
        with patch("httpx.AsyncClient", return_value=client):
            url = await _find_endpoint("target.com", 443, "/", 5.0, True)
        assert url == "https:/target.com/"

    @pytest.mark.asyncio
    async def test_network_error_continues(self) -> None:
        client = self._mock_client(side_effect=httpx.ConnectError("refused"))
        with patch("httpx.AsyncClient", return_value=client):
            url = await _find_endpoint("target.com", 443, "/", 5.0, True)
        assert url == "https:/target.com/"


class TestExecuteQuery:
    @pytest.mark.asyncio
    @respx.mock
    async def test_success_with_variables_and_headers(self) -> None:
        respx.post("https://h/graphql").mock(
            return_value=httpx.Response(200, json={"data": {"__typename": "Query"}})
        )
        status, data = await _execute_query(
            "https://h/graphql",
            "{ __typename }",
            variables={"x": 1},
            headers={"X-Test": "v"},
        )
        assert status == 200
        assert data["data"]["__typename"] == "Query"

    @pytest.mark.asyncio
    @respx.mock
    async def test_non_json_response(self) -> None:
        respx.post("https://h/graphql").mock(
            return_value=httpx.Response(200, text="plain text")
        )
        status, data = await _execute_query("https://h/graphql", "query")
        assert status == 200
        assert data["raw"] == "plain text"

    @pytest.mark.asyncio
    @respx.mock
    async def test_connection_error(self) -> None:
        respx.post("https://h/graphql").mock(side_effect=httpx.ConnectError("refused"))
        status, data = await _execute_query("https://h/graphql", "query")
        assert status == 0
        assert data == {"error": "connection_failed"}


class TestIntrospectSchema:
    @pytest.mark.asyncio
    @respx.mock
    async def test_returns_data(self) -> None:
        respx.post("https://h/graphql").mock(
            return_value=httpx.Response(200, json={"data": {"__schema": {}}})
        )
        data = await _introspect_schema("https://h/graphql", 5.0)
        assert "__schema" in data["data"]

    @pytest.mark.asyncio
    @respx.mock
    async def test_bad_status_returns_empty(self) -> None:
        respx.post("https://h/graphql").mock(
            return_value=httpx.Response(403, json={"errors": []})
        )
        assert await _introspect_schema("https://h/graphql", 5.0) == {}

    @pytest.mark.asyncio
    @respx.mock
    async def test_errors_returned_empty(self) -> None:
        respx.post("https://h/graphql").mock(
            return_value=httpx.Response(200, json={"errors": [{"message": "no"}]})
        )
        assert await _introspect_schema("https://h/graphql", 5.0) == {}


# ─── Tester Error Handlers ───────────────────────────────────────────────────


class TestTesterErrorHandlers:
    @pytest.mark.asyncio
    async def test_introspection_execute_error(self) -> None:
        with patch(
            "mytools.web.graphqlattack._execute_query",
            side_effect=RuntimeError("boom"),
        ):
            result = await _test_introspection(
                "h", 443, "/", 5.0, True, "https://h/graphql", _schema_info()
            )
        assert any(a.error == "boom" for a in result)

    @pytest.mark.asyncio
    async def test_depth_abuse_execute_error(self) -> None:
        with patch(
            "mytools.web.graphqlattack._execute_query",
            side_effect=RuntimeError("boom"),
        ):
            result = await _test_depth_abuse(
                "h", 443, "/", 5.0, True, "https://h/graphql", _schema_info()
            )
        assert any(a.error == "boom" for a in result)

    @pytest.mark.asyncio
    @respx.mock
    async def test_batch_abuse_network_error(self) -> None:
        respx.post("https://h/graphql").mock(side_effect=httpx.ConnectError("refused"))
        result = await _test_batch_abuse(
            "h", 443, "/", 5.0, True, "https://h/graphql", _schema_info()
        )
        assert any(a.error for a in result)

    @pytest.mark.asyncio
    async def test_alias_overload_execute_error(self) -> None:
        with patch(
            "mytools.web.graphqlattack._execute_query",
            side_effect=RuntimeError("boom"),
        ):
            result = await _test_alias_overload(
                "h", 443, "/", 5.0, True, "https://h/graphql", _schema_info()
            )
        assert any(a.error == "boom" for a in result)

    @pytest.mark.asyncio
    async def test_schema_stitching_execute_error(self) -> None:
        with patch(
            "mytools.web.graphqlattack._execute_query",
            side_effect=RuntimeError("boom"),
        ):
            result = await _test_schema_stitching(
                "h", 443, "/", 5.0, True, "https://h/graphql", _schema_info()
            )
        assert any(a.error == "boom" for a in result)

    @pytest.mark.asyncio
    @respx.mock
    async def test_persisted_abuse_network_error(self) -> None:
        respx.post("https://h/graphql").mock(side_effect=httpx.ConnectError("refused"))
        result = await _test_persisted_abuse(
            "h", 443, "/", 5.0, True, "https://h/graphql", _schema_info()
        )
        assert any(a.error for a in result)

    @pytest.mark.asyncio
    async def test_resolver_analysis_sql_injection_detected(self) -> None:
        with patch(
            "mytools.web.graphqlattack._execute_query",
            return_value=(200, {"error": "sql syntax error"}),
        ):
            result = await _test_resolver_analysis(
                "h", 443, "/", 5.0, True, "https://h/graphql", _schema_info()
            )
        sqli = [a for a in result if a.technique == "sql_injection_in_resolver"]
        assert sqli and sqli[0].vulnerable is True

    @pytest.mark.asyncio
    async def test_resolver_analysis_execute_error(self) -> None:
        with patch(
            "mytools.web.graphqlattack._execute_query",
            side_effect=RuntimeError("boom"),
        ):
            result = await _test_resolver_analysis(
                "h", 443, "/", 5.0, True, "https://h/graphql", _schema_info()
            )
        assert any(a.error == "boom" for a in result)

    @pytest.mark.asyncio
    @respx.mock
    async def test_persisted_enum_network_error(self) -> None:
        respx.post("https://h/graphql").mock(side_effect=httpx.ConnectError("refused"))
        result = await _test_persisted_enum(
            "h", 443, "/", 5.0, True, "https://h/graphql", _schema_info()
        )
        assert any(a.error for a in result)


# ─── Parse Introspection Extra Branches ──────────────────────────────────────


class TestParseIntrospectionExtra:
    def test_data_not_dict(self) -> None:
        types, qt, mt, st = _parse_introspection({"data": "not-a-dict"})
        assert (types, qt, mt, st) == ([], "", "", "")

    def test_schema_not_dict(self) -> None:
        types, qt, mt, st = _parse_introspection({"data": {"__schema": "nope"}})
        assert (types, qt, mt, st) == ([], "", "", "")

    def test_types_not_a_list(self) -> None:
        types, qt, _mt, _st = _parse_introspection(
            {"data": {"__schema": {"types": "not-a-list"}}}
        )
        assert types == []
        assert qt == ""

    def test_type_entry_not_a_dict(self) -> None:
        data: dict[str, object] = {
            "data": {
                "__schema": {"types": ["junk", {"name": "User", "kind": "OBJECT"}]}
            }
        }
        types, _qt, _mt, _st = _parse_introspection(data)
        assert types == ["User (OBJECT)"]


# ─── Persisted Enumeration Branches ──────────────────────────────────────────


class TestPersistedAbuseEnumerationBranches:
    @pytest.mark.asyncio
    @respx.mock
    async def test_enumeration_mixed_statuses(self) -> None:
        calls = {"n": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            n = calls["n"]
            calls["n"] += 1
            if n in (0, 3):
                return httpx.Response(403, json={"errors": []})
            if n in (1, 4):
                return httpx.Response(200, json={"foo": "bar"})
            return httpx.Response(200, json={"data": {"__typename": "Query"}})

        respx.post("https://h/graphql").mock(side_effect=handler)
        result = await _test_persisted_abuse(
            "h", 443, "/", 5.0, True, "https://h/graphql", _schema_info()
        )
        assert len(result) == 4
        assert any(a.technique == "persisted_query_enumeration" for a in result)


class TestPersistedEnumBranches:
    @pytest.mark.asyncio
    @respx.mock
    async def test_mixed_statuses(self) -> None:
        calls = {"n": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            n = calls["n"]
            calls["n"] += 1
            if n in (0, 5):
                return httpx.Response(403, json={"errors": []})
            if n in (1, 6):
                return httpx.Response(200, json={"foo": "bar"})
            return httpx.Response(200, json={"data": {"__typename": "Query"}})

        respx.post("https://h/graphql").mock(side_effect=handler)
        with patch(
            "mytools.web.graphqlattack._execute_query",
            new=AsyncMock(return_value=(200, {"data": {"__typename": "Query"}})),
        ):
            result = await _test_persisted_enum(
                "h", 443, "/", 5.0, True, "https://h/graphql", _schema_info()
            )
        assert len(result) == 4
        assert {a.technique for a in result} == {
            "hash_bruteforce",
            "id_enumeration",
            "query_from_response",
            "persisted_vs_dynamic",
        }


# ─── Print Results Categories ────────────────────────────────────────────────


class TestPrintResultsCategories:
    def test_vulnerable_and_secure_categories(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        v = _make_attempt("full_introspection", "introspection", vulnerable=True)
        e = _make_attempt("some_tech", "depth_abuse", error="x")
        r = GraphQLAttackResult(
            target="https://target.com/graphql",
            host="target.com",
            port=443,
            tls=True,
            endpoint="https://target.com/graphql",
            schema_found=True,
            types_count=5,
            queries_count=1,
            mutations_count=0,
            attempts=[v, e],
            vulnerable_techniques=["full_introspection"],
            issues=[],
            overall_status="vulnerable",
        )
        print_results(r)
        out = capsys.readouterr().out
        assert "introspection: 1 vulnerable" in out
        assert "full_introspection" in out
        assert "depth_abuse: secure" in out


# ─── run_scan ────────────────────────────────────────────────────────────────


class TestRunScan:
    @pytest.mark.asyncio
    async def test_vulnerable_result(self) -> None:
        att = _make_attempt("full_introspection", "introspection", vulnerable=True)
        with (
            patch(
                "mytools.web.graphqlattack._find_endpoint",
                new_callable=AsyncMock,
                return_value="https://target.com/graphql",
            ),
            patch(
                "mytools.web.graphqlattack._introspect_schema",
                new_callable=AsyncMock,
                return_value={
                    "data": {
                        "__schema": {
                            "types": [{"name": "User", "kind": "OBJECT"}],
                            "queryType": {"name": "Query"},
                        }
                    }
                },
            ),
            patch(
                "mytools.web.graphqlattack._CATEGORY_DISPATCH",
                {"introspection": AsyncMock(return_value=[att])},
            ),
        ):
            result = await run_scan("https://target.com", ["introspection"], 5.0, None)
        assert result.overall_status == "vulnerable"
        assert result.schema_found is True
        assert result.types_count == 1
        assert result.vulnerable_techniques == ["full_introspection"]

    @pytest.mark.asyncio
    async def test_secure_with_invalid_category_and_issue(self) -> None:
        err_att = _make_attempt("cat_error", "introspection", error="boom")
        with (
            patch(
                "mytools.web.graphqlattack._find_endpoint",
                new_callable=AsyncMock,
                return_value="https://target.com/graphql",
            ),
            patch(
                "mytools.web.graphqlattack._introspect_schema",
                new_callable=AsyncMock,
                return_value={},
            ),
            patch(
                "mytools.web.graphqlattack._CATEGORY_DISPATCH",
                {"introspection": AsyncMock(return_value=[err_att])},
            ),
        ):
            result = await run_scan(
                "https://target.com", ["bogus", "introspection"], 5.0, None
            )
        assert result.overall_status == "secure"
        assert result.issues == ["Errors: cat_error"]
        assert result.schema_found is False

    @pytest.mark.asyncio
    async def test_default_categories_with_output(self, tmp_path) -> None:
        att = _make_attempt("some_tech", "introspection", vulnerable=True)
        out_file = tmp_path / "out.json"
        with (
            patch(
                "mytools.web.graphqlattack._find_endpoint",
                new_callable=AsyncMock,
                return_value="https://target.com/graphql",
            ),
            patch(
                "mytools.web.graphqlattack._introspect_schema",
                new_callable=AsyncMock,
                return_value={},
            ),
            patch(
                "mytools.web.graphqlattack._CATEGORY_DISPATCH",
                {"introspection": AsyncMock(return_value=[att])},
            ),
        ):
            result = await run_scan("https://target.com", None, 5.0, str(out_file))
        assert result.overall_status == "vulnerable"
        assert out_file.exists()

    @pytest.mark.asyncio
    async def test_tester_exception_is_recorded(self) -> None:
        async def _boom(
            *_args: object, **_kwargs: object
        ) -> list[GraphQLAttackAttempt]:
            raise RuntimeError("tester failed")

        with (
            patch(
                "mytools.web.graphqlattack._find_endpoint",
                new_callable=AsyncMock,
                return_value="https://target.com/graphql",
            ),
            patch(
                "mytools.web.graphqlattack._introspect_schema",
                new_callable=AsyncMock,
                return_value={},
            ),
            patch(
                "mytools.web.graphqlattack._CATEGORY_DISPATCH", {"introspection": _boom}
            ),
        ):
            result = await run_scan("https://target.com", ["introspection"], 5.0, None)
        assert result.issues == ["Errors: introspection_error"]


# ─── run_once / main ─────────────────────────────────────────────────────────


class TestRunOnce:
    def test_vulnerable_returns_1(self) -> None:
        result = MagicMock()
        result.overall_status = "vulnerable"
        with patch(
            "mytools.web.graphqlattack.run_scan",
            new_callable=AsyncMock,
            return_value=result,
        ):
            assert run_once(MagicMock()) == 1

    def test_secure_returns_0(self) -> None:
        result = MagicMock()
        result.overall_status = "secure"
        with patch(
            "mytools.web.graphqlattack.run_scan",
            new_callable=AsyncMock,
            return_value=result,
        ):
            assert run_once(MagicMock()) == 0


class TestMainEntry:
    def test_main(self) -> None:
        with patch("mytools.web.graphqlattack.run_main_loop", return_value=0):
            assert main() == 0

    def test_main_guard(self) -> None:
        with (
            patch("mytools.core.utils.run_main_loop", side_effect=SystemExit(0)),
            pytest.raises(SystemExit) as exc_info,
        ):
            runpy.run_module("mytools.web.graphqlattack", run_name="__main__")
        assert exc_info.value.code == 0
