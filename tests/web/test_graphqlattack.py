"""Testes do modulo graphqlattack.py — GraphQL Attack Testing."""

from __future__ import annotations

import pytest

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
    _parse_introspection,
    _parse_url,
    build_parser,
    print_results,
)

# ─── Dataclass Tests ─────────────────────────────────────────────────────────


class TestGraphQLAttackAttempt:
    def test_creation(self) -> None:
        a = GraphQLAttackAttempt(
            technique="schema_discovery", category="introspection",
            description="desc", vulnerable=False, details="test", error="",
            endpoint="https://target.com/graphql", query_type="Query",
            schema_types=10, response_code=200,
        )
        assert a.technique == "schema_discovery"
        assert a.category == "introspection"
        assert a.vulnerable is False

    def test_frozen(self) -> None:
        a = GraphQLAttackAttempt(
            technique="t", category="c", description="d",
            vulnerable=False, details="", error="",
            endpoint="", query_type="", schema_types=0, response_code=0,
        )
        with pytest.raises(AttributeError):
            a.technique = "changed"  # type: ignore[misc]


class TestGraphQLAttackResult:
    def test_creation(self) -> None:
        r = GraphQLAttackResult(
            target="https://target.com/graphql", host="target.com", port=443, tls=True,
            endpoint="https://target.com/graphql", schema_found=True,
            types_count=10, queries_count=1, mutations_count=1,
            attempts=[], vulnerable_techniques=[], issues=[], overall_status="secure",
        )
        assert r.overall_status == "secure"
        assert r.schema_found is True

    def test_frozen(self) -> None:
        r = GraphQLAttackResult(
            target="t", host="h", port=443, tls=True,
            endpoint="", schema_found=False, types_count=0,
            queries_count=0, mutations_count=0,
            attempts=[], vulnerable_techniques=[], issues=[], overall_status="secure",
        )
        with pytest.raises(AttributeError):
            r.target = "changed"  # type: ignore[misc]


# ─── Category Map Tests ─────────────────────────────────────────────────────


class TestCategoryMap:
    def test_all_categories_present(self) -> None:
        expected = {
            "introspection", "depth_abuse", "batch_abuse", "alias_overload",
            "schema_stitching", "persisted_abuse", "resolver_analysis", "persisted_enum",
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
        html = 'GraphQL Playground loaded'
        assert _detect_tool(html) == "playground"

    def test_unknown(self) -> None:
        html = '<html><body>test</body></html>'
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
            target="https://target.com/graphql", host="target.com", port=443, tls=True,
            endpoint="https://target.com/graphql", schema_found=False,
            types_count=0, queries_count=0, mutations_count=0,
            attempts=[], vulnerable_techniques=[], issues=[], overall_status="secure",
        )
        print_results(r)
        output = capsys.readouterr().out
        assert "GraphQL Attack Testing" in output
        assert "SECURE" in output

    def test_vulnerable(self, capsys: pytest.CaptureFixture[str]) -> None:
        r = GraphQLAttackResult(
            target="https://target.com/graphql", host="target.com", port=443, tls=True,
            endpoint="https://target.com/graphql", schema_found=True,
            types_count=10, queries_count=1, mutations_count=0,
            attempts=[], vulnerable_techniques=["full_introspection"],
            issues=["Errors: test_error"], overall_status="vulnerable",
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
        args = parser.parse_args(["https://target.com/graphql", "-c", "introspection", "depth_abuse"])
        assert args.categories == ["introspection", "depth_abuse"]

    def test_build_parser_all_choices(self) -> None:
        parser = build_parser()
        for cat in _CATEGORY_MAP:
            args = parser.parse_args(["https://target.com/graphql", "-c", cat])
            assert args.categories == [cat]


# ─── Async Category Tests (Mocked) ──────────────────────────────────────────


@pytest.mark.asyncio
async def test_category_dispatch_all_return_lists() -> None:
    """All category dispatchers should return a list."""
    schema_info = {"types": ["User (OBJECT)"], "query_type": "Query", "mutation_type": "", "subscription_type": ""}
    for cat, fn in _CATEGORY_DISPATCH.items():
        result = await fn("target.com", 443, "/graphql", 5.0, True, "https://target.com/graphql", schema_info)
        assert isinstance(result, list), f"{cat} did not return a list"
        assert len(result) > 0, f"{cat} returned empty list"
        for attempt in result:
            assert isinstance(attempt, GraphQLAttackAttempt)
            assert attempt.category == cat
