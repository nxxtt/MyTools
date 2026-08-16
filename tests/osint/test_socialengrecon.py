#!/usr/bin/env python3
"""Testes unitarios do modulo de Social Engineering Recon."""

import asyncio
import runpy
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
import respx

from mytools.core.utils import RateLimiter
from mytools.osint.socialengrecon import (
    EmployeeInfo,
    _async_run_once,
    _dedup_employees,
    _extract_domain_name,
    _query_github,
    _query_hunter,
    _query_webpages,
    build_parser,
    main,
    print_results,
    run_once,
    scan_employees,
)

# ── Dataclass ────────────────────────────────────────────────────────────────


class TestEmployeeInfo:
    def test_frozen(self):
        e = EmployeeInfo(domain="x.com", name="A", email="a@x.com")
        with pytest.raises(AttributeError):
            e.name = "B"  # type: ignore[misc]

    def test_defaults(self):
        e = EmployeeInfo(domain="x.com")
        assert e.name == ""
        assert e.email == ""
        assert e.position == ""
        assert e.seniority == ""
        assert e.department == ""
        assert e.source == ""
        assert e.profile_url == ""

    def test_all_fields(self):
        e = EmployeeInfo(
            domain="x.com",
            name="John Doe",
            email="john@x.com",
            position="Engineer",
            seniority="senior",
            department="engineering",
            source="github",
            profile_url="https://github.com/john",
        )
        assert e.position == "Engineer"
        assert e.source == "github"


# ── _extract_domain_name ─────────────────────────────────────────────────────


class TestExtractDomainName:
    def test_two_parts(self):
        assert _extract_domain_name("example.com") == "example"

    def test_three_parts(self):
        assert _extract_domain_name("www.example.com") == "example"

    def test_single_part(self):
        assert _extract_domain_name("com") == "com"

    def test_co_uk(self):
        assert _extract_domain_name("example.co.uk") == "example"


# ── _dedup_employees ─────────────────────────────────────────────────────────


class TestDedupEmployees:
    def test_dedup_by_email(self):
        employees = [
            EmployeeInfo(domain="x.com", email="a@x.com", name="A"),
            EmployeeInfo(domain="x.com", email="a@x.com", name="B"),
        ]
        result = _dedup_employees(employees)
        assert len(result) == 1
        assert result[0].name == "A"

    def test_dedup_by_name(self):
        employees = [
            EmployeeInfo(domain="x.com", name="John Doe"),
            EmployeeInfo(domain="x.com", name="John Doe"),
        ]
        result = _dedup_employees(employees)
        assert len(result) == 1

    def test_different_names(self):
        employees = [
            EmployeeInfo(domain="x.com", name="John Doe"),
            EmployeeInfo(domain="x.com", name="Jane Smith"),
        ]
        result = _dedup_employees(employees)
        assert len(result) == 2

    def test_empty(self):
        assert _dedup_employees([]) == []

    def test_no_email_no_name(self):
        employees = [
            EmployeeInfo(domain="x.com"),
            EmployeeInfo(domain="x.com"),
        ]
        result = _dedup_employees(employees)
        assert len(result) == 2


# ── _query_github ─────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_github_found():
    repos_resp = [{"full_name": "example/repo1"}, {"full_name": "example/repo2"}]
    contrib_resp = [{"login": "john"}, {"login": "jane"}]
    user_resp = {
        "name": "John Doe",
        "email": "john@example.com",
        "bio": "",
        "company": "@Example",
        "html_url": "https://github.com/john",
    }

    with respx.mock:
        respx.route(method="GET", url__startswith="https://api.github.com/orgs/").mock(
            return_value=httpx.Response(200, json=repos_resp),
        )
        respx.route(
            method="GET",
            url="https://api.github.com/repos/example/repo1/contributors?per_page=30",
        ).mock(
            return_value=httpx.Response(200, json=contrib_resp),
        )
        respx.route(
            method="GET",
            url="https://api.github.com/repos/example/repo2/contributors?per_page=30",
        ).mock(
            return_value=httpx.Response(200, json=[]),
        )
        respx.route(method="GET", url="https://api.github.com/users/john").mock(
            return_value=httpx.Response(200, json=user_resp),
        )
        respx.route(method="GET", url="https://api.github.com/users/jane").mock(
            return_value=httpx.Response(
                200,
                json={
                    "name": "Jane Smith",
                    "email": "",
                    "bio": "",
                    "company": "",
                    "html_url": "",
                },
            ),
        )

        client = httpx.AsyncClient()
        rl = RateLimiter(0)
        emps = await _query_github(client, "example.com", 5.0, rl, max_results=10)
        await client.aclose()
        assert len(emps) >= 1
        assert any(e.email == "john@example.com" for e in emps)


@pytest.mark.asyncio
async def test_github_org_not_found():
    with respx.mock:
        respx.route(method="GET", url__startswith="https://api.github.com/orgs/").mock(
            return_value=httpx.Response(404),
        )
        client = httpx.AsyncClient()
        rl = RateLimiter(0)
        emps = await _query_github(client, "nonexistent99999.com", 5.0, rl)
        await client.aclose()
        assert emps == []


@pytest.mark.asyncio
async def test_github_error():
    with respx.mock:
        respx.route(method="GET", url__startswith="https://api.github.com/").mock(
            side_effect=httpx.ConnectError("refused"),
        )
        client = httpx.AsyncClient()
        rl = RateLimiter(0)
        emps = await _query_github(client, "example.com", 5.0, rl)
        await client.aclose()
        assert emps == []


# ── _query_hunter ─────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_hunter_found():
    resp = {
        "data": {
            "emails": [
                {
                    "first_name": "John",
                    "last_name": "Doe",
                    "value": "john@example.com",
                    "position": "Engineer",
                    "seniority": "senior",
                    "department": "engineering",
                },
            ]
        }
    }
    with respx.mock:
        respx.route(method="GET", url__startswith="https://api.hunter.io/").mock(
            return_value=httpx.Response(200, json=resp),
        )
        client = httpx.AsyncClient()
        rl = RateLimiter(0)
        emps = await _query_hunter(client, "example.com", "fake-key", 5.0, rl)
        await client.aclose()
        assert len(emps) == 1
        assert emps[0].email == "john@example.com"
        assert emps[0].source == "hunter"


@pytest.mark.asyncio
async def test_hunter_no_key():
    client = httpx.AsyncClient()
    rl = RateLimiter(0)
    emps = await _query_hunter(client, "example.com", "", 5.0, rl)
    await client.aclose()
    assert emps == []


@pytest.mark.asyncio
async def test_hunter_error():
    with respx.mock:
        respx.route(method="GET", url__startswith="https://api.hunter.io/").mock(
            side_effect=httpx.ConnectError("refused"),
        )
        client = httpx.AsyncClient()
        rl = RateLimiter(0)
        emps = await _query_hunter(client, "example.com", "fake-key", 5.0, rl)
        await client.aclose()
        assert emps == []


@pytest.mark.asyncio
async def test_hunter_no_emails():
    with respx.mock:
        respx.route(method="GET", url__startswith="https://api.hunter.io/").mock(
            return_value=httpx.Response(200, json={"data": {"emails": []}}),
        )
        client = httpx.AsyncClient()
        rl = RateLimiter(0)
        emps = await _query_hunter(client, "example.com", "fake-key", 5.0, rl)
        await client.aclose()
        assert emps == []


# ── _query_webpages ───────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_webpages_found():
    html = """
    <html><body>
    <h2>John Doe</h2><p>CEO</p>
    <h3>Jane Smith</h3><p>CTO</p>
    </body></html>
    """
    with respx.mock:
        respx.route(method="GET", url="https://example.com/about").mock(
            return_value=httpx.Response(200, text=html),
        )
        respx.route(method="GET", url__startswith="https://example.com/").mock(
            return_value=httpx.Response(404),
        )
        client = httpx.AsyncClient()
        rl = RateLimiter(0)
        emps = await _query_webpages(client, "example.com", 5.0, rl)
        await client.aclose()
        assert len(emps) >= 1
        assert any(e.name == "John Doe" for e in emps)


@pytest.mark.asyncio
async def test_webpages_no_team():
    with respx.mock:
        respx.route(method="GET", url__startswith="https://example.com/").mock(
            return_value=httpx.Response(404),
        )
        client = httpx.AsyncClient()
        rl = RateLimiter(0)
        emps = await _query_webpages(client, "example.com", 5.0, rl)
        await client.aclose()
        assert emps == []


@pytest.mark.asyncio
async def test_webpages_error():
    with respx.mock:
        respx.route(method="GET", url__startswith="https://example.com/").mock(
            side_effect=httpx.ConnectError("refused"),
        )
        client = httpx.AsyncClient()
        rl = RateLimiter(0)
        emps = await _query_webpages(client, "example.com", 5.0, rl)
        await client.aclose()
        assert emps == []


# ── build_parser ──────────────────────────────────────────────────────────────


@pytest.mark.smoke
class TestBuildParser:
    def test_has_domain(self):
        args = build_parser().parse_args(["example.com"])
        assert args.domain == "example.com"

    def test_has_list(self):
        args = build_parser().parse_args(["-l", "domains.txt"])
        assert args.target_list == "domains.txt"

    def test_has_source(self):
        args = build_parser().parse_args(["--source", "hunter"])
        assert args.sources == ["hunter"]

    def test_has_hunter_key(self):
        args = build_parser().parse_args(["--hunter-api-key", "abc123"])
        assert args.hunter_api_key == "abc123"

    def test_has_max_results(self):
        args = build_parser().parse_args(["--max-results", "100"])
        assert args.max_results == 100

    def test_default_sources(self):
        args = build_parser().parse_args([])
        assert args.sources is None


# ── print_results ─────────────────────────────────────────────────────────────


class TestPrintResults:
    def test_empty(self, capsys):
        print_results([])
        out = capsys.readouterr().out
        assert "Nenhum" in out

    def test_with_results(self, capsys):
        employees = [
            EmployeeInfo(
                domain="x.com",
                name="John Doe",
                email="john@x.com",
                position="Engineer",
                source="github",
            ),
        ]
        print_results(employees)
        out = capsys.readouterr().out
        assert "John Doe" in out
        assert "john@x.com" in out


# ── scan_employees (mock) ────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_scan_employees_github_only():
    repos_resp = [{"full_name": "example/repo1"}]
    contrib_resp = [{"login": "john"}]
    user_resp = {
        "name": "John",
        "email": "john@example.com",
        "bio": "",
        "company": "",
        "html_url": "",
    }

    with respx.mock:
        respx.route(method="GET", url__startswith="https://api.github.com/orgs/").mock(
            return_value=httpx.Response(200, json=repos_resp),
        )
        respx.route(
            method="GET",
            url="https://api.github.com/repos/example/repo1/contributors?per_page=30",
        ).mock(
            return_value=httpx.Response(200, json=contrib_resp),
        )
        respx.route(method="GET", url="https://api.github.com/users/john").mock(
            return_value=httpx.Response(200, json=user_resp),
        )

        employees = await scan_employees(
            domain="example.com",
            sources=["github"],
            api_keys={},
            timeout=5.0,
            user_agent="test/1.0",
        )
        assert any(e.email == "john@example.com" for e in employees)


@pytest.mark.asyncio
async def test_scan_employees_hunter_no_key():
    employees = await scan_employees(
        domain="example.com",
        sources=["hunter"],
        api_keys={},
        timeout=5.0,
        user_agent="test/1.0",
    )
    assert employees == []


@pytest.mark.asyncio
async def test_scan_employees_unknown_source():
    employees = await scan_employees(
        domain="example.com",
        sources=["unknown_source"],
        api_keys={},
        timeout=5.0,
        user_agent="test/1.0",
    )
    assert employees == []


# ── _query_github edge/error paths ───────────────────────────────────────────


class TestGithubEdges:
    @pytest.mark.asyncio
    @respx.mock
    async def test_repos_invalid_json(self):
        respx.get(url__startswith="https://api.github.com/orgs/").mock(
            return_value=httpx.Response(200, text="<not json>"),
        )
        client = httpx.AsyncClient()
        rl = RateLimiter(0)
        emps = await _query_github(client, "example.com", 5.0, rl)
        await client.aclose()
        assert emps == []

    @pytest.mark.asyncio
    @respx.mock
    async def test_repos_not_list(self):
        respx.get(url__startswith="https://api.github.com/orgs/").mock(
            return_value=httpx.Response(200, json={"a": 1}),
        )
        client = httpx.AsyncClient()
        rl = RateLimiter(0)
        emps = await _query_github(client, "example.com", 5.0, rl)
        await client.aclose()
        assert emps == []

    @pytest.mark.asyncio
    @respx.mock
    async def test_repo_not_dict_and_no_name(self):
        respx.get(url__startswith="https://api.github.com/orgs/").mock(
            return_value=httpx.Response(
                200,
                json=["bad", {"other": 1}, {"full_name": "example/repo1"}],
            ),
        )
        respx.get(url__startswith="https://api.github.com/repos/").mock(
            return_value=httpx.Response(200, json=[{"login": "john"}]),
        )
        respx.get(url__startswith="https://api.github.com/users/").mock(
            return_value=httpx.Response(
                200,
                json={
                    "name": "John",
                    "email": "john@example.com",
                    "bio": "",
                    "html_url": "",
                },
            ),
        )
        client = httpx.AsyncClient()
        rl = RateLimiter(0)
        emps = await _query_github(client, "example.com", 5.0, rl)
        await client.aclose()
        assert len(emps) == 1
        assert emps[0].name == "John"

    @pytest.mark.asyncio
    @respx.mock
    async def test_contributors_fetch_error(self):
        respx.get(url__startswith="https://api.github.com/orgs/").mock(
            return_value=httpx.Response(200, json=[{"full_name": "example/repo1"}]),
        )
        respx.get(url__startswith="https://api.github.com/repos/").mock(
            side_effect=httpx.ConnectError("refused"),
        )
        client = httpx.AsyncClient()
        rl = RateLimiter(0)
        emps = await _query_github(client, "example.com", 5.0, rl)
        await client.aclose()
        assert emps == []

    @pytest.mark.asyncio
    @respx.mock
    async def test_contributors_non_200(self):
        respx.get(url__startswith="https://api.github.com/orgs/").mock(
            return_value=httpx.Response(200, json=[{"full_name": "example/repo1"}]),
        )
        respx.get(url__startswith="https://api.github.com/repos/").mock(
            return_value=httpx.Response(500),
        )
        client = httpx.AsyncClient()
        rl = RateLimiter(0)
        emps = await _query_github(client, "example.com", 5.0, rl)
        await client.aclose()
        assert emps == []

    @pytest.mark.asyncio
    @respx.mock
    async def test_contributors_invalid_json(self):
        respx.get(url__startswith="https://api.github.com/orgs/").mock(
            return_value=httpx.Response(200, json=[{"full_name": "example/repo1"}]),
        )
        respx.get(url__startswith="https://api.github.com/repos/").mock(
            return_value=httpx.Response(200, text="<not json>"),
        )
        client = httpx.AsyncClient()
        rl = RateLimiter(0)
        emps = await _query_github(client, "example.com", 5.0, rl)
        await client.aclose()
        assert emps == []

    @pytest.mark.asyncio
    @respx.mock
    async def test_contributors_not_list(self):
        respx.get(url__startswith="https://api.github.com/orgs/").mock(
            return_value=httpx.Response(200, json=[{"full_name": "example/repo1"}]),
        )
        respx.get(url__startswith="https://api.github.com/repos/").mock(
            return_value=httpx.Response(200, json={"a": 1}),
        )
        client = httpx.AsyncClient()
        rl = RateLimiter(0)
        emps = await _query_github(client, "example.com", 5.0, rl)
        await client.aclose()
        assert emps == []

    @pytest.mark.asyncio
    @respx.mock
    async def test_contrib_not_dict(self):
        respx.get(url__startswith="https://api.github.com/orgs/").mock(
            return_value=httpx.Response(200, json=[{"full_name": "example/repo1"}]),
        )
        respx.get(url__startswith="https://api.github.com/repos/").mock(
            return_value=httpx.Response(200, json=[42]),
        )
        client = httpx.AsyncClient()
        rl = RateLimiter(0)
        emps = await _query_github(client, "example.com", 5.0, rl)
        await client.aclose()
        assert emps == []

    @pytest.mark.asyncio
    @respx.mock
    async def test_user_fetch_error(self):
        respx.get(url__startswith="https://api.github.com/orgs/").mock(
            return_value=httpx.Response(200, json=[{"full_name": "example/repo1"}]),
        )
        respx.get(url__startswith="https://api.github.com/repos/").mock(
            return_value=httpx.Response(200, json=[{"login": "john"}]),
        )
        respx.get(url__startswith="https://api.github.com/users/").mock(
            side_effect=httpx.ConnectError("refused"),
        )
        client = httpx.AsyncClient()
        rl = RateLimiter(0)
        emps = await _query_github(client, "example.com", 5.0, rl)
        await client.aclose()
        assert emps == []

    @pytest.mark.asyncio
    @respx.mock
    async def test_user_non_200(self):
        respx.get(url__startswith="https://api.github.com/orgs/").mock(
            return_value=httpx.Response(200, json=[{"full_name": "example/repo1"}]),
        )
        respx.get(url__startswith="https://api.github.com/repos/").mock(
            return_value=httpx.Response(200, json=[{"login": "john"}]),
        )
        respx.get(url__startswith="https://api.github.com/users/").mock(
            return_value=httpx.Response(500),
        )
        client = httpx.AsyncClient()
        rl = RateLimiter(0)
        emps = await _query_github(client, "example.com", 5.0, rl)
        await client.aclose()
        assert emps == []

    @pytest.mark.asyncio
    @respx.mock
    async def test_user_invalid_json(self):
        respx.get(url__startswith="https://api.github.com/orgs/").mock(
            return_value=httpx.Response(200, json=[{"full_name": "example/repo1"}]),
        )
        respx.get(url__startswith="https://api.github.com/repos/").mock(
            return_value=httpx.Response(200, json=[{"login": "john"}]),
        )
        respx.get(url__startswith="https://api.github.com/users/").mock(
            return_value=httpx.Response(200, text="<not json>"),
        )
        client = httpx.AsyncClient()
        rl = RateLimiter(0)
        emps = await _query_github(client, "example.com", 5.0, rl)
        await client.aclose()
        assert emps == []

    @pytest.mark.asyncio
    @respx.mock
    async def test_user_not_dict(self):
        respx.get(url__startswith="https://api.github.com/orgs/").mock(
            return_value=httpx.Response(200, json=[{"full_name": "example/repo1"}]),
        )
        respx.get(url__startswith="https://api.github.com/repos/").mock(
            return_value=httpx.Response(200, json=[{"login": "john"}]),
        )
        respx.get(url__startswith="https://api.github.com/users/").mock(
            return_value=httpx.Response(200, json=[1, 2]),
        )
        client = httpx.AsyncClient()
        rl = RateLimiter(0)
        emps = await _query_github(client, "example.com", 5.0, rl)
        await client.aclose()
        assert emps == []

    @pytest.mark.asyncio
    @respx.mock
    async def test_duplicate_login_skipped(self):
        respx.get(url__startswith="https://api.github.com/orgs/").mock(
            return_value=httpx.Response(200, json=[{"full_name": "example/repo1"}]),
        )
        respx.get(url__startswith="https://api.github.com/repos/").mock(
            return_value=httpx.Response(
                200, json=[{"login": "john"}, {"login": "john"}]
            ),
        )
        respx.get(url__startswith="https://api.github.com/users/").mock(
            return_value=httpx.Response(
                200,
                json={
                    "name": "John",
                    "email": "john@example.com",
                    "bio": "",
                    "html_url": "",
                },
            ),
        )
        client = httpx.AsyncClient()
        rl = RateLimiter(0)
        emps = await _query_github(client, "example.com", 5.0, rl)
        await client.aclose()
        assert len(emps) == 1

    @pytest.mark.asyncio
    @respx.mock
    async def test_bio_no_separator(self):
        respx.get(url__startswith="https://api.github.com/orgs/").mock(
            return_value=httpx.Response(200, json=[{"full_name": "example/repo1"}]),
        )
        respx.get(url__startswith="https://api.github.com/repos/").mock(
            return_value=httpx.Response(200, json=[{"login": "john"}]),
        )
        respx.get(url__startswith="https://api.github.com/users/").mock(
            return_value=httpx.Response(
                200,
                json={
                    "name": "John",
                    "email": "john@example.com",
                    "bio": "Independent Developer",
                    "html_url": "",
                },
            ),
        )
        client = httpx.AsyncClient()
        rl = RateLimiter(0)
        emps = await _query_github(client, "example.com", 5.0, rl)
        await client.aclose()
        assert len(emps) == 1
        assert emps[0].position == ""

    @pytest.mark.asyncio
    @respx.mock
    async def test_bio_sep_case_mismatch(self):
        respx.get(url__startswith="https://api.github.com/orgs/").mock(
            return_value=httpx.Response(200, json=[{"full_name": "example/repo1"}]),
        )
        respx.get(url__startswith="https://api.github.com/repos/").mock(
            return_value=httpx.Response(200, json=[{"login": "john"}]),
        )
        respx.get(url__startswith="https://api.github.com/users/").mock(
            return_value=httpx.Response(
                200,
                json={
                    "name": "John",
                    "email": "john@example.com",
                    "bio": "John At Example",
                    "html_url": "",
                },
            ),
        )
        client = httpx.AsyncClient()
        rl = RateLimiter(0)
        emps = await _query_github(client, "example.com", 5.0, rl)
        await client.aclose()
        assert len(emps) == 1
        assert emps[0].position == ""

    @pytest.mark.asyncio
    @respx.mock
    async def test_user_no_name_email(self):
        respx.get(url__startswith="https://api.github.com/orgs/").mock(
            return_value=httpx.Response(200, json=[{"full_name": "example/repo1"}]),
        )
        respx.get(url__startswith="https://api.github.com/repos/").mock(
            return_value=httpx.Response(200, json=[{"login": "ghost"}]),
        )
        respx.get(url__startswith="https://api.github.com/users/").mock(
            return_value=httpx.Response(
                200,
                json={"name": "", "email": "", "bio": "", "html_url": ""},
            ),
        )
        client = httpx.AsyncClient()
        rl = RateLimiter(0)
        emps = await _query_github(client, "example.com", 5.0, rl)
        await client.aclose()
        assert emps == []

    @pytest.mark.asyncio
    @respx.mock
    async def test_bio_position(self):
        respx.get(url__startswith="https://api.github.com/orgs/").mock(
            return_value=httpx.Response(200, json=[{"full_name": "example/repo1"}]),
        )
        respx.get(url__startswith="https://api.github.com/repos/").mock(
            return_value=httpx.Response(200, json=[{"login": "john"}]),
        )
        respx.get(url__startswith="https://api.github.com/users/").mock(
            return_value=httpx.Response(
                200,
                json={
                    "name": "John",
                    "email": "",
                    "bio": "Software Engineer at Example Corp",
                    "html_url": "",
                },
            ),
        )
        client = httpx.AsyncClient()
        rl = RateLimiter(0)
        emps = await _query_github(client, "example.com", 5.0, rl)
        await client.aclose()
        assert any("Example Corp" in e.position for e in emps)

    @pytest.mark.asyncio
    @respx.mock
    async def test_max_results_repo_break(self):
        respx.get(url__startswith="https://api.github.com/orgs/").mock(
            return_value=httpx.Response(
                200,
                json=[{"full_name": "example/repo1"}, {"full_name": "example/repo2"}],
            ),
        )
        respx.get(url__startswith="https://api.github.com/repos/").mock(
            return_value=httpx.Response(200, json=[{"login": "john"}]),
        )
        respx.get(url__startswith="https://api.github.com/users/").mock(
            return_value=httpx.Response(
                200,
                json={
                    "name": "John",
                    "email": "john@example.com",
                    "bio": "",
                    "html_url": "",
                },
            ),
        )
        client = httpx.AsyncClient()
        rl = RateLimiter(0)
        emps = await _query_github(client, "example.com", 5.0, rl, max_results=1)
        await client.aclose()
        assert len(emps) == 1

    @pytest.mark.asyncio
    @respx.mock
    async def test_max_results_contrib_break(self):
        respx.get(url__startswith="https://api.github.com/orgs/").mock(
            return_value=httpx.Response(200, json=[{"full_name": "example/repo1"}]),
        )
        respx.get(url__startswith="https://api.github.com/repos/").mock(
            return_value=httpx.Response(
                200,
                json=[{"login": "john"}, {"login": "jane"}],
            ),
        )
        respx.get(url__startswith="https://api.github.com/users/").mock(
            return_value=httpx.Response(
                200,
                json={
                    "name": "John",
                    "email": "john@example.com",
                    "bio": "",
                    "html_url": "",
                },
            ),
        )
        client = httpx.AsyncClient()
        rl = RateLimiter(0)
        emps = await _query_github(client, "example.com", 5.0, rl, max_results=1)
        await client.aclose()
        assert len(emps) == 1

    @pytest.mark.asyncio
    @respx.mock
    async def test_repo_loop_break_between_repos(self):
        respx.get(url__startswith="https://api.github.com/orgs/").mock(
            return_value=httpx.Response(
                200,
                json=[{"full_name": "example/repo1"}, {"full_name": "example/repo2"}],
            ),
        )
        respx.get(url__startswith="https://api.github.com/repos/").mock(
            return_value=httpx.Response(
                200,
                json=[{"login": "john"}, {"login": "jane"}],
            ),
        )
        respx.get(url__startswith="https://api.github.com/users/").mock(
            return_value=httpx.Response(
                200,
                json={
                    "name": "John",
                    "email": "john@example.com",
                    "bio": "",
                    "html_url": "",
                },
            ),
        )
        client = httpx.AsyncClient()
        rl = RateLimiter(0)
        emps = await _query_github(client, "example.com", 5.0, rl, max_results=2)
        await client.aclose()
        assert len(emps) == 2


# ── _query_hunter edge/error paths ───────────────────────────────────────────


class TestHunterEdges:
    @pytest.mark.asyncio
    @respx.mock
    async def test_non_200(self):
        respx.get(url__startswith="https://api.hunter.io/").mock(
            return_value=httpx.Response(500),
        )
        client = httpx.AsyncClient()
        rl = RateLimiter(0)
        emps = await _query_hunter(client, "example.com", "key", 5.0, rl)
        await client.aclose()
        assert emps == []

    @pytest.mark.asyncio
    @respx.mock
    async def test_invalid_json(self):
        respx.get(url__startswith="https://api.hunter.io/").mock(
            return_value=httpx.Response(200, text="<not json>"),
        )
        client = httpx.AsyncClient()
        rl = RateLimiter(0)
        emps = await _query_hunter(client, "example.com", "key", 5.0, rl)
        await client.aclose()
        assert emps == []

    @pytest.mark.asyncio
    @respx.mock
    async def test_emails_not_list(self):
        respx.get(url__startswith="https://api.hunter.io/").mock(
            return_value=httpx.Response(200, json={"data": {"emails": {"a": 1}}}),
        )
        client = httpx.AsyncClient()
        rl = RateLimiter(0)
        emps = await _query_hunter(client, "example.com", "key", 5.0, rl)
        await client.aclose()
        assert emps == []

    @pytest.mark.asyncio
    @respx.mock
    async def test_data_null(self):
        respx.get(url__startswith="https://api.hunter.io/").mock(
            return_value=httpx.Response(200, json={"data": None}),
        )
        client = httpx.AsyncClient()
        rl = RateLimiter(0)
        emps = await _query_hunter(client, "example.com", "key", 5.0, rl)
        await client.aclose()
        assert emps == []

    @pytest.mark.asyncio
    @respx.mock
    async def test_item_not_dict(self):
        respx.get(url__startswith="https://api.hunter.io/").mock(
            return_value=httpx.Response(200, json={"data": {"emails": [42]}}),
        )
        client = httpx.AsyncClient()
        rl = RateLimiter(0)
        emps = await _query_hunter(client, "example.com", "key", 5.0, rl)
        await client.aclose()
        assert emps == []


# ── _query_webpages edge paths ───────────────────────────────────────────────


class TestWebpagesEdges:
    @pytest.mark.asyncio
    @respx.mock
    async def test_filters(self):
        html = """
        <h2>John Doe</h2><p>CEO</p>
        <h3>Phone 12345</h3><p>CTO</p>
        <h3>abc</h3><p>CEO</p>
        <h3>a</h3><p>CEO</p>
        <h3></h3><p>CEO</p>
        <h2>Jane Smith</h2><p>random text no keyword</p>
        """
        respx.get(url__startswith="https://example.com/").mock(
            return_value=httpx.Response(200, text=html),
        )
        client = httpx.AsyncClient()
        rl = RateLimiter(0)
        emps = await _query_webpages(client, "example.com", 5.0, rl)
        await client.aclose()
        names = {e.name for e in emps}
        assert "John Doe" in names
        assert "Jane Smith" in names
        assert all(e.position == "CEO" or e.position == "" for e in emps)

    @pytest.mark.asyncio
    @respx.mock
    async def test_max_results_break(self):
        html = "<h2>John Doe</h2><p>CEO</p>"
        respx.get(url__startswith="https://example.com/").mock(
            return_value=httpx.Response(200, text=html),
        )
        client = httpx.AsyncClient()
        rl = RateLimiter(0)
        emps = await _query_webpages(client, "example.com", 5.0, rl, max_results=1)
        await client.aclose()
        assert len(emps) == 1

    @pytest.mark.asyncio
    @respx.mock
    async def test_lowercase_name_and_no_sibling(self):
        html = """
        <h2>john smith</h2><p>CEO</p>
        <h3>John Doe</h3>
        """
        respx.get(url="https://example.com/about").mock(
            return_value=httpx.Response(200, text=html),
        )
        respx.get(url__startswith="https://example.com/").mock(
            return_value=httpx.Response(404),
        )
        client = httpx.AsyncClient()
        rl = RateLimiter(0)
        emps = await _query_webpages(client, "example.com", 5.0, rl)
        await client.aclose()
        assert len(emps) == 1
        assert emps[0].name == "John Doe"
        assert emps[0].position == ""


# ── scan_employees com fonte web ─────────────────────────────────────────────


@pytest.mark.asyncio
@respx.mock
async def test_scan_employees_web_source():
    html = "<h2>John Doe</h2><p>CEO</p>"
    respx.get(url__startswith="https://example.com/").mock(
        return_value=httpx.Response(200, text=html),
    )
    employees = await scan_employees(
        domain="example.com",
        sources=["web"],
        api_keys={},
        timeout=5.0,
        user_agent="test/1.0",
    )
    assert any(e.source == "web" for e in employees)


# ── run_once / _async_run_once / main ────────────────────────────────────────


class TestRunOnce:
    def test_run_once(self):
        args = build_parser().parse_args(["example.com"])
        with (
            patch(
                "mytools.osint.socialengrecon._async_run_once",
                new_callable=MagicMock,
                return_value=0,
            ),
            patch(
                "mytools.osint.socialengrecon.safe_asyncio_run",
                new_callable=MagicMock,
                return_value=0,
            ) as mock_safe,
        ):
            result = run_once(args)
            assert result == 0
        mock_safe.assert_called_once()


class TestAsyncRunOnce:
    def test_dry_run(self):
        args = build_parser().parse_args(["example.com", "--dry-run"])
        result = asyncio.run(_async_run_once(args))
        assert result == 0

    def test_hunter_without_key(self):
        args = build_parser().parse_args(["example.com", "--source", "hunter"])
        with patch(
            "mytools.osint.socialengrecon.scan_employees",
            new=AsyncMock(return_value=[]),
        ):
            result = asyncio.run(_async_run_once(args))
        assert result == 0

    def test_print_results_path(self):
        emp = EmployeeInfo(domain="example.com", name="John Doe", source="github")
        args = build_parser().parse_args(["example.com"])
        with patch(
            "mytools.osint.socialengrecon.scan_employees",
            new=AsyncMock(return_value=[emp]),
        ):
            result = asyncio.run(_async_run_once(args))
        assert result == 0

    def test_output_flag(self, tmp_path):
        out_file = tmp_path / "out.json"
        args = build_parser().parse_args(["example.com", "-o", str(out_file)])
        with (
            patch(
                "mytools.osint.socialengrecon.scan_employees",
                new=AsyncMock(return_value=[]),
            ),
            patch("mytools.osint.socialengrecon.write_output") as mock_write,
        ):
            result = asyncio.run(_async_run_once(args))
        assert result == 0
        mock_write.assert_called_once()

    def test_quiet_skips_print(self, tmp_path):
        out_file = tmp_path / "out.json"
        args = build_parser().parse_args(["example.com", "-q", "-o", str(out_file)])
        with (
            patch(
                "mytools.osint.socialengrecon.scan_employees",
                new=AsyncMock(return_value=[]),
            ),
            patch("mytools.osint.socialengrecon.print_results") as mock_print,
            patch("mytools.osint.socialengrecon.write_output") as mock_write,
        ):
            result = asyncio.run(_async_run_once(args))
        assert result == 0
        mock_print.assert_not_called()
        mock_write.assert_called_once()

    def test_missing_target_returns_1(self):
        args = build_parser().parse_args([])
        result = asyncio.run(_async_run_once(args))
        assert result == 1

    def test_list_file_multiple_domains(self, tmp_path):
        lst = tmp_path / "domains.txt"
        lst.write_text("one.com\ntwo.com\n", encoding="utf-8")
        args = build_parser().parse_args(["-l", str(lst)])
        emp = EmployeeInfo(domain="one.com", name="John", source="github")
        with (
            patch(
                "mytools.osint.socialengrecon.scan_employees",
                new=AsyncMock(return_value=[emp]),
            ) as mock_scan,
            patch("mytools.osint.socialengrecon.print_results"),
        ):
            result = asyncio.run(_async_run_once(args))
        assert result == 0
        assert mock_scan.call_count == 2
        assert mock_scan.call_args_list[0].kwargs["domain"] == "one.com"
        assert mock_scan.call_args_list[1].kwargs["domain"] == "two.com"

    def test_list_file_missing_returns_1(self, tmp_path):
        args = build_parser().parse_args(["-l", str(tmp_path / "nope.txt")])
        result = asyncio.run(_async_run_once(args))
        assert result == 1

    def test_list_file_dry_run(self, tmp_path):
        lst = tmp_path / "domains.txt"
        lst.write_text("one.com\ntwo.com\n", encoding="utf-8")
        args = build_parser().parse_args(["-l", str(lst), "--dry-run"])
        result = asyncio.run(_async_run_once(args))
        assert result == 0

    def test_json_output_flag(self):
        emp = EmployeeInfo(domain="example.com", name="John", source="github")
        args = build_parser().parse_args(["example.com", "--json"])
        with (
            patch(
                "mytools.osint.socialengrecon.scan_employees",
                new=AsyncMock(return_value=[emp]),
            ),
            patch("mytools.osint.socialengrecon.print_json") as mock_json,
            patch("mytools.osint.socialengrecon.print_results") as mock_print,
        ):
            result = asyncio.run(_async_run_once(args))
        assert result == 0
        mock_json.assert_called_once()
        mock_print.assert_not_called()

    def test_output_dir_flag(self, tmp_path):
        emp = EmployeeInfo(domain="example.com", name="John", source="github")
        out_dir = tmp_path / "out"
        args = build_parser().parse_args(["example.com", "--output-dir", str(out_dir)])
        with (
            patch(
                "mytools.osint.socialengrecon.scan_employees",
                new=AsyncMock(return_value=[emp]),
            ),
            patch("mytools.osint.socialengrecon.write_output") as mock_write,
        ):
            result = asyncio.run(_async_run_once(args))
        assert result == 0
        mock_write.assert_called_once()
        assert out_dir.is_dir()


class TestMain:
    def test_main(self):
        with patch(
            "mytools.osint.socialengrecon.run_main_loop", return_value=0
        ) as mock_loop:
            assert main() == 0
        mock_loop.assert_called_once()

    def test_main_guard(self):
        with (
            patch("mytools.core.utils.run_main_loop", side_effect=SystemExit(0)),
            patch("sys.argv", ["mytools-soceng", "example.com"]),
            pytest.raises(SystemExit),
        ):
            runpy.run_module("mytools.osint.socialengrecon", run_name="__main__")
