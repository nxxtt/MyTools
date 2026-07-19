#!/usr/bin/env python3
"""Testes unitarios do modulo de Email Breach Check."""
import httpx
import pytest
import respx

from mytools.core.utils import RateLimiter
from mytools.osint.emailbreachcheck import (
    EmailBreach,
    _classify_severity,
    _dedup_breaches,
    _load_emails,
    _query_email,
    _query_hibp,
    _query_leakcheck,
    _query_xposedornot,
    build_parser,
    check_breaches,
    print_results,
)

# ── Dataclass ────────────────────────────────────────────────────────────────


class TestEmailBreach:
    def test_frozen(self):
        b = EmailBreach(email="a@b.com", breach_name="X")
        with pytest.raises(AttributeError):
            b.email = "c"  # type: ignore[misc]

    def test_defaults(self):
        b = EmailBreach(email="a@b.com", breach_name="X")
        assert b.breach_date == ""
        assert b.pwn_count == 0
        assert b.data_classes == ""
        assert b.source == ""

    def test_all_fields(self):
        b = EmailBreach(
            email="a@b.com", breach_name="LinkedIn", breach_date="2012-05-05",
            pwn_count=164000000, data_classes="passwords,emails", source="hibp",
        )
        assert b.pwn_count == 164000000
        assert b.source == "hibp"


# ── _classify_severity ───────────────────────────────────────────────────────


class TestClassifySeverity:
    def test_low(self):
        assert _classify_severity(1, "") == "low"

    def test_medium(self):
        assert _classify_severity(2, "") == "medium"

    def test_high(self):
        assert _classify_severity(5, "") == "high"

    def test_critical_count(self):
        assert _classify_severity(10, "") == "critical"

    def test_critical_passwords(self):
        assert _classify_severity(1, "passwords,emails") == "critical"

    def test_critical_creditcards(self):
        assert _classify_severity(1, "creditcards") == "critical"

    def test_no_sensitive(self):
        assert _classify_severity(1, "emails,usernames") == "low"


# ── _dedup_breaches ──────────────────────────────────────────────────────────


class TestDedupBreaches:
    def test_no_duplicates(self):
        breaches = [
            EmailBreach(email="a@b.com", breach_name="X", source="a"),
            EmailBreach(email="a@b.com", breach_name="Y", source="b"),
        ]
        result = _dedup_breaches(breaches)
        assert len(result) == 2

    def test_with_duplicates(self):
        breaches = [
            EmailBreach(email="a@b.com", breach_name="X", source="a"),
            EmailBreach(email="a@b.com", breach_name="X", source="b"),
        ]
        result = _dedup_breaches(breaches)
        assert len(result) == 1
        assert result[0].source == "a"

    def test_case_insensitive(self):
        breaches = [
            EmailBreach(email="A@B.com", breach_name="X", source="a"),
            EmailBreach(email="a@b.com", breach_name="x", source="b"),
        ]
        result = _dedup_breaches(breaches)
        assert len(result) == 1

    def test_different_emails_same_breach(self):
        breaches = [
            EmailBreach(email="a@b.com", breach_name="X", source="a"),
            EmailBreach(email="c@d.com", breach_name="X", source="a"),
        ]
        result = _dedup_breaches(breaches)
        assert len(result) == 2

    def test_empty(self):
        assert _dedup_breaches([]) == []


# ── _query_xposedornot ──────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_xposedornot_breach_found():
    with respx.mock:
        respx.route(method="GET", url__startswith="https://api.xposedornot.com/").mock(
            return_value=httpx.Response(200, json={"breaches": ["LinkedIn", "Adobe"]}),
        )
        client = httpx.AsyncClient()
        rl = RateLimiter(0)
        breaches = await _query_xposedornot(client, "test@test.com", 5.0, rl)
        await client.aclose()
        assert len(breaches) == 2
        assert breaches[0].breach_name == "LinkedIn"
        assert breaches[0].source == "xposedornot"


@pytest.mark.asyncio
async def test_xposedornot_no_breaches():
    with respx.mock:
        respx.route(method="GET", url__startswith="https://api.xposedornot.com/").mock(
            return_value=httpx.Response(200, json={"breaches": []}),
        )
        client = httpx.AsyncClient()
        rl = RateLimiter(0)
        breaches = await _query_xposedornot(client, "test@test.com", 5.0, rl)
        await client.aclose()
        assert breaches == []


@pytest.mark.asyncio
async def test_xposedornot_dict_breaches():
    with respx.mock:
        respx.route(method="GET", url__startswith="https://api.xposedornot.com/").mock(
            return_value=httpx.Response(200, json={"breaches": {"LinkedIn": {}, "Adobe": {}}}),
        )
        client = httpx.AsyncClient()
        rl = RateLimiter(0)
        breaches = await _query_xposedornot(client, "test@test.com", 5.0, rl)
        await client.aclose()
        assert len(breaches) == 2


@pytest.mark.asyncio
async def test_xposedornot_error():
    with respx.mock:
        respx.route(method="GET", url__startswith="https://api.xposedornot.com/").mock(
            side_effect=httpx.ConnectError("refused"),
        )
        client = httpx.AsyncClient()
        rl = RateLimiter(0)
        breaches = await _query_xposedornot(client, "test@test.com", 5.0, rl)
        await client.aclose()
        assert breaches == []


@pytest.mark.asyncio
async def test_xposedornot_non_200():
    with respx.mock:
        respx.route(method="GET", url__startswith="https://api.xposedornot.com/").mock(
            return_value=httpx.Response(500),
        )
        client = httpx.AsyncClient()
        rl = RateLimiter(0)
        breaches = await _query_xposedornot(client, "test@test.com", 5.0, rl)
        await client.aclose()
        assert breaches == []


# ── _query_leakcheck ─────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_leakcheck_breach_found():
    with respx.mock:
        respx.route(method="GET", url__startswith="https://leakcheck.io/").mock(
            return_value=httpx.Response(200, json={
                "success": True, "found": 2,
                "sources": [{"name": "LinkedIn", "date": "2012"}, {"name": "Adobe", "date": "2013"}],
            }),
        )
        client = httpx.AsyncClient()
        rl = RateLimiter(0)
        breaches = await _query_leakcheck(client, "test@test.com", 5.0, rl)
        await client.aclose()
        assert len(breaches) == 2
        assert breaches[0].source == "leakcheck"


@pytest.mark.asyncio
async def test_leakcheck_no_breaches():
    with respx.mock:
        respx.route(method="GET", url__startswith="https://leakcheck.io/").mock(
            return_value=httpx.Response(200, json={"success": True, "found": 0}),
        )
        client = httpx.AsyncClient()
        rl = RateLimiter(0)
        breaches = await _query_leakcheck(client, "test@test.com", 5.0, rl)
        await client.aclose()
        assert breaches == []


@pytest.mark.asyncio
async def test_leakcheck_string_sources():
    with respx.mock:
        respx.route(method="GET", url__startswith="https://leakcheck.io/").mock(
            return_value=httpx.Response(200, json={
                "success": True, "found": 1, "sources": ["LinkedIn"],
            }),
        )
        client = httpx.AsyncClient()
        rl = RateLimiter(0)
        breaches = await _query_leakcheck(client, "test@test.com", 5.0, rl)
        await client.aclose()
        assert len(breaches) == 1
        assert breaches[0].breach_name == "LinkedIn"


@pytest.mark.asyncio
async def test_leakcheck_error():
    with respx.mock:
        respx.route(method="GET", url__startswith="https://leakcheck.io/").mock(
            side_effect=httpx.ConnectError("refused"),
        )
        client = httpx.AsyncClient()
        rl = RateLimiter(0)
        breaches = await _query_leakcheck(client, "test@test.com", 5.0, rl)
        await client.aclose()
        assert breaches == []


# ── _query_hibp ──────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_hibp_breach_found():
    with respx.mock:
        respx.route(method="GET", url__startswith="https://haveibeenpwned.com/").mock(
            return_value=httpx.Response(200, json=[
                {"Name": "LinkedIn", "BreachDate": "2012-05-05", "PwnCount": 164000000, "DataClasses": ["passwords", "emails"]},
            ]),
        )
        client = httpx.AsyncClient()
        rl = RateLimiter(0)
        breaches = await _query_hibp(client, "test@test.com", "fake-key", 5.0, rl)
        await client.aclose()
        assert len(breaches) == 1
        assert breaches[0].breach_name == "LinkedIn"
        assert breaches[0].pwn_count == 164000000
        assert breaches[0].source == "hibp"


@pytest.mark.asyncio
async def test_hibp_404_not_found():
    with respx.mock:
        respx.route(method="GET", url__startswith="https://haveibeenpwned.com/").mock(
            return_value=httpx.Response(404),
        )
        client = httpx.AsyncClient()
        rl = RateLimiter(0)
        breaches = await _query_hibp(client, "test@test.com", "fake-key", 5.0, rl)
        await client.aclose()
        assert breaches == []


@pytest.mark.asyncio
async def test_hibp_no_api_key():
    client = httpx.AsyncClient()
    rl = RateLimiter(0)
    breaches = await _query_hibp(client, "test@test.com", "", 5.0, rl)
    await client.aclose()
    assert breaches == []


@pytest.mark.asyncio
async def test_hibp_error():
    with respx.mock:
        respx.route(method="GET", url__startswith="https://haveibeenpwned.com/").mock(
            side_effect=httpx.ConnectError("refused"),
        )
        client = httpx.AsyncClient()
        rl = RateLimiter(0)
        breaches = await _query_hibp(client, "test@test.com", "fake-key", 5.0, rl)
        await client.aclose()
        assert breaches == []


# ── _query_email ──────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_query_email_multiple_sources():
    with respx.mock:
        respx.route(method="GET", url__startswith="https://api.xposedornot.com/").mock(
            return_value=httpx.Response(200, json={"breaches": ["LinkedIn"]}),
        )
        respx.route(method="GET", url__startswith="https://leakcheck.io/").mock(
            return_value=httpx.Response(200, json={"success": True, "found": 1, "sources": [{"name": "LinkedIn"}]}),
        )
        client = httpx.AsyncClient()
        rl = RateLimiter(0)
        breaches = await _query_email(client, "test@test.com", ["xposedornot", "leakcheck"], {}, 5.0, rl)
        await client.aclose()
        names = {b.breach_name for b in breaches}
        assert "LinkedIn" in names


# ── build_parser ──────────────────────────────────────────────────────────────


@pytest.mark.smoke
class TestBuildParser:
    def test_has_emails(self):
        args = build_parser().parse_args(["a@b.com"])
        assert args.emails == ["a@b.com"]

    def test_has_file(self):
        args = build_parser().parse_args(["-f", "emails.txt"])
        assert args.email_file == "emails.txt"

    def test_has_source(self):
        args = build_parser().parse_args(["--source", "hibp"])
        assert args.sources == ["hibp"]

    def test_has_hibp_key(self):
        args = build_parser().parse_args(["--hibp-api-key", "abc123"])
        assert args.hibp_api_key == "abc123"

    def test_default_sources(self):
        args = build_parser().parse_args([])
        assert args.sources is None

    def test_multiple_sources(self):
        args = build_parser().parse_args(["--source", "xposedornot", "--source", "hibp"])
        assert args.sources == ["xposedornot", "hibp"]


# ── _load_emails ─────────────────────────────────────────────────────────────


class TestLoadEmails:
    def test_from_args(self):
        args = build_parser().parse_args(["a@b.com", "c@d.com"])
        emails = _load_emails(args)
        assert emails == ["a@b.com", "c@d.com"]

    def test_dedup(self):
        args = build_parser().parse_args(["a@b.com", "a@b.com"])
        emails = _load_emails(args)
        assert emails == ["a@b.com"]

    def test_empty(self):
        args = build_parser().parse_args([])
        emails = _load_emails(args)
        assert emails == []


# ── print_results ─────────────────────────────────────────────────────────────


class TestPrintResults:
    def test_empty(self, capsys):
        print_results([])
        out = capsys.readouterr().out
        assert "Nenhum" in out

    def test_with_results(self, capsys):
        breaches = [
            EmailBreach(email="a@b.com", breach_name="LinkedIn", source="hibp"),
        ]
        print_results(breaches)
        out = capsys.readouterr().out
        assert "LinkedIn" in out
        assert "a@b.com" in out


# ── check_breaches (mock) ────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_check_breaches_xposedornot():
    with respx.mock:
        respx.route(method="GET", url__startswith="https://api.xposedornot.com/").mock(
            return_value=httpx.Response(200, json={"breaches": ["Adobe"]}),
        )
        breaches = await check_breaches(
            emails=["test@test.com"],
            sources=["xposedornot"],
            api_keys={},
            timeout=5.0,
            concurrency=3,
            user_agent="test/1.0",
        )
        assert len(breaches) == 1
        assert breaches[0].breach_name == "Adobe"


@pytest.mark.asyncio
async def test_check_breaches_no_results():
    with respx.mock:
        respx.route(method="GET", url__startswith="https://api.xposedornot.com/").mock(
            return_value=httpx.Response(200, json={"breaches": []}),
        )
        breaches = await check_breaches(
            emails=["test@test.com"],
            sources=["xposedornot"],
            api_keys={},
            timeout=5.0,
            concurrency=3,
            user_agent="test/1.0",
        )
        assert breaches == []


@pytest.mark.asyncio
async def test_check_breaches_dedup_across_sources():
    with respx.mock:
        respx.route(method="GET", url__startswith="https://api.xposedornot.com/").mock(
            return_value=httpx.Response(200, json={"breaches": ["LinkedIn"]}),
        )
        respx.route(method="GET", url__startswith="https://leakcheck.io/").mock(
            return_value=httpx.Response(200, json={"success": True, "found": 1, "sources": [{"name": "LinkedIn"}]}),
        )
        breaches = await check_breaches(
            emails=["test@test.com"],
            sources=["xposedornot", "leakcheck"],
            api_keys={},
            timeout=5.0,
            concurrency=3,
            user_agent="test/1.0",
        )
        linkedin = [b for b in breaches if b.breach_name == "LinkedIn"]
        assert len(linkedin) == 1
