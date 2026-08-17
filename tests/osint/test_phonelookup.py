"""Testes para o modulo mytools.osint.phonelookup."""

import argparse
import runpy
from unittest.mock import AsyncMock, patch

import httpx
import phonenumbers
import pytest
import respx

from mytools.core.utils import FetchError
from mytools.osint.phonelookup import (
    _CARRIER_MAP,
    _DDD_MAP,
    PhoneResult,
    _ipqs,
    _lookup_br,
    _numlookup,
    build_parser,
    parse_number,
    print_results,
    run_scan,
)

BR_MOBILE = "+5561981280041"


# ── parse_number ────────────────────────────────────────────────────────────


def test_parse_br_mobile() -> None:
    r = parse_number(BR_MOBILE)
    assert r.is_valid is True
    assert r.e164 == BR_MOBILE
    assert r.country_code == "BR"
    assert r.country_name == "Brasil"
    assert r.ddd == "61"
    assert r.uf == "DF"
    assert r.cities
    assert r.carrier_local == "Vivo"
    assert r.line_type == "movel"
    assert "America/Sao_Paulo" in r.timezone


def test_parse_us_number() -> None:
    r = parse_number("+12125551234")
    assert r.is_valid is True
    assert r.country_code == "US"
    assert r.country_name == "Estados Unidos"
    assert r.ddd == ""
    assert r.carrier_local == ""


def test_parse_invalid() -> None:
    r = parse_number("abc")
    assert r.is_valid is False
    assert any("Numero invalido" in i for i in r.issues)


def test_parse_empty() -> None:
    r = parse_number("")
    assert r.is_valid is False


def test_parse_region_none_fallback() -> None:
    fake = phonenumbers.parse("+12125551234", None)
    with patch(
        "mytools.osint.phonelookup.phonenumbers.parse",
        side_effect=[phonenumbers.NumberParseException(0, "x"), fake],
    ):
        r = parse_number("12125551234", "XX")
    assert r.is_valid is True
    assert r.country_code == "US"


# ── _lookup_br ──────────────────────────────────────────────────────────────


def _base_result() -> PhoneResult:
    return PhoneResult(
        raw_number=BR_MOBILE,
        e164=BR_MOBILE,
        local_format="",
        international_format="",
        country_code="BR",
        country_name="Brasil",
    )


def test_lookup_br_fixed() -> None:
    num = phonenumbers.parse("6132224444", "BR")
    r = _lookup_br(_base_result(), num)
    assert r.ddd == "61"
    assert r.line_type == "linha fixa"


def test_lookup_br_short_ns() -> None:
    num = phonenumbers.parse("61", "BR")
    with patch(
        "mytools.osint.phonelookup.phonenumbers.national_significant_number",
        return_value="123",
    ):
        r = _lookup_br(_base_result(), num)
    assert r.ddd == ""
    assert r.carrier_local == ""


def test_lookup_br_unknown_ddd_and_carrier() -> None:
    num = phonenumbers.parse(BR_MOBILE, "BR")
    with (
        patch.dict(_DDD_MAP, {}, clear=True),
        patch.dict(_CARRIER_MAP, {}, clear=True),
    ):
        r = _lookup_br(_base_result(), num)
    assert r.uf == ""
    assert r.cities == []
    assert r.carrier_local == ""


# ── _numlookup ──────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_numlookup_no_key() -> None:
    client = httpx.AsyncClient()
    assert await _numlookup(client, BR_MOBILE, "", "BR", 5.0) is None
    await client.aclose()


@pytest.mark.asyncio
async def test_numlookup_success() -> None:
    with respx.mock:
        respx.route(
            method="GET",
            url__startswith="https://api.numlookupapi.com/v1/validate/",
        ).mock(
            return_value=httpx.Response(
                200,
                json={
                    "valid": True,
                    "number": BR_MOBILE,
                    "carrier": "TIM",
                    "location": "Brasilia",
                    "line_type": "mobile",
                    "country_code": "BR",
                    "country_name": "Brazil",
                },
            ),
        )
        client = httpx.AsyncClient()
        data = await _numlookup(client, BR_MOBILE, "KEY", "BR", 5.0)
        await client.aclose()
        assert data is not None
        assert data["carrier"] == "TIM"
        assert "error" not in data


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "status, expected",
    [
        (401, "chave invalida"),
        (429, "rate limit"),
        (500, "HTTP 500"),
    ],
)
async def test_numlookup_errors(status: int, expected: str) -> None:
    with respx.mock:
        respx.route(
            method="GET",
            url__startswith="https://api.numlookupapi.com/v1/validate/",
        ).mock(return_value=httpx.Response(status, json={"message": "err"}))
        client = httpx.AsyncClient()
        data = await _numlookup(client, BR_MOBILE, "KEY", "BR", 5.0)
        await client.aclose()
        assert data == {"error": expected}


@pytest.mark.asyncio
async def test_numlookup_bad_json() -> None:
    with respx.mock:
        respx.route(
            method="GET",
            url__startswith="https://api.numlookupapi.com/v1/validate/",
        ).mock(return_value=httpx.Response(200, text="not-json"))
        client = httpx.AsyncClient()
        data = await _numlookup(client, BR_MOBILE, "KEY", "BR", 5.0)
        await client.aclose()
        assert data == {"error": "resposta invalida"}


@pytest.mark.asyncio
async def test_numlookup_non_dict() -> None:
    with respx.mock:
        respx.route(
            method="GET",
            url__startswith="https://api.numlookupapi.com/v1/validate/",
        ).mock(return_value=httpx.Response(200, json=[]))
        client = httpx.AsyncClient()
        data = await _numlookup(client, BR_MOBILE, "KEY", "BR", 5.0)
        await client.aclose()
        assert data == {"error": "resposta invalida"}


@pytest.mark.asyncio
async def test_numlookup_fetch_error() -> None:
    client = httpx.AsyncClient()
    with patch(
        "mytools.osint.phonelookup.fetch",
        side_effect=FetchError("u", 1, ValueError("boom")),
    ):
        data = await _numlookup(client, BR_MOBILE, "KEY", "BR", 5.0)
    await client.aclose()
    assert data == {"error": "falha de rede"}


# ── _ipqs ───────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_ipqs_no_key() -> None:
    client = httpx.AsyncClient()
    assert await _ipqs(client, BR_MOBILE, "", "BR", 5.0) is None
    await client.aclose()


@pytest.mark.asyncio
async def test_ipqs_success() -> None:
    with respx.mock:
        respx.route(
            method="GET",
            url__startswith="https://www.ipqualityscore.com/api/json/phone/",
        ).mock(
            return_value=httpx.Response(
                200,
                json={
                    "success": True,
                    "valid": True,
                    "fraud_score": 85,
                    "active": True,
                    "risky": True,
                    "carrier": "TIM",
                },
            ),
        )
        client = httpx.AsyncClient()
        data = await _ipqs(client, BR_MOBILE, "KEY", "BR", 5.0)
        await client.aclose()
        assert data is not None
        assert data["fraud_score"] == 85
        assert "error" not in data


@pytest.mark.asyncio
async def test_ipqs_no_country() -> None:
    with respx.mock:
        respx.route(
            method="GET",
            url__startswith="https://www.ipqualityscore.com/api/json/phone/",
        ).mock(
            return_value=httpx.Response(200, json={"success": False, "message": "x"})
        )
        client = httpx.AsyncClient()
        data = await _ipqs(client, BR_MOBILE, "KEY", "", 5.0)
        await client.aclose()
        assert data == {"success": False, "message": "x"}


@pytest.mark.asyncio
async def test_ipqs_http_error() -> None:
    with respx.mock:
        respx.route(
            method="GET",
            url__startswith="https://www.ipqualityscore.com/api/json/phone/",
        ).mock(return_value=httpx.Response(500, text="boom"))
        client = httpx.AsyncClient()
        data = await _ipqs(client, BR_MOBILE, "KEY", "BR", 5.0)
        await client.aclose()
        assert data == {"error": "HTTP 500"}


@pytest.mark.asyncio
async def test_ipqs_bad_json() -> None:
    with respx.mock:
        respx.route(
            method="GET",
            url__startswith="https://www.ipqualityscore.com/api/json/phone/",
        ).mock(return_value=httpx.Response(200, text="not-json"))
        client = httpx.AsyncClient()
        data = await _ipqs(client, BR_MOBILE, "KEY", "BR", 5.0)
        await client.aclose()
        assert data == {"error": "resposta invalida"}


@pytest.mark.asyncio
async def test_ipqs_non_dict() -> None:
    with respx.mock:
        respx.route(
            method="GET",
            url__startswith="https://www.ipqualityscore.com/api/json/phone/",
        ).mock(return_value=httpx.Response(200, json="nope"))
        client = httpx.AsyncClient()
        data = await _ipqs(client, BR_MOBILE, "KEY", "BR", 5.0)
        await client.aclose()
        assert data == {"error": "resposta invalida"}


@pytest.mark.asyncio
async def test_ipqs_fetch_error() -> None:
    client = httpx.AsyncClient()
    with patch(
        "mytools.osint.phonelookup.fetch",
        side_effect=FetchError("u", 1, ValueError("boom")),
    ):
        data = await _ipqs(client, BR_MOBILE, "KEY", "BR", 5.0)
    await client.aclose()
    assert data == {"error": "falha de rede"}


# ── run_scan ────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_run_scan_invalid_no_client() -> None:
    with patch("mytools.osint.phonelookup.create_async_client") as mock_client:
        r = await run_scan("abc", numlookup_key="K", ipqs_key="K")
        mock_client.assert_not_called()
    assert r.is_valid is False


@pytest.mark.asyncio
async def test_run_scan_offline() -> None:
    r = await run_scan(BR_MOBILE)
    assert r.is_valid is True
    assert r.sources == ["local"]
    assert r.numlookup == {}
    assert r.ipqs == {}


@pytest.mark.asyncio
async def test_run_scan_both_keys_success() -> None:
    with (
        patch(
            "mytools.osint.phonelookup._numlookup",
            new=AsyncMock(return_value={"carrier": "TIM"}),
        ),
        patch(
            "mytools.osint.phonelookup._ipqs",
            new=AsyncMock(return_value={"fraud_score": 10}),
        ),
    ):
        r = await run_scan(BR_MOBILE, numlookup_key="K", ipqs_key="K")
    assert r.numlookup == {"carrier": "TIM"}
    assert r.ipqs == {"fraud_score": 10}
    assert r.sources == ["local", "numlookup", "ipqs"]
    assert r.issues == []


@pytest.mark.asyncio
async def test_run_scan_both_keys_error() -> None:
    with (
        patch(
            "mytools.osint.phonelookup._numlookup",
            new=AsyncMock(return_value={"error": "rate limit"}),
        ),
        patch(
            "mytools.osint.phonelookup._ipqs",
            new=AsyncMock(return_value={"error": "HTTP 500"}),
        ),
    ):
        r = await run_scan(BR_MOBILE, numlookup_key="K", ipqs_key="K")
    assert any("NumLookup: rate limit" in i for i in r.issues)
    assert any("IPQS: HTTP 500" in i for i in r.issues)


@pytest.mark.asyncio
async def test_run_scan_keys_return_none() -> None:
    with (
        patch("mytools.osint.phonelookup._numlookup", new=AsyncMock(return_value=None)),
        patch("mytools.osint.phonelookup._ipqs", new=AsyncMock(return_value=None)),
    ):
        r = await run_scan(BR_MOBILE, numlookup_key="K", ipqs_key="K")
    assert r.sources == ["local"]
    assert r.numlookup == {}
    assert r.ipqs == {}
    assert r.issues == []


# ── print_results ───────────────────────────────────────────────────────────


def test_print_invalid(capsys) -> None:
    print_results(parse_number("abc"))
    out = capsys.readouterr().out
    assert "invalido" in out.lower()


def test_print_valid_with_apis(capsys) -> None:
    r = PhoneResult(
        raw_number=BR_MOBILE,
        e164=BR_MOBILE,
        local_format="(61) 98128-0041",
        international_format="+55 61 98128-0041",
        country_code="BR",
        country_name="Brasil",
        region="Distrito Federal",
        is_valid=True,
        line_type="movel",
        ddd="61",
        uf="DF",
        cities=["Brasilia"],
        carrier_local="Vivo",
        numlookup={"carrier": "TIM", "location": "Brasilia", "line_type": "mobile"},
        ipqs={
            "fraud_score": 80,
            "risky": True,
            "active": False,
            "city": "Brasilia",
            "zip_code": "N/A",
        },
        sources=["local", "numlookup", "ipqs"],
    )
    print_results(r)
    out = capsys.readouterr().out
    assert "TIM" in out
    assert "Fraud score: 80" in out
    assert "Risco: Sim" in out
    assert "Ativo: False" in out
    assert "Operadora (aprox.)" not in out


def test_print_ipqs_low(capsys) -> None:
    r = PhoneResult(
        raw_number=BR_MOBILE,
        e164=BR_MOBILE,
        local_format="",
        international_format="",
        country_code="BR",
        country_name="Brasil",
        is_valid=True,
        line_type="movel",
        ipqs={"fraud_score": 10, "risky": False},
    )
    print_results(r)
    out = capsys.readouterr().out
    assert "Fraud score: 10" in out
    assert "Risco: Nao" in out


def test_print_issues(capsys) -> None:
    r = PhoneResult(
        raw_number=BR_MOBILE,
        e164=BR_MOBILE,
        local_format="",
        international_format="",
        country_code="BR",
        country_name="Brasil",
        is_valid=True,
        line_type="movel",
        issues=["NumLookup: rate limit"],
    )
    print_results(r)
    out = capsys.readouterr().out
    assert "rate limit" in out


def test_print_full_br(capsys) -> None:
    r = PhoneResult(
        raw_number=BR_MOBILE,
        e164=BR_MOBILE,
        local_format="(61) 98128-0041",
        international_format="+55 61 98128-0041",
        country_code="BR",
        country_name="Brasil",
        region="Distrito Federal",
        timezone="America/Sao_Paulo",
        is_valid=True,
        line_type="movel",
        ddd="61",
        uf="DF",
        cities=["Brasilia"],
        numlookup={
            "carrier": "TIM",
            "location": "Brasilia",
            "line_type": "mobile",
            "country_name": "Brazil",
        },
        ipqs={"active": True},
    )
    print_results(r)
    out = capsys.readouterr().out
    assert "Fuso: America/Sao_Paulo" in out
    assert "UF: DF" in out
    assert "Cidades: Brasilia" in out
    assert "Operadora: TIM" in out
    assert "Localizacao: Brasilia" in out
    assert "Tipo de linha: mobile" in out
    assert "Pais: Brazil" in out
    assert "Ativo: True" in out


def test_print_numlookup_partial(capsys) -> None:
    r = PhoneResult(
        raw_number=BR_MOBILE,
        e164=BR_MOBILE,
        local_format="",
        international_format="",
        country_code="BR",
        country_name="Brasil",
        is_valid=True,
        line_type="movel",
        numlookup={"country_name": "Brazil"},
    )
    print_results(r)
    out = capsys.readouterr().out
    assert "Pais: Brazil" in out
    assert "Operadora: TIM" not in out
    assert "Localizacao: Brasilia" not in out


def test_print_br_carrier_local(capsys) -> None:
    r = PhoneResult(
        raw_number=BR_MOBILE,
        e164=BR_MOBILE,
        local_format="",
        international_format="",
        country_code="BR",
        country_name="Brasil",
        is_valid=True,
        line_type="movel",
        ddd="61",
        uf="DF",
        cities=["Brasilia"],
        carrier_local="Vivo",
    )
    print_results(r)
    out = capsys.readouterr().out
    assert "Operadora (aprox.): Vivo" in out


def test_print_br_empty_fields(capsys) -> None:
    r = PhoneResult(
        raw_number=BR_MOBILE,
        e164=BR_MOBILE,
        local_format="",
        international_format="",
        country_code="BR",
        country_name="Brasil",
        is_valid=True,
        line_type="movel",
        ddd="61",
    )
    print_results(r)
    out = capsys.readouterr().out
    assert "DDD: 61" in out
    assert "Operadora (aprox.)" not in out


def test_print_ipqs_no_fraud(capsys) -> None:
    r = PhoneResult(
        raw_number=BR_MOBILE,
        e164=BR_MOBILE,
        local_format="",
        international_format="",
        country_code="BR",
        country_name="Brasil",
        is_valid=True,
        line_type="movel",
        ipqs={"fraud_score": None, "active": True, "spammer": 1},
    )
    print_results(r)
    out = capsys.readouterr().out
    assert "Fraud score" not in out
    assert "Spammer: Sim" in out


# ── build_parser ────────────────────────────────────────────────────────────


def test_build_parser() -> None:
    args = build_parser().parse_args(["+5511999999999", "--region", "US"])
    assert args.number == "+5511999999999"
    assert args.region == "US"


def test_build_parser_env_keys() -> None:
    with patch.dict(
        "os.environ",
        {"MYTOOLS_NUMLOOKUP_KEY": "NL", "MYTOOLS_IPQS_KEY": "IQ"},
    ):
        args = build_parser().parse_args([BR_MOBILE])
    assert args.numlookup_key == "NL"
    assert args.ipqs_key == "IQ"


def test_build_parser_missing_env() -> None:
    with patch.dict("os.environ", {}, clear=True):
        args = build_parser().parse_args([BR_MOBILE])
    assert args.numlookup_key is None
    assert args.ipqs_key is None


# ── _async_run_once / run_once ──────────────────────────────────────────────


def _valid_result() -> PhoneResult:
    return PhoneResult(
        raw_number=BR_MOBILE,
        e164=BR_MOBILE,
        local_format="(61) 98128-0041",
        international_format="+55 61 98128-0041",
        country_code="BR",
        country_name="Brasil",
        is_valid=True,
        line_type="movel",
    )


def test_async_run_once_json(capsys) -> None:

    args = build_parser().parse_args([BR_MOBILE, "--json"])
    with patch(
        "mytools.osint.phonelookup.run_scan",
        new=AsyncMock(return_value=_valid_result()),
    ):
        code = _async_run_once_run(args)
    assert code == 0
    out = capsys.readouterr().out
    assert '"e164": "+5561981280041"' in out


def test_async_run_once_invalid_exit1() -> None:

    args = build_parser().parse_args(["abc"])
    with patch(
        "mytools.osint.phonelookup.run_scan",
        new=AsyncMock(return_value=parse_number("abc")),
    ):
        code = _async_run_once_run(args)
    assert code == 1


def test_async_run_once_no_number() -> None:

    args = build_parser().parse_args([""])
    assert _async_run_once_run(args) == 1


def test_async_run_once_quiet(capsys) -> None:

    args = build_parser().parse_args([BR_MOBILE])
    with (
        patch("mytools.osint.phonelookup.init_scanner", return_value=True),
        patch(
            "mytools.osint.phonelookup.run_scan",
            new=AsyncMock(return_value=_valid_result()),
        ),
    ):
        code = _async_run_once_run(args)
    assert code == 0
    assert capsys.readouterr().out == ""


def test_async_run_once_output_dir(tmp_path) -> None:

    args = build_parser().parse_args([BR_MOBILE, "--output-dir", str(tmp_path)])
    with patch(
        "mytools.osint.phonelookup.run_scan",
        new=AsyncMock(return_value=_valid_result()),
    ):
        code = _async_run_once_run(args)
    assert code == 0
    assert (tmp_path / "phone.json").exists()


def test_async_run_once_output(tmp_path) -> None:

    out = tmp_path / "out.json"
    args = build_parser().parse_args([BR_MOBILE, "--output", str(out)])
    with patch(
        "mytools.osint.phonelookup.run_scan",
        new=AsyncMock(return_value=_valid_result()),
    ):
        code = _async_run_once_run(args)
    assert code == 0
    assert out.exists()


def test_run_once_dispatch() -> None:
    from mytools.osint.phonelookup import run_once

    args = build_parser().parse_args([BR_MOBILE])
    with patch(
        "mytools.osint.phonelookup.run_scan",
        new=AsyncMock(return_value=_valid_result()),
    ):
        assert run_once(args) == 0


# ── main guard ──────────────────────────────────────────────────────────────


def test_main_guard() -> None:
    with (
        patch("mytools.core.utils.run_main_loop", side_effect=SystemExit(0)),
        patch("sys.argv", ["mytools-phone", BR_MOBILE]),
        pytest.raises(SystemExit),
    ):
        runpy.run_module("mytools.osint.phonelookup", run_name="__main__")


def _async_run_once_run(args: argparse.Namespace) -> int:
    import asyncio

    from mytools.osint.phonelookup import _async_run_once

    return asyncio.run(_async_run_once(args))
