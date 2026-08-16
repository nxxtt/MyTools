#!/usr/bin/env python3
"""Testes unitarios do modulo de DNSSEC Validation."""

import argparse
import datetime
from unittest.mock import MagicMock, patch

import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.rcode
import dns.rdatatype
import dns.resolver
import dns.rrset
import pytest

from mytools.dns.dnssecvalidation import (
    DnssecCheck,
    DnssecResult,
    _check_dnskey,
    _check_ds,
    _check_nsec,
    _check_rrsig,
    _evaluate_algorithm_strength,
    _extract_rrsigs,
    _is_valid_nameserver,
    _random_label,
    _zone_uses_nsec,
    _zone_uses_nsec3,
    banner,
    build_parser,
    main,
    print_results,
    run_once,
    scan_dnssec,
)


class TestDnssecCheck:
    """Testes do dataclass DnssecCheck."""

    def test_frozen(self) -> None:
        c = DnssecCheck(check="test", status="pass", detail="ok", severity="low")
        with pytest.raises(AttributeError):
            c.check = "x"  # type: ignore[misc]

    def test_slots(self) -> None:
        assert hasattr(DnssecCheck, "__slots__")


class TestDnssecResult:
    """Testes do dataclass DnssecResult."""

    def test_frozen(self) -> None:
        r = DnssecResult(
            domain="a",
            nameserver="b",
            is_signed=False,
            has_ds=False,
            has_dnskey=False,
            has_rrsig=False,
            chain_valid=False,
            algorithm_strength="unknown",
            checks=[],
            overall_status="unsigned",
        )
        with pytest.raises(AttributeError):
            r.domain = "x"  # type: ignore[misc]

    def test_slots(self) -> None:
        assert hasattr(DnssecResult, "__slots__")


class TestParser:
    """Testes do build_parser."""

    def test_basic(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["example.com"])
        assert args.domain == "example.com"

    def test_nameserver(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["example.com", "--nameserver", "1.1.1.1"])
        assert args.nameserver == "1.1.1.1"

    def test_query_timeout(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["example.com", "--query-timeout", "10.0"])
        assert args.query_timeout == 10.0


class TestPrintResults:
    """Testes da funcao print_results."""

    def test_secure(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = DnssecResult(
            domain="example.com",
            nameserver="8.8.8.8",
            is_signed=True,
            has_ds=True,
            has_dnskey=True,
            has_rrsig=True,
            chain_valid=True,
            algorithm_strength="strong",
            checks=[
                DnssecCheck("dnskey_ksk", "pass", "1 KSK", "low"),
                DnssecCheck("ds_record", "pass", "1 DS", "low"),
            ],
            overall_status="secure",
        )
        print_results(result)
        out = capsys.readouterr().out
        assert "DNSSEC Validation" in out
        assert "SECURE" in out

    def test_unsigned(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = DnssecResult(
            domain="test.com",
            nameserver="8.8.8.8",
            is_signed=False,
            has_ds=False,
            has_dnskey=False,
            has_rrsig=False,
            chain_valid=False,
            algorithm_strength="unknown",
            checks=[
                DnssecCheck("dnskey", "missing", "Nenhum DNSKEY", "high"),
            ],
            overall_status="unsigned",
        )
        print_results(result)
        out = capsys.readouterr().out
        assert "NAO CONFIGURADO" in out or "unsigned" in out.lower()

    def test_broken(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = DnssecResult(
            domain="broken.com",
            nameserver="8.8.8.8",
            is_signed=True,
            has_ds=False,
            has_dnskey=True,
            has_rrsig=True,
            chain_valid=False,
            algorithm_strength="medium",
            checks=[
                DnssecCheck("rrsig_expiry", "warn", "2 expiradas", "high"),
            ],
            overall_status="insecure",
        )
        print_results(result)
        out = capsys.readouterr().out
        assert "INSECURE" in out


class TestScanDnssec:
    """Testes da funcao scan_dnssec com mocks."""

    @patch(
        "mytools.dns.dnssecvalidation._evaluate_algorithm_strength",
        return_value="strong",
    )
    @patch("mytools.dns.dnssecvalidation._check_nsec", return_value=[])
    @patch("mytools.dns.dnssecvalidation._check_rrsig")
    @patch("mytools.dns.dnssecvalidation._check_ds")
    @patch("mytools.dns.dnssecvalidation._check_dnskey")
    def test_secure(
        self,
        mock_dnskey: MagicMock,
        mock_ds: MagicMock,
        mock_rrsig: MagicMock,
        mock_nsec: MagicMock,
        mock_algo: MagicMock,
    ) -> None:
        mock_dnskey.return_value = (
            True,
            [DnssecCheck("dnskey_ksk", "pass", "1 KSK", "low")],
            {13},
        )
        mock_ds.return_value = (True, [DnssecCheck("ds_record", "pass", "1 DS", "low")])
        mock_rrsig.return_value = (
            True,
            [DnssecCheck("rrsig_expiry", "pass", "1 valida", "low")],
        )

        result = scan_dnssec("example.com")
        assert result.overall_status == "secure"
        assert result.chain_valid is True

    @patch(
        "mytools.dns.dnssecvalidation._evaluate_algorithm_strength",
        return_value="unknown",
    )
    @patch("mytools.dns.dnssecvalidation._check_nsec", return_value=[])
    @patch("mytools.dns.dnssecvalidation._check_rrsig")
    @patch("mytools.dns.dnssecvalidation._check_ds")
    @patch("mytools.dns.dnssecvalidation._check_dnskey")
    def test_unsigned(
        self,
        mock_dnskey: MagicMock,
        mock_ds: MagicMock,
        mock_rrsig: MagicMock,
        mock_nsec: MagicMock,
        mock_algo: MagicMock,
    ) -> None:
        mock_dnskey.return_value = (
            False,
            [DnssecCheck("dnskey", "missing", "Nenhum", "high")],
            {},
        )
        mock_ds.return_value = (
            False,
            [DnssecCheck("ds_record", "missing", "Nenhum", "medium")],
        )
        mock_rrsig.return_value = (
            False,
            [DnssecCheck("rrsig", "missing", "Nenhum", "high")],
        )

        result = scan_dnssec("test.com")
        assert result.overall_status == "unsigned"
        assert result.chain_valid is False

    @patch(
        "mytools.dns.dnssecvalidation._evaluate_algorithm_strength", return_value="weak"
    )
    @patch("mytools.dns.dnssecvalidation._check_nsec", return_value=[])
    @patch("mytools.dns.dnssecvalidation._check_rrsig")
    @patch("mytools.dns.dnssecvalidation._check_ds")
    @patch("mytools.dns.dnssecvalidation._check_dnskey")
    def test_weak_algo(
        self,
        mock_dnskey: MagicMock,
        mock_ds: MagicMock,
        mock_rrsig: MagicMock,
        mock_nsec: MagicMock,
        mock_algo: MagicMock,
    ) -> None:
        mock_dnskey.return_value = (
            True,
            [DnssecCheck("dnskey_ksk", "pass", "1 KSK", "low")],
            {13},
        )
        mock_ds.return_value = (True, [DnssecCheck("ds_record", "pass", "1 DS", "low")])
        mock_rrsig.return_value = (
            True,
            [DnssecCheck("rrsig_expiry", "pass", "1 valida", "low")],
        )

        result = scan_dnssec("weak.com")
        assert result.algorithm_strength == "weak"
        assert any(c.check == "algorithm_strength" for c in result.checks)


class TestAlgorithmSets:
    """Testes dos sets de algoritmos DNSSEC."""

    def test_weak_algorithms(self) -> None:
        from mytools.dns.dnssecvalidation import WEAK_ALGORITHMS

        assert 5 in WEAK_ALGORITHMS  # RSASHA1
        assert 7 in WEAK_ALGORITHMS  # RSASHA1-NSEC3-SHA1
        assert 8 not in WEAK_ALGORITHMS  # RSASHA256 should NOT be weak

    def test_medium_algorithms(self) -> None:
        from mytools.dns.dnssecvalidation import MEDIUM_ALGORITHMS

        assert 8 in MEDIUM_ALGORITHMS  # RSASHA256
        assert 10 in MEDIUM_ALGORITHMS  # RSASHA512

    def test_strong_algorithms(self) -> None:
        from mytools.dns.dnssecvalidation import STRONG_ALGORITHMS

        assert 13 in STRONG_ALGORITHMS  # ECDSAP256SHA256
        assert 14 in STRONG_ALGORITHMS  # ECDSAP384SHA384
        assert 15 in STRONG_ALGORITHMS  # ED25519
        assert 16 in STRONG_ALGORITHMS  # ED448

    def test_algorithm_8_not_in_weak(self) -> None:
        from mytools.dns.dnssecvalidation import MEDIUM_ALGORITHMS, WEAK_ALGORITHMS

        assert 8 not in WEAK_ALGORITHMS
        assert 8 in MEDIUM_ALGORITHMS

    def test_no_overlap_between_sets(self) -> None:
        from mytools.dns.dnssecvalidation import (
            MEDIUM_ALGORITHMS,
            STRONG_ALGORITHMS,
            WEAK_ALGORITHMS,
        )

        assert set() == WEAK_ALGORITHMS & MEDIUM_ALGORITHMS
        assert set() == WEAK_ALGORITHMS & STRONG_ALGORITHMS
        assert set() == MEDIUM_ALGORITHMS & STRONG_ALGORITHMS


class TestCheckDnskey:
    """Testes da funcao _check_dnskey."""

    def _make_rr(self, flags: int, algorithm: int) -> MagicMock:
        rr = MagicMock()
        rr.flags = flags
        rr.algorithm = algorithm
        return rr

    def test_success_with_ksk_and_zsk(self) -> None:
        resolver = MagicMock()
        resolver.resolve.return_value = [
            self._make_rr(256, 8),
            self._make_rr(257, 13),
        ]
        has_dnskey, checks, _algos = _check_dnskey("example.com", resolver)
        assert has_dnskey is True
        statuses = {c.check: c.status for c in checks}
        assert statuses["dnskey_ksk"] == "pass"
        assert statuses["dnskey_zsk"] == "pass"
        assert statuses["dnskey_algorithms"] == "pass"
        assert "RSASHA256" in checks[-1].detail

    def test_no_ksk(self) -> None:
        resolver = MagicMock()
        resolver.resolve.return_value = [self._make_rr(256, 8)]
        _has_dnskey, checks, _algos = _check_dnskey("example.com", resolver)
        assert any(c.check == "dnskey_ksk" and c.status == "warn" for c in checks)

    def test_no_zsk(self) -> None:
        resolver = MagicMock()
        resolver.resolve.return_value = [self._make_rr(257, 8)]
        _has_dnskey, checks, _algos = _check_dnskey("example.com", resolver)
        assert any(c.check == "dnskey_zsk" and c.status == "warn" for c in checks)

    def test_unknown_flags_ignored(self) -> None:
        resolver = MagicMock()
        resolver.resolve.return_value = [self._make_rr(128, 8)]
        _has_dnskey, checks, _algos = _check_dnskey("example.com", resolver)
        assert any(c.check == "dnskey_ksk" and c.status == "warn" for c in checks)
        assert any(c.check == "dnskey_zsk" and c.status == "warn" for c in checks)

    def test_nxdomain(self) -> None:
        resolver = MagicMock()
        resolver.resolve.side_effect = dns.resolver.NXDOMAIN()
        has_dnskey, checks, _algos = _check_dnskey("example.com", resolver)
        assert has_dnskey is False
        assert checks[0].status == "fail"

    def test_noanswer(self) -> None:
        resolver = MagicMock()
        resolver.resolve.side_effect = dns.resolver.NoAnswer()
        has_dnskey, checks, _algos = _check_dnskey("example.com", resolver)
        assert has_dnskey is False
        assert checks[0].status == "missing"

    def test_timeout(self) -> None:
        resolver = MagicMock()
        resolver.resolve.side_effect = dns.exception.Timeout()
        _has_dnskey, checks, _algos = _check_dnskey("example.com", resolver)
        assert checks[0].status == "fail"

    def test_generic_dns_exception(self) -> None:
        resolver = MagicMock()
        resolver.resolve.side_effect = dns.exception.DNSException("boom")
        _has_dnskey, checks, _algos = _check_dnskey("example.com", resolver)
        assert checks[0].status == "fail"
        assert "boom" in checks[0].detail


class TestCheckDs:
    """Testes da funcao _check_ds."""

    def test_success(self) -> None:
        resolver = MagicMock()
        resolver.resolve.return_value = [MagicMock(), MagicMock()]
        has_ds, checks = _check_ds("example.com", resolver)
        assert has_ds is True
        assert checks[0].status == "pass"
        assert "2 DS" in checks[0].detail

    def test_noanswer(self) -> None:
        resolver = MagicMock()
        resolver.resolve.side_effect = dns.resolver.NoAnswer()
        has_ds, checks = _check_ds("example.com", resolver)
        assert has_ds is False
        assert checks[0].status == "missing"

    def test_nxdomain(self) -> None:
        resolver = MagicMock()
        resolver.resolve.side_effect = dns.resolver.NXDOMAIN()
        _has_ds, checks = _check_ds("example.com", resolver)
        assert checks[0].status == "fail"

    def test_timeout(self) -> None:
        resolver = MagicMock()
        resolver.resolve.side_effect = dns.exception.Timeout()
        _has_ds, checks = _check_ds("example.com", resolver)
        assert checks[0].status == "fail"

    def test_generic_dns_exception(self) -> None:
        resolver = MagicMock()
        resolver.resolve.side_effect = dns.exception.DNSException("err")
        _has_ds, checks = _check_ds("example.com", resolver)
        assert checks[0].status == "fail"


class TestCheckRrsig:
    """Testes da funcao _check_rrsig."""

    def _make_rr(self, expiration: int) -> MagicMock:
        rr = MagicMock()
        rr.expiration = expiration
        return rr

    def _make_answer(self, rrs: list[MagicMock]) -> MagicMock:
        answer = MagicMock()
        response = MagicMock()
        rrset = MagicMock()
        rrset.rdtype = dns.rdatatype.RRSIG
        rrset.__iter__.return_value = iter(rrs)
        response.answer = [rrset]
        answer.response = response
        return answer

    def test_queries_soa_not_rrsig(self) -> None:
        resolver = MagicMock()
        resolver.resolve.return_value = self._make_answer([self._make_rr(123456)])
        _check_rrsig("example.com", resolver)
        resolver.resolve.assert_called_once_with("example.com", "SOA")

    def test_valid_signatures(self) -> None:
        future = int(datetime.datetime.now(datetime.UTC).timestamp()) + 100000
        resolver = MagicMock()
        resolver.resolve.return_value = self._make_answer(
            [self._make_rr(future), self._make_rr(future)]
        )
        has_rrsig, checks = _check_rrsig("example.com", resolver)
        assert has_rrsig is True
        assert checks[0].status == "pass"
        assert "2 assinatura(s) valida(s)" in checks[0].detail

    def test_expired_signatures(self) -> None:
        past = int(datetime.datetime.now(datetime.UTC).timestamp()) - 100000
        resolver = MagicMock()
        resolver.resolve.return_value = self._make_answer([self._make_rr(past)])
        _has_rrsig, checks = _check_rrsig("example.com", resolver)
        assert checks[0].status == "warn"
        assert "1 assinatura(s) expirada(s)" in checks[0].detail

    def test_unsigned_zone_soa_no_rrsig(self) -> None:
        resolver = MagicMock()
        resolver.resolve.return_value = self._make_answer([])
        has_rrsig, checks = _check_rrsig("example.com", resolver)
        assert has_rrsig is False
        assert checks[0].check == "rrsig"
        assert checks[0].status == "missing"

    def test_exception_parsing_expiry(self) -> None:
        resolver = MagicMock()
        resolver.resolve.return_value = self._make_answer([self._make_rr(123456)])
        with patch(
            "mytools.dns.dnssecvalidation.dns.dnssec.to_timestamp",
            side_effect=ValueError("bad ts"),
        ):
            _has_rrsig, checks = _check_rrsig("example.com", resolver)
        assert checks[0].status == "pass"

    def test_noanswer(self) -> None:
        resolver = MagicMock()
        resolver.resolve.side_effect = dns.resolver.NoAnswer()
        has_rrsig, checks = _check_rrsig("example.com", resolver)
        assert has_rrsig is False
        assert checks[0].status == "missing"

    def test_nxdomain(self) -> None:
        resolver = MagicMock()
        resolver.resolve.side_effect = dns.resolver.NXDOMAIN()
        _has_rrsig, checks = _check_rrsig("example.com", resolver)
        assert checks[0].status == "fail"

    def test_timeout(self) -> None:
        resolver = MagicMock()
        resolver.resolve.side_effect = dns.exception.Timeout()
        _has_rrsig, checks = _check_rrsig("example.com", resolver)
        assert checks[0].status == "fail"

    def test_generic_dns_exception(self) -> None:
        resolver = MagicMock()
        resolver.resolve.side_effect = dns.exception.DNSException("err")
        _has_rrsig, checks = _check_rrsig("example.com", resolver)
        assert checks[0].status == "fail"


class TestExtractRrsigs:
    """Testes da funcao _extract_rrsigs."""

    def test_response_with_non_rrsig_rrset(self) -> None:
        answer = MagicMock()
        response = MagicMock()
        non_rrsig = MagicMock()
        non_rrsig.rdtype = dns.rdatatype.A
        rrsig = MagicMock()
        rrsig.rdtype = dns.rdatatype.RRSIG
        rrsig.__iter__.return_value = iter(["sig1", "sig2"])
        response.answer = [non_rrsig, rrsig]
        answer.response = response
        result = _extract_rrsigs(answer)
        assert result == ["sig1", "sig2"]

    def test_response_none_answer_iterable(self) -> None:
        answer = MagicMock()
        answer.response = None
        answer.__iter__.return_value = iter(["sig1", "sig2"])
        result = _extract_rrsigs(answer)
        assert result == ["sig1", "sig2"]

    def test_response_none_answer_not_iterable(self) -> None:
        answer = MagicMock()
        answer.response = None
        type(answer).__iter__ = None
        result = _extract_rrsigs(answer)
        assert result == []

    def test_empty_answer(self) -> None:
        answer = MagicMock()
        response = MagicMock()
        response.answer = []
        answer.response = response
        assert _extract_rrsigs(answer) == []

    def test_no_response(self) -> None:
        answer = MagicMock()
        answer.response = None
        assert _extract_rrsigs(answer) == []


class TestRandomLabel:
    """Testes da funcao _random_label."""

    def test_default_length(self) -> None:
        label = _random_label()
        assert len(label) == 12
        assert label.islower()
        assert label.isalpha()

    def test_custom_length(self) -> None:
        assert len(_random_label(5)) == 5


class TestIsValidNameserver:
    """Testes da funcao _is_valid_nameserver."""

    def test_valid_ip(self) -> None:
        assert _is_valid_nameserver("8.8.8.8") is True

    def test_valid_hostname(self) -> None:
        assert _is_valid_nameserver("ns1.example.com") is True

    def test_valid_ipv6(self) -> None:
        assert _is_valid_nameserver("2001:4860:4860::8888") is True

    def test_empty(self) -> None:
        assert _is_valid_nameserver("") is False

    def test_whitespace(self) -> None:
        assert _is_valid_nameserver("8.8.8.8 1.1.1.1") is False

    def test_leading_dot(self) -> None:
        assert _is_valid_nameserver(".example.com") is False

    def test_trailing_dash(self) -> None:
        assert _is_valid_nameserver("example.com-") is False


class TestCheckNsec:
    """Testes da funcao _check_nsec."""

    @patch("mytools.dns.dnssecvalidation._zone_uses_nsec", return_value=True)
    def test_nsec_success(self, mock_nsec: MagicMock) -> None:
        resolver = MagicMock()
        checks = _check_nsec("example.com", resolver)
        mock_nsec.assert_called_once_with("example.com", resolver)
        assert checks[0].check == "nsec"
        assert checks[0].status == "pass"
        assert "NSEC record(s)" in checks[0].detail

    @patch("mytools.dns.dnssecvalidation._zone_uses_nsec", return_value=False)
    @patch("mytools.dns.dnssecvalidation._zone_uses_nsec3", return_value=True)
    def test_nsec3_success(self, mock_nsec3: MagicMock, mock_nsec: MagicMock) -> None:
        resolver = MagicMock()
        checks = _check_nsec("example.com", resolver)
        assert checks[0].check == "nsec3"
        assert checks[0].status == "pass"
        assert "NSEC3PARAM" in checks[0].detail

    @patch("mytools.dns.dnssecvalidation._zone_uses_nsec", return_value=False)
    @patch("mytools.dns.dnssecvalidation._zone_uses_nsec3", return_value=False)
    def test_both_missing(self, mock_nsec3: MagicMock, mock_nsec: MagicMock) -> None:
        resolver = MagicMock()
        checks = _check_nsec("example.com", resolver)
        assert checks[0].check == "nsec"
        assert checks[0].status == "missing"

    @patch("mytools.dns.dnssecvalidation._random_label", return_value="abc")
    def test_zone_uses_nsec_nxdomain_with_nsec(self, mock_label: MagicMock) -> None:
        qname = dns.name.from_text("abc.example.com")
        msg = dns.message.make_response(dns.message.make_query(qname, "A"))
        msg.set_rcode(dns.rcode.NXDOMAIN)
        msg.flags |= dns.flags.AA
        rrset = dns.rrset.from_text(
            dns.name.from_text("zzz.example.com"),
            3600,
            "IN",
            "NSEC",
            "abc.example.com A NS SOA RRSIG NSEC DNSKEY",
        )
        msg.authority.append(rrset)
        exc = dns.resolver.NXDOMAIN(qnames=[qname], responses={qname: msg})
        resolver = MagicMock()
        resolver.resolve.side_effect = exc
        assert _zone_uses_nsec("example.com", resolver) is True

    @patch("mytools.dns.dnssecvalidation._random_label", return_value="abc")
    def test_zone_uses_nsec_nxdomain_no_nsec(self, mock_label: MagicMock) -> None:
        qname = dns.name.from_text("abc.example.com")
        msg = dns.message.make_response(dns.message.make_query(qname, "A"))
        msg.set_rcode(dns.rcode.NXDOMAIN)
        msg.flags |= dns.flags.AA
        exc = dns.resolver.NXDOMAIN(qnames=[qname], responses={qname: msg})
        resolver = MagicMock()
        resolver.resolve.side_effect = exc
        assert _zone_uses_nsec("example.com", resolver) is False

    @patch("mytools.dns.dnssecvalidation._random_label", return_value="abc")
    def test_zone_uses_nsec_not_nxdomain(self, mock_label: MagicMock) -> None:
        resolver = MagicMock()
        resolver.resolve.return_value = [MagicMock()]
        assert _zone_uses_nsec("example.com", resolver) is False

    @patch("mytools.dns.dnssecvalidation._random_label", return_value="abc")
    def test_zone_uses_nsec_exc_response_raises(
        self, mock_label: MagicMock, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        qname = dns.name.from_text("abc.example.com")
        msg = dns.message.make_response(dns.message.make_query(qname, "A"))
        msg.set_rcode(dns.rcode.NXDOMAIN)
        msg.flags |= dns.flags.AA
        exc = dns.resolver.NXDOMAIN(qnames=[qname], responses={qname: msg})

        def boom(_name: object) -> None:
            raise RuntimeError("boom")

        monkeypatch.setattr(exc, "response", boom)
        resolver = MagicMock()
        resolver.resolve.side_effect = exc
        assert _zone_uses_nsec("example.com", resolver) is False

    @patch("mytools.dns.dnssecvalidation._random_label", return_value="abc")
    def test_zone_uses_nsec_generic_dns_exception(self, mock_label: MagicMock) -> None:
        resolver = MagicMock()
        resolver.resolve.side_effect = dns.exception.DNSException("err")
        assert _zone_uses_nsec("example.com", resolver) is False

    def test_zone_uses_nsec3_with_param(self) -> None:
        resolver = MagicMock()
        resolver.resolve.return_value = [MagicMock()]
        assert _zone_uses_nsec3("example.com", resolver) is True

    def test_zone_uses_nsec3_no_answer(self) -> None:
        resolver = MagicMock()
        resolver.resolve.side_effect = dns.resolver.NoAnswer()
        assert _zone_uses_nsec3("example.com", resolver) is False


class TestEvaluateAlgorithmStrength:
    """Testes da funcao _evaluate_algorithm_strength."""

    def test_strong(self) -> None:
        assert _evaluate_algorithm_strength({13}) == "strong"

    def test_medium(self) -> None:
        assert _evaluate_algorithm_strength({8}) == "medium"

    def test_weak(self) -> None:
        assert _evaluate_algorithm_strength({5}) == "weak"

    def test_unknown(self) -> None:
        assert _evaluate_algorithm_strength({1}) == "unknown"

    def test_empty(self) -> None:
        assert _evaluate_algorithm_strength(set()) == "unknown"


class TestScanDnssecAdditional:
    """Cobertura adicional dos branches de overall_status do scan_dnssec."""

    @patch(
        "mytools.dns.dnssecvalidation._evaluate_algorithm_strength",
        return_value="strong",
    )
    @patch("mytools.dns.dnssecvalidation._check_nsec", return_value=[])
    @patch("mytools.dns.dnssecvalidation._check_rrsig")
    @patch("mytools.dns.dnssecvalidation._check_ds")
    @patch("mytools.dns.dnssecvalidation._check_dnskey")
    def test_insecure(
        self,
        mock_dnskey: MagicMock,
        mock_ds: MagicMock,
        mock_rrsig: MagicMock,
        mock_nsec: MagicMock,
        mock_algo: MagicMock,
    ) -> None:
        mock_dnskey.return_value = (True, [], {13})
        mock_ds.return_value = (False, [])
        mock_rrsig.return_value = (True, [])

        result = scan_dnssec("insecure.com")
        assert result.overall_status == "insecure"
        assert result.is_signed is True
        assert result.has_ds is False

    @patch(
        "mytools.dns.dnssecvalidation._evaluate_algorithm_strength",
        return_value="weak",
    )
    @patch("mytools.dns.dnssecvalidation._check_nsec", return_value=[])
    @patch("mytools.dns.dnssecvalidation._check_rrsig")
    @patch("mytools.dns.dnssecvalidation._check_ds")
    @patch("mytools.dns.dnssecvalidation._check_dnskey")
    def test_partial_with_weak_algo(
        self,
        mock_dnskey: MagicMock,
        mock_ds: MagicMock,
        mock_rrsig: MagicMock,
        mock_nsec: MagicMock,
        mock_algo: MagicMock,
    ) -> None:
        mock_dnskey.return_value = (True, [], {13})
        mock_ds.return_value = (True, [])
        mock_rrsig.return_value = (True, [])

        result = scan_dnssec("partial.com")
        assert result.overall_status == "partial"


class TestPrintResultsPartial:
    """Cobertura do branch 'partial' em print_results."""

    def test_partial(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = DnssecResult(
            domain="partial.com",
            nameserver="8.8.8.8",
            is_signed=True,
            has_ds=True,
            has_dnskey=True,
            has_rrsig=True,
            chain_valid=True,
            algorithm_strength="weak",
            checks=[
                DnssecCheck(
                    "algorithm_strength", "warn", "Algoritmos fracos", "medium"
                ),
            ],
            overall_status="partial",
        )
        print_results(result)
        out = capsys.readouterr().out
        assert "parcialmente configurado" in out


class TestBanner:
    """Testes da funcao banner."""

    def test_banner_calls_create_banner(self) -> None:
        with patch("mytools.dns.dnssecvalidation.create_banner") as mock_cb:
            mock_banner = MagicMock()
            mock_cb.return_value = mock_banner
            banner()
            mock_cb.assert_called_once()
            mock_banner.assert_called_once()


def _make_run_once_args(**overrides: object) -> argparse.Namespace:
    """Cria namespace de args para run_once do dnssecvalidation."""
    defaults = {
        "domain": "example.com",
        "dry_run": False,
        "nameserver": "8.8.8.8",
        "query_timeout": 5.0,
        "output": None,
    }
    defaults.update(overrides)
    return argparse.Namespace(**defaults)


class TestRunOnce:
    """Testes do run_once/_async_run_once."""

    @patch("mytools.dns.dnssecvalidation.init_scanner", return_value=False)
    def test_no_domain(self, mock_init: MagicMock) -> None:
        assert run_once(_make_run_once_args(domain=None)) == 1

    @patch("mytools.dns.dnssecvalidation.init_scanner", return_value=False)
    def test_dry_run(self, mock_init: MagicMock) -> None:
        assert run_once(_make_run_once_args(dry_run=True)) == 0

    @patch("mytools.dns.dnssecvalidation.init_scanner", return_value=False)
    def test_invalid_nameserver(self, mock_init: MagicMock) -> None:
        assert run_once(_make_run_once_args(nameserver="bad name server")) == 1

    @patch("mytools.dns.dnssecvalidation.print_results")
    @patch("mytools.dns.dnssecvalidation.scan_dnssec")
    @patch("mytools.dns.dnssecvalidation.init_scanner", return_value=False)
    def test_full_run(
        self,
        mock_init: MagicMock,
        mock_scan: MagicMock,
        mock_print: MagicMock,
    ) -> None:
        result = DnssecResult(
            domain="example.com",
            nameserver="8.8.8.8",
            is_signed=True,
            has_ds=True,
            has_dnskey=True,
            has_rrsig=True,
            chain_valid=True,
            algorithm_strength="strong",
            checks=[],
            overall_status="secure",
        )
        mock_scan.return_value = result
        assert run_once(_make_run_once_args()) == 0
        mock_scan.assert_called_once_with(
            domain="example.com", nameserver="8.8.8.8", timeout=5.0
        )
        mock_print.assert_called_once_with(result)

    @patch("mytools.dns.dnssecvalidation.write_output")
    @patch("mytools.dns.dnssecvalidation.print_results")
    @patch("mytools.dns.dnssecvalidation.scan_dnssec")
    @patch("mytools.dns.dnssecvalidation.init_scanner", return_value=False)
    def test_with_output(
        self,
        mock_init: MagicMock,
        mock_scan: MagicMock,
        mock_print: MagicMock,
        mock_write: MagicMock,
    ) -> None:
        result = DnssecResult(
            domain="example.com",
            nameserver="8.8.8.8",
            is_signed=True,
            has_ds=True,
            has_dnskey=True,
            has_rrsig=True,
            chain_valid=True,
            algorithm_strength="strong",
            checks=[],
            overall_status="secure",
        )
        mock_scan.return_value = result
        assert run_once(_make_run_once_args(output="out.json")) == 0
        mock_write.assert_called_once()

    @patch("mytools.dns.dnssecvalidation.print_json")
    @patch("mytools.dns.dnssecvalidation.print_results")
    @patch("mytools.dns.dnssecvalidation.scan_dnssec")
    @patch("mytools.dns.dnssecvalidation.init_scanner", return_value=False)
    def test_json_output(
        self,
        mock_init: MagicMock,
        mock_scan: MagicMock,
        mock_print: MagicMock,
        mock_json: MagicMock,
    ) -> None:
        result = DnssecResult(
            domain="example.com",
            nameserver="8.8.8.8",
            is_signed=True,
            has_ds=True,
            has_dnskey=True,
            has_rrsig=True,
            chain_valid=True,
            algorithm_strength="strong",
            checks=[],
            overall_status="secure",
        )
        mock_scan.return_value = result
        assert run_once(_make_run_once_args(json_output=True)) == 0
        mock_json.assert_called_once()

    @patch("mytools.dns.dnssecvalidation.ensure_output_dir")
    @patch("mytools.dns.dnssecvalidation.write_output")
    @patch("mytools.dns.dnssecvalidation.print_results")
    @patch("mytools.dns.dnssecvalidation.scan_dnssec")
    @patch("mytools.dns.dnssecvalidation.init_scanner", return_value=False)
    def test_output_dir(
        self,
        mock_init: MagicMock,
        mock_scan: MagicMock,
        mock_print: MagicMock,
        mock_write: MagicMock,
        mock_ensure: MagicMock,
    ) -> None:
        result = DnssecResult(
            domain="example.com",
            nameserver="8.8.8.8",
            is_signed=True,
            has_ds=True,
            has_dnskey=True,
            has_rrsig=True,
            chain_valid=True,
            algorithm_strength="strong",
            checks=[],
            overall_status="secure",
        )
        mock_scan.return_value = result
        assert run_once(_make_run_once_args(output_dir="reports")) == 0
        mock_ensure.assert_called_once_with("reports")
        mock_write.assert_called_once()

    @patch("mytools.dns.dnssecvalidation.write_output")
    @patch("mytools.dns.dnssecvalidation.print_results")
    @patch("mytools.dns.dnssecvalidation.scan_dnssec")
    @patch("mytools.dns.dnssecvalidation.init_scanner", return_value=True)
    def test_quiet_skips_print(
        self,
        mock_init: MagicMock,
        mock_scan: MagicMock,
        mock_print: MagicMock,
        mock_write: MagicMock,
    ) -> None:
        result = DnssecResult(
            domain="example.com",
            nameserver="8.8.8.8",
            is_signed=True,
            has_ds=True,
            has_dnskey=True,
            has_rrsig=True,
            chain_valid=True,
            algorithm_strength="strong",
            checks=[],
            overall_status="secure",
        )
        mock_scan.return_value = result
        assert run_once(_make_run_once_args(quiet=True)) == 0
        mock_print.assert_not_called()
        mock_write.assert_not_called()


class TestMain:
    """Testes da funcao main."""

    def test_main_calls_run_main_loop(self) -> None:
        with patch(
            "mytools.dns.dnssecvalidation.run_main_loop", return_value=0
        ) as mock_loop:
            assert main() == 0
            mock_loop.assert_called_once()


class TestMainGuard:
    """Testes do guard `if __name__ == \"__main__\"`."""

    def test_guard_runs(self) -> None:
        import runpy

        with (
            patch("mytools.core.utils.run_main_loop", side_effect=SystemExit(0)),
            patch("sys.argv", ["mytools-dnssec", "example.com"]),
            pytest.raises(SystemExit) as exc_info,
        ):
            runpy.run_module("mytools.dns.dnssecvalidation", run_name="__main__")
        assert exc_info.value.code == 0
