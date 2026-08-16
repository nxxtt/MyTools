#!/usr/bin/env python3
"""Testes unitarios do modulo de NSEC Walking."""

import argparse
from typing import ClassVar
from unittest.mock import MagicMock, patch

import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.rcode
import dns.resolver
import dns.rrset
import pytest

from mytools.dns.nsecwalking import (
    NsecEntry,
    NsecResult,
    _iter_nsec_rrs,
    _parse_nsec_types,
    _query_nsec,
    _random_label,
    banner,
    build_parser,
    main,
    print_results,
    run_once,
    scan_nsec,
)


class TestNsecEntry:
    """Testes do dataclass NsecEntry."""

    def test_frozen(self) -> None:
        e = NsecEntry(name="a", next_name="b", record_types=["A"])
        with pytest.raises(AttributeError):
            e.name = "x"  # type: ignore[misc]

    def test_slots(self) -> None:
        assert hasattr(NsecEntry, "__slots__")


class TestNsecResult:
    """Testes do dataclass NsecResult."""

    def test_frozen(self) -> None:
        r = NsecResult(
            domain="a",
            names_found=[],
            total_names=0,
            has_nsec3=False,
            zone_enumerated=False,
            entries=[],
            max_hops=0,
            hops_used=0,
        )
        with pytest.raises(AttributeError):
            r.domain = "x"  # type: ignore[misc]

    def test_slots(self) -> None:
        assert hasattr(NsecResult, "__slots__")


class TestRandomLabel:
    """Testes da funcao _random_label."""

    def test_length(self) -> None:
        label = _random_label(10)
        assert len(label) == 10

    def test_alphabetic(self) -> None:
        label = _random_label(20)
        assert label.isalpha()

    def test_lowercase(self) -> None:
        label = _random_label(20)
        assert label == label.lower()


class TestParseNsecTypes:
    """Testes da funcao _parse_nsec_types."""

    def test_empty(self) -> None:
        assert _parse_nsec_types("") == []

    def test_known_types(self) -> None:
        result = _parse_nsec_types("A NS SOA MX")
        assert "A" in result
        assert "NS" in result

    def test_unknown_types(self) -> None:
        result = _parse_nsec_types("TYPE255 TYPE256")
        assert len(result) == 2


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

    def test_max_hops(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["example.com", "--max-hops", "100"])
        assert args.max_hops == 100

    def test_query_timeout(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["example.com", "--query-timeout", "5.0"])
        assert args.query_timeout == 5.0


class TestPrintResults:
    """Testes da funcao print_results."""

    def test_enumerated(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = NsecResult(
            domain="example.com",
            names_found=["a.example.com", "b.example.com"],
            total_names=2,
            has_nsec3=False,
            zone_enumerated=True,
            entries=[
                NsecEntry("x.example.com", "a.example.com", ["A"]),
                NsecEntry("a.example.com", "b.example.com", ["A", "MX"]),
            ],
            max_hops=500,
            hops_used=2,
        )
        print_results(result)
        out = capsys.readouterr().out
        assert "NSEC Walking" in out
        assert "Enumerado: SIM" in out

    def test_nsec3(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = NsecResult(
            domain="test.com",
            names_found=[],
            total_names=0,
            has_nsec3=True,
            zone_enumerated=False,
            entries=[],
            max_hops=500,
            hops_used=0,
        )
        print_results(result)
        out = capsys.readouterr().out
        assert "NSEC3 detectado" in out

    def test_empty(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = NsecResult(
            domain="empty.com",
            names_found=[],
            total_names=0,
            has_nsec3=False,
            zone_enumerated=False,
            entries=[],
            max_hops=500,
            hops_used=0,
        )
        print_results(result)
        out = capsys.readouterr().out
        assert "Nenhum registro NSEC" in out


class TestScanNsec:
    """Testes da funcao scan_nsec com mocks."""

    @patch("mytools.dns.nsecwalking._query_nsec")
    def test_basic(self, mock_query: MagicMock) -> None:
        mock_query.return_value = ("x.example.com", "a.example.com", ["A"], False)
        result = scan_nsec("example.com", max_hops=3)
        assert result.total_names >= 0

    @patch("mytools.dns.nsecwalking._query_nsec")
    def test_nsec3_detected(self, mock_query: MagicMock) -> None:
        mock_query.return_value = ("x.test.com", "", ["NSEC3"], True)
        result = scan_nsec("test.com")
        assert result.has_nsec3 is True
        assert result.zone_enumerated is False

    @patch("mytools.dns.nsecwalking._query_nsec")
    def test_max_hops(self, mock_query: MagicMock) -> None:
        mock_query.return_value = ("x.example.com", "a.example.com", ["A"], False)
        result = scan_nsec("example.com", max_hops=2)
        assert result.hops_used <= 2

    @patch("mytools.dns.nsecwalking._query_nsec")
    def test_empty_response(self, mock_query: MagicMock) -> None:
        mock_query.return_value = ("", "", [], False)
        result = scan_nsec("example.com")
        assert result.total_names == 0

    @patch("mytools.dns.nsecwalking._query_nsec")
    def test_max_hops_zero(self, mock_query: MagicMock) -> None:
        result = scan_nsec("example.com", max_hops=0)
        assert result.total_names == 0
        assert result.hops_used == 0
        assert result.zone_enumerated is False
        mock_query.assert_not_called()

    @patch("mytools.dns.nsecwalking._query_nsec")
    def test_reaches_domain_breaks(self, mock_query: MagicMock) -> None:
        mock_query.return_value = ("x.example.com", "example.com", ["A"], False)
        result = scan_nsec("example.com", max_hops=5)
        assert result.total_names == 1
        assert result.hops_used == 1


class TestParseNsecTypesAdditional:
    """Cobertura adicional dos branches de _parse_nsec_types."""

    def test_integer_bitmap_tokens(self) -> None:
        result = _parse_nsec_types("47 48")
        assert "TYPE47" in result or "47" in result

    def test_unknown_type_number(self) -> None:
        result = _parse_nsec_types("TYPE1234")
        assert "TYPE1234" in result

    def test_type_with_non_numeric(self) -> None:
        result = _parse_nsec_types("TYPExyz")
        assert "TYPExyz" in result

    def test_unmatched_token(self) -> None:
        result = _parse_nsec_types("FOO")
        assert "FOO" in result

    def test_str_raises(self) -> None:
        class BadStr:
            def __str__(self) -> str:
                raise RuntimeError("boom")

        assert _parse_nsec_types(BadStr()) == []

    def test_bitmap_name_tokens_with_string_keys(self) -> None:
        from mytools.dns.nsecwalking import TYPE_BITMAPS

        string_keyed = {name: name for name in TYPE_BITMAPS.values()}
        with patch("mytools.dns.nsecwalking.TYPE_BITMAPS", string_keyed):
            result = _parse_nsec_types("A NS SOA")
        assert "A" in result
        assert "NS" in result

    def test_windows_iteration_raises(self) -> None:
        class BadWindows:
            windows: ClassVar[list[int]] = [1]

            def __iter__(self) -> None:
                raise RuntimeError("boom")

        result = _parse_nsec_types(BadWindows())
        assert isinstance(result, list)

    def test_windows_decoding_success(self) -> None:
        class GoodWindows:
            windows: ClassVar[list[tuple[int, bytes]]] = [(0, b"\x40")]

        result = _parse_nsec_types(GoodWindows())
        assert "A" in result


class TestIterNsecRrs:
    """Testes da funcao _iter_nsec_rrs."""

    def test_none_rrsets(self) -> None:
        assert list(_iter_nsec_rrs(None, dns.rdatatype.NSEC)) == []

    def test_empty_rrsets(self) -> None:
        assert list(_iter_nsec_rrs([], dns.rdatatype.NSEC)) == []

    def test_matching_rdtype(self) -> None:
        rrset = MagicMock()
        rrset.rdtype = dns.rdatatype.NSEC
        rrset.__iter__.return_value = iter(["rr1", "rr2"])
        result = list(_iter_nsec_rrs([rrset], dns.rdatatype.NSEC))
        assert result == ["rr1", "rr2"]

    def test_non_matching_rdtype(self) -> None:
        rrset = MagicMock()
        rrset.rdtype = dns.rdatatype.A
        result = list(_iter_nsec_rrs([rrset], dns.rdatatype.NSEC))
        assert result == []

    def test_mixed_rrsets(self) -> None:
        a = MagicMock()
        a.rdtype = dns.rdatatype.A
        nsec = MagicMock()
        nsec.rdtype = dns.rdatatype.NSEC
        nsec.__iter__.return_value = iter(["only"])
        result = list(_iter_nsec_rrs([a, nsec], dns.rdatatype.NSEC))
        assert result == ["only"]


class TestQueryNsec:
    """Testes da funcao _query_nsec."""

    def _mock_resolver(self, side_effect: object) -> MagicMock:
        mock_resolver = MagicMock()
        mock_resolver.resolve.side_effect = side_effect
        return mock_resolver

    @patch("mytools.dns.nsecwalking.dns.resolver.Resolver")
    def test_nsec_success(self, mock_cls: MagicMock) -> None:
        rr = MagicMock()
        rr.next = "a.example.com"
        mock_cls.return_value = self._mock_resolver([[rr]])
        name, next_name, _types, is_nsec3 = _query_nsec("example.com", "8.8.8.8", 3.0)
        assert name != ""
        assert next_name == "a.example.com"
        assert is_nsec3 is False

    @patch("mytools.dns.nsecwalking.dns.resolver.Resolver")
    def test_noanswer_then_nsec3_success(self, mock_cls: MagicMock) -> None:
        rr3 = MagicMock()
        rr3.next_hashed = "HASH123"
        mock_cls.return_value = self._mock_resolver([dns.resolver.NoAnswer(), [rr3]])
        _name, next_name, _types, is_nsec3 = _query_nsec("example.com", "8.8.8.8", 3.0)
        assert next_name == "HASH123"
        assert is_nsec3 is True

    @patch("mytools.dns.nsecwalking.dns.resolver.Resolver")
    def test_noanswer_then_nsec3_noanswer(self, mock_cls: MagicMock) -> None:
        mock_cls.return_value = self._mock_resolver(
            [dns.resolver.NoAnswer(), dns.resolver.NoAnswer()]
        )
        _name, next_name, _types, is_nsec3 = _query_nsec("example.com", "8.8.8.8", 3.0)
        assert next_name == ""
        assert is_nsec3 is False

    @patch("mytools.dns.nsecwalking.dns.resolver.Resolver")
    def test_noanswer_then_nsec3_exception(self, mock_cls: MagicMock) -> None:
        mock_cls.return_value = self._mock_resolver(
            [dns.resolver.NoAnswer(), RuntimeError("boom")]
        )
        _name, next_name, _types, _is_nsec3 = _query_nsec("example.com", "8.8.8.8", 3.0)
        assert next_name == ""

    @patch("mytools.dns.nsecwalking.dns.resolver.Resolver")
    def test_nxdomain_then_nsec_success(self, mock_cls: MagicMock) -> None:
        rr = MagicMock()
        rr.next = "b.example.com"
        mock_cls.return_value = self._mock_resolver([dns.resolver.NXDOMAIN(), [rr]])
        _name, next_name, _types, is_nsec3 = _query_nsec("example.com", "8.8.8.8", 3.0)
        assert next_name == "b.example.com"
        assert is_nsec3 is False

    @patch("mytools.dns.nsecwalking.dns.resolver.Resolver")
    def test_nxdomain_then_nsec3_success(self, mock_cls: MagicMock) -> None:
        rr3 = MagicMock()
        rr3.next_hashed = "HASH456"
        mock_cls.return_value = self._mock_resolver(
            [dns.resolver.NXDOMAIN(), dns.resolver.NoAnswer(), [rr3]]
        )
        _name, next_name, _types, is_nsec3 = _query_nsec("example.com", "8.8.8.8", 3.0)
        assert next_name == "HASH456"
        assert is_nsec3 is True

    @patch("mytools.dns.nsecwalking.dns.resolver.Resolver")
    def test_nxdomain_then_nsec3_exception(self, mock_cls: MagicMock) -> None:
        mock_cls.return_value = self._mock_resolver(
            [dns.resolver.NXDOMAIN(), dns.resolver.NoAnswer(), RuntimeError("x")]
        )
        _name, next_name, _types, _is_nsec3 = _query_nsec("example.com", "8.8.8.8", 3.0)
        assert next_name == ""

    @patch("mytools.dns.nsecwalking.dns.resolver.Resolver")
    def test_nxdomain_then_nsec_exception(self, mock_cls: MagicMock) -> None:
        mock_cls.return_value = self._mock_resolver(
            [dns.resolver.NXDOMAIN(), RuntimeError("x")]
        )
        _name, next_name, _types, _is_nsec3 = _query_nsec("example.com", "8.8.8.8", 3.0)
        assert next_name == ""

    @patch("mytools.dns.nsecwalking.dns.resolver.Resolver")
    def test_nxdomain_reads_authority_nsec(self, mock_cls: MagicMock) -> None:
        qname = dns.name.from_text("abc.example.com")
        msg = dns.message.make_response(dns.message.make_query(qname, "NSEC"))
        msg.set_rcode(dns.rcode.NXDOMAIN)
        msg.flags |= dns.flags.AA
        rrset = dns.rrset.from_text(
            dns.name.from_text("zzz.example.com"),
            3600,
            "IN",
            "NSEC",
            "aaa.example.com A NS SOA RRSIG NSEC DNSKEY",
        )
        msg.authority.append(rrset)
        exc = dns.resolver.NXDOMAIN(qnames=[qname], responses={qname: msg})
        mock_cls.return_value = self._mock_resolver(exc)

        _name, next_name, types, is_nsec3 = _query_nsec(
            "example.com", "8.8.8.8", 3.0, query_name="abc.example.com"
        )
        assert next_name.rstrip(".") == "aaa.example.com"
        assert is_nsec3 is False
        assert "A" in types
        mock_cls.return_value.resolve.assert_called_once()

    @patch("mytools.dns.nsecwalking.dns.resolver.Resolver")
    def test_nxdomain_reads_authority_nsec3(self, mock_cls: MagicMock) -> None:
        qname = dns.name.from_text("abc.example.com")
        msg = dns.message.make_response(dns.message.make_query(qname, "NSEC"))
        msg.set_rcode(dns.rcode.NXDOMAIN)
        msg.flags |= dns.flags.AA
        nsec3_rr = MagicMock()
        nsec3_rr.next_hashed = "HASH123"
        nsec3_rrset = MagicMock()
        nsec3_rrset.rdtype = dns.rdatatype.NSEC3
        nsec3_rrset.__iter__.return_value = iter([nsec3_rr])
        msg.authority.append(nsec3_rrset)
        exc = dns.resolver.NXDOMAIN(qnames=[qname], responses={qname: msg})
        mock_cls.return_value = self._mock_resolver(exc)

        _name, next_name, _types, is_nsec3 = _query_nsec(
            "example.com", "8.8.8.8", 3.0, query_name="abc.example.com"
        )
        assert is_nsec3 is True
        assert next_name == "HASH123"

    @patch("mytools.dns.nsecwalking.dns.resolver.Resolver")
    def test_nxdomain_authority_no_nsec_falls_back(
        self, mock_cls: MagicMock
    ) -> None:
        qname = dns.name.from_text("abc.example.com")
        msg = dns.message.make_response(dns.message.make_query(qname, "NSEC"))
        msg.set_rcode(dns.rcode.NXDOMAIN)
        msg.flags |= dns.flags.AA
        a_rrset = MagicMock()
        a_rrset.rdtype = dns.rdatatype.A
        msg.authority.append(a_rrset)
        exc = dns.resolver.NXDOMAIN(qnames=[qname], responses={qname: msg})
        mock_cls.return_value = self._mock_resolver(exc)

        _name, next_name, _types, _is_nsec3 = _query_nsec(
            "example.com", "8.8.8.8", 3.0, query_name="abc.example.com"
        )
        assert next_name == ""

    @patch("mytools.dns.nsecwalking.dns.resolver.Resolver")
    def test_timeout(self, mock_cls: MagicMock) -> None:
        mock_cls.return_value = self._mock_resolver(dns.exception.Timeout())
        _name, next_name, _types, _is_nsec3 = _query_nsec("example.com", "8.8.8.8", 3.0)
        assert next_name == ""

    @patch("mytools.dns.nsecwalking.dns.resolver.Resolver")
    def test_dns_exception(self, mock_cls: MagicMock) -> None:
        mock_cls.return_value = self._mock_resolver(dns.exception.DNSException("err"))
        _name, next_name, _types, _is_nsec3 = _query_nsec("example.com", "8.8.8.8", 3.0)
        assert next_name == ""

    @patch("mytools.dns.nsecwalking.dns.resolver.Resolver")
    def test_nsec_empty_answer(self, mock_cls: MagicMock) -> None:
        mock_cls.return_value = self._mock_resolver([[]])
        _name, next_name, _types, is_nsec3 = _query_nsec("example.com", "8.8.8.8", 3.0)
        assert next_name == ""
        assert is_nsec3 is False

    @patch("mytools.dns.nsecwalking.dns.resolver.Resolver")
    def test_noanswer_then_nsec3_empty_answer(self, mock_cls: MagicMock) -> None:
        mock_cls.return_value = self._mock_resolver([dns.resolver.NoAnswer(), []])
        _name, next_name, _types, is_nsec3 = _query_nsec("example.com", "8.8.8.8", 3.0)
        assert next_name == ""
        assert is_nsec3 is False

    @patch("mytools.dns.nsecwalking.dns.resolver.Resolver")
    def test_nxdomain_then_nsec_empty_answer(self, mock_cls: MagicMock) -> None:
        mock_cls.return_value = self._mock_resolver([dns.resolver.NXDOMAIN(), []])
        _name, next_name, _types, is_nsec3 = _query_nsec("example.com", "8.8.8.8", 3.0)
        assert next_name == ""
        assert is_nsec3 is False

    @patch("mytools.dns.nsecwalking.dns.resolver.Resolver")
    def test_nxdomain_then_noanswer_then_nsec3_empty_answer(
        self, mock_cls: MagicMock
    ) -> None:
        mock_cls.return_value = self._mock_resolver(
            [dns.resolver.NXDOMAIN(), dns.resolver.NoAnswer(), []]
        )
        _name, next_name, _types, is_nsec3 = _query_nsec("example.com", "8.8.8.8", 3.0)
        assert next_name == ""
        assert is_nsec3 is False


class TestPrintResultsManyEntries:
    """Cobertura do branch de mais de 50 entradas em print_results."""

    def test_many_entries(self, capsys: pytest.CaptureFixture[str]) -> None:
        entries = [
            NsecEntry(f"x{i}.example.com", f"n{i}.example.com", ["A"])
            for i in range(60)
        ]
        result = NsecResult(
            domain="example.com",
            names_found=[f"n{i}.example.com" for i in range(60)],
            total_names=60,
            has_nsec3=False,
            zone_enumerated=True,
            entries=entries,
            max_hops=500,
            hops_used=60,
        )
        print_results(result)
        out = capsys.readouterr().out
        assert "e mais" in out

    def test_many_entries_empty_types(self, capsys: pytest.CaptureFixture[str]) -> None:
        entries = [
            NsecEntry("seed.example.com", "n0.example.com", []),
            *[
                NsecEntry(f"x{i}.example.com", f"n{i}.example.com", ["A"])
                for i in range(1, 55)
            ],
        ]
        result = NsecResult(
            domain="example.com",
            names_found=[e.next_name for e in entries],
            total_names=len(entries),
            has_nsec3=False,
            zone_enumerated=True,
            entries=entries,
            max_hops=500,
            hops_used=len(entries),
        )
        print_results(result)
        out = capsys.readouterr().out
        assert "e mais" in out


class TestBanner:
    """Testes da funcao banner."""

    def test_banner_calls_create_banner(self) -> None:
        with patch("mytools.dns.nsecwalking.create_banner") as mock_cb:
            mock_banner = MagicMock()
            mock_cb.return_value = mock_banner
            banner()
            mock_cb.assert_called_once()
            mock_banner.assert_called_once()


def _make_run_once_args(**overrides: object) -> argparse.Namespace:
    """Cria namespace de args para run_once do nsecwalking."""
    defaults = {
        "domain": "example.com",
        "dry_run": False,
        "nameserver": "8.8.8.8",
        "max_hops": 100,
        "query_timeout": 3.0,
        "output": None,
    }
    defaults.update(overrides)
    return argparse.Namespace(**defaults)


class TestRunOnce:
    """Testes do run_once/_async_run_once."""

    @patch("mytools.dns.nsecwalking.init_scanner", return_value=False)
    def test_no_domain(self, mock_init: MagicMock) -> None:
        assert run_once(_make_run_once_args(domain=None)) == 1

    @patch("mytools.dns.nsecwalking.init_scanner", return_value=False)
    def test_dry_run(self, mock_init: MagicMock) -> None:
        assert run_once(_make_run_once_args(dry_run=True)) == 0

    @patch("mytools.dns.nsecwalking.print_results")
    @patch("mytools.dns.nsecwalking.scan_nsec")
    @patch("mytools.dns.nsecwalking.init_scanner", return_value=False)
    def test_full_run(
        self,
        mock_init: MagicMock,
        mock_scan: MagicMock,
        mock_print: MagicMock,
    ) -> None:
        result = NsecResult(
            domain="example.com",
            names_found=["a.example.com"],
            total_names=1,
            has_nsec3=False,
            zone_enumerated=True,
            entries=[],
            max_hops=100,
            hops_used=1,
        )
        mock_scan.return_value = result
        assert run_once(_make_run_once_args()) == 1
        mock_scan.assert_called_once_with(
            domain="example.com",
            nameserver="8.8.8.8",
            max_hops=100,
            timeout=3.0,
        )
        mock_print.assert_called_once_with(result)

    @patch("mytools.dns.nsecwalking.print_json")
    @patch("mytools.dns.nsecwalking.print_results")
    @patch("mytools.dns.nsecwalking.scan_nsec")
    @patch("mytools.dns.nsecwalking.init_scanner", return_value=False)
    def test_json_output(
        self,
        mock_init: MagicMock,
        mock_scan: MagicMock,
        mock_print: MagicMock,
        mock_json: MagicMock,
    ) -> None:
        result = NsecResult(
            domain="example.com",
            names_found=["a.example.com"],
            total_names=1,
            has_nsec3=False,
            zone_enumerated=True,
            entries=[],
            max_hops=100,
            hops_used=1,
        )
        mock_scan.return_value = result
        assert run_once(_make_run_once_args(json_output=True)) == 1
        mock_json.assert_called_once()

    @patch("mytools.dns.nsecwalking.ensure_output_dir")
    @patch("mytools.dns.nsecwalking.write_output")
    @patch("mytools.dns.nsecwalking.print_results")
    @patch("mytools.dns.nsecwalking.scan_nsec")
    @patch("mytools.dns.nsecwalking.init_scanner", return_value=False)
    def test_output_dir(
        self,
        mock_init: MagicMock,
        mock_scan: MagicMock,
        mock_print: MagicMock,
        mock_write: MagicMock,
        mock_ensure: MagicMock,
    ) -> None:
        result = NsecResult(
            domain="example.com",
            names_found=["a.example.com"],
            total_names=1,
            has_nsec3=False,
            zone_enumerated=True,
            entries=[],
            max_hops=100,
            hops_used=1,
        )
        mock_scan.return_value = result
        assert run_once(_make_run_once_args(output_dir="reports")) == 1
        mock_ensure.assert_called_once_with("reports")
        mock_write.assert_called_once()

    @patch("mytools.dns.nsecwalking.write_output")
    @patch("mytools.dns.nsecwalking.print_results")
    @patch("mytools.dns.nsecwalking.scan_nsec")
    @patch("mytools.dns.nsecwalking.init_scanner", return_value=False)
    def test_with_output(
        self,
        mock_init: MagicMock,
        mock_scan: MagicMock,
        mock_print: MagicMock,
        mock_write: MagicMock,
    ) -> None:
        result = NsecResult(
            domain="example.com",
            names_found=[],
            total_names=0,
            has_nsec3=False,
            zone_enumerated=False,
            entries=[],
            max_hops=100,
            hops_used=0,
        )
        mock_scan.return_value = result
        assert run_once(_make_run_once_args(output="out.json")) == 0
        mock_write.assert_called_once()

    @patch("mytools.dns.nsecwalking.print_results")
    @patch("mytools.dns.nsecwalking.scan_nsec")
    @patch("mytools.dns.nsecwalking.init_scanner", return_value=False)
    def test_safe_zone_returns_zero(
        self,
        mock_init: MagicMock,
        mock_scan: MagicMock,
        mock_print: MagicMock,
    ) -> None:
        result = NsecResult(
            domain="example.com",
            names_found=[],
            total_names=0,
            has_nsec3=True,
            zone_enumerated=False,
            entries=[],
            max_hops=100,
            hops_used=0,
        )
        mock_scan.return_value = result
        assert run_once(_make_run_once_args()) == 0

    @patch("mytools.dns.nsecwalking.write_output")
    @patch("mytools.dns.nsecwalking.print_results")
    @patch("mytools.dns.nsecwalking.scan_nsec")
    @patch("mytools.dns.nsecwalking.init_scanner", return_value=True)
    def test_quiet_skips_print(
        self,
        mock_init: MagicMock,
        mock_scan: MagicMock,
        mock_print: MagicMock,
        mock_write: MagicMock,
    ) -> None:
        result = NsecResult(
            domain="example.com",
            names_found=[],
            total_names=0,
            has_nsec3=False,
            zone_enumerated=False,
            entries=[],
            max_hops=100,
            hops_used=0,
        )
        mock_scan.return_value = result
        assert run_once(_make_run_once_args(quiet=True)) == 0
        mock_print.assert_not_called()
        mock_write.assert_not_called()


class TestMain:
    """Testes da funcao main."""

    def test_main_calls_run_main_loop(self) -> None:
        with patch(
            "mytools.dns.nsecwalking.run_main_loop", return_value=0
        ) as mock_loop:
            assert main() == 0
            mock_loop.assert_called_once()


class TestMainGuard:
    """Testes do guard `if __name__ == \"__main__\"`."""

    def test_guard_runs(self) -> None:
        import runpy

        with (
            patch("mytools.core.utils.run_main_loop", side_effect=SystemExit(0)),
            patch("sys.argv", ["mytools-nsec", "example.com"]),
            pytest.raises(SystemExit) as exc_info,
        ):
            runpy.run_module("mytools.dns.nsecwalking", run_name="__main__")
        assert exc_info.value.code == 0
