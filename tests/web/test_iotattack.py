#!/usr/bin/env python3
"""Tests for iotattack.py."""

from __future__ import annotations

import inspect
import runpy
import struct
from collections.abc import Callable
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

import mytools.web.iotattack as iotattack_module
from mytools.web.iotattack import (
    _CATEGORY_DISPATCH,
    _CATEGORY_MAP,
    _MODBUS_EXCEPTIONS,
    _MODBUS_FC,
    _MQTT_PACKET_TYPES,
    _OPCUA_MESSAGE_TYPES,
    _OPCUA_SECURITY_POLICIES,
    _SNMP_COMMUNITIES,
    _SNMP_OIDS,
    IoTAttackAttempt,
    IoTAttackResult,
    _encode_varint,
    _make_attempt,
    _parse_target,
    _snmp_build_get_request,
    _snmp_encode_length,
    _snmp_encode_oid,
    _snmp_parse_response,
    _snmp_parse_value,
    build_parser,
    print_results,
)


class TestIoTAttackAttempt:
    def test_creation(self) -> None:
        a = IoTAttackAttempt(
            technique="modbus_scan",
            category="iot",
            description="Modbus TCP scanner",
            vulnerable=False,
            details="test",
            error="",
            endpoint="192.168.1.1:502",
            protocol="modbus",
            port=502,
            device_info={},
        )
        assert a.technique == "modbus_scan"
        assert a.vulnerable is False
        assert a.port == 502

    def test_frozen(self) -> None:
        a = IoTAttackAttempt(
            technique="t",
            category="c",
            description="d",
            vulnerable=False,
            details="",
            error="",
            endpoint="e",
            protocol="p",
            port=1,
            device_info={},
        )
        with pytest.raises(AttributeError):
            a.technique = "changed"  # type: ignore[misc]


class TestIoTAttackResult:
    def test_creation(self) -> None:
        r = IoTAttackResult(
            target="192.168.1.1",
            host="192.168.1.1",
            port=502,
            protocols_found=[],
            attempts=[],
            vulnerable_techniques=[],
            issues=[],
            overall_status="secure",
        )
        assert r.overall_status == "secure"
        assert r.port == 502

    def test_frozen(self) -> None:
        r = IoTAttackResult(
            target="t",
            host="h",
            port=1,
            protocols_found=[],
            attempts=[],
            vulnerable_techniques=[],
            issues=[],
            overall_status="secure",
        )
        with pytest.raises(AttributeError):
            r.host = "changed"  # type: ignore[misc]


class TestCategoryMap:
    def test_all_categories_present(self) -> None:
        assert set(_CATEGORY_MAP.keys()) == {"iot"}

    def test_iot_techniques(self) -> None:
        assert set(_CATEGORY_MAP["iot"]) == {
            "modbus_scan",
            "opcua_discovery",
            "bacnet_scan",
            "snmp_brute",
            "mqtt_enum",
        }

    def test_total_techniques(self) -> None:
        total = sum(len(v) for v in _CATEGORY_MAP.values())
        assert total == 5

    def test_dispatch_matches_map(self) -> None:
        for cat in _CATEGORY_MAP:
            assert cat in _CATEGORY_DISPATCH

    def test_all_dispatches_are_coroutines(self) -> None:
        for cat, fn in _CATEGORY_DISPATCH.items():
            assert inspect.iscoroutinefunction(fn), f"{cat} is not a coroutine"


class TestParseTarget:
    def test_host_port(self) -> None:
        host, port = _parse_target("192.168.1.1:502")
        assert host == "192.168.1.1"
        assert port == 502

    def test_host_only(self) -> None:
        host, port = _parse_target("192.168.1.1")
        assert host == "192.168.1.1"
        assert port == 502

    def test_with_scheme(self) -> None:
        host, port = _parse_target("opc.tcp://192.168.1.1:4840")
        assert host == "192.168.1.1"
        assert port == 4840

    def test_mqtt_port(self) -> None:
        _host, port = _parse_target("192.168.1.1:1883")
        assert port == 1883


class TestEncodeVarint:
    def test_zero(self) -> None:
        assert _encode_varint(0) == b"\x00"

    def test_single_byte(self) -> None:
        assert _encode_varint(127) == b"\x7f"

    def test_two_bytes(self) -> None:
        assert _encode_varint(128) == b"\x80\x01"

    def test_large_value(self) -> None:
        result = _encode_varint(65535)
        assert len(result) > 1


class TestSnmpEncodeLength:
    def test_short(self) -> None:
        assert _snmp_encode_length(5) == b"\x05"

    def test_long(self) -> None:
        result = _snmp_encode_length(300)
        assert result[0] & 0x80 != 0


class TestSnmpEncodeOid:
    def test_known_oid(self) -> None:
        result = _snmp_encode_oid("1.3.6.1.2.1.1.1.0")
        assert result[0:1] == b"\x06"
        assert len(result) > 2

    def test_simple_oid(self) -> None:
        result = _snmp_encode_oid("1.0")
        assert len(result) >= 3


class TestSnmpBuildGetRequest:
    def test_builds_valid_packet(self) -> None:
        packet = _snmp_build_get_request("public", "1.3.6.1.2.1.1.1.0")
        assert packet[0:2] == b"\x30\x02" or packet[0:1] == b"\x30"
        assert b"public" in packet

    def test_with_request_id(self) -> None:
        packet = _snmp_build_get_request("private", "1.3.6.1.2.1.1.5.0", request_id=42)
        assert b"private" in packet


class TestSnmpParseValue:
    def test_integer(self) -> None:
        data = bytes([0x02, 0x01, 0x05])
        val, _offset = _snmp_parse_value(data, 0)
        assert val == 5

    def test_string(self) -> None:
        s = b"hello"
        data = bytes([0x04, len(s)]) + s
        val, _offset = _snmp_parse_value(data, 0)
        assert val == "hello"

    def test_oid(self) -> None:
        data = b"\x06\x06\x2b\x06\x01\x02\x01\x01"
        val, _offset = _snmp_parse_value(data, 0)
        assert "." in str(val)


class TestSnmpParseResponse:
    def test_empty(self) -> None:
        result = _snmp_parse_response(b"")
        assert "raw" in result

    def test_short(self) -> None:
        result = _snmp_parse_response(b"\x30\x02\x01\x01")
        assert "raw" in result


class TestModbusConstants:
    def test_function_codes(self) -> None:
        assert 0x01 in _MODBUS_FC
        assert 0x03 in _MODBUS_FC
        assert 0x04 in _MODBUS_FC

    def test_exceptions(self) -> None:
        assert 0x01 in _MODBUS_EXCEPTIONS
        assert 0x02 in _MODBUS_EXCEPTIONS
        assert 0x03 in _MODBUS_EXCEPTIONS


class TestOpcuaConstants:
    def test_message_types(self) -> None:
        assert b"HEL" in _OPCUA_MESSAGE_TYPES
        assert b"ACK" in _OPCUA_MESSAGE_TYPES
        assert b"MSG" in _OPCUA_MESSAGE_TYPES

    def test_security_policies(self) -> None:
        assert len(_OPCUA_SECURITY_POLICIES) == 4


class TestSnmpConstants:
    def test_communities(self) -> None:
        assert "public" in _SNMP_COMMUNITIES
        assert "private" in _SNMP_COMMUNITIES

    def test_oids(self) -> None:
        assert "sysDescr" in _SNMP_OIDS
        assert "sysName" in _SNMP_OIDS


class TestMqttConstants:
    def test_packet_types(self) -> None:
        assert 1 in _MQTT_PACKET_TYPES
        assert _MQTT_PACKET_TYPES[1] == "CONNECT"

    def test_topics(self) -> None:
        from mytools.web.iotattack import _MQTT_TOPICS

        assert "$SYS/#" in _MQTT_TOPICS
        assert "#" in _MQTT_TOPICS


class TestMakeAttempt:
    def test_creation(self) -> None:
        a = _make_attempt(
            "modbus_scan",
            "iot",
            "Modbus scanner",
            True,
            "details",
            "",
            "192.168.1.1:502",
            "modbus",
            502,
        )
        assert a.vulnerable is True
        assert a.technique == "modbus_scan"

    def test_with_device_info(self) -> None:
        info = {"device_id": 1}
        a = _make_attempt(
            "opcua_discovery",
            "iot",
            "desc",
            False,
            "details",
            "",
            "endpoint",
            "opcua",
            4840,
            info,
        )
        assert a.device_info == info


class TestPrintResults:
    def test_secure(self, capsys: pytest.CaptureFixture[str]) -> None:
        r = IoTAttackResult(
            target="192.168.1.1",
            host="192.168.1.1",
            port=502,
            protocols_found=[],
            attempts=[],
            vulnerable_techniques=[],
            issues=[],
            overall_status="secure",
        )
        print_results(r)
        output = capsys.readouterr().out
        assert "IoT & Industrial Attack Testing" in output
        assert "SECURE" in output

    def test_vulnerable(self, capsys: pytest.CaptureFixture[str]) -> None:
        a = IoTAttackAttempt(
            technique="modbus_scan",
            category="iot",
            description="desc",
            vulnerable=True,
            details="modbus found",
            error="",
            endpoint="192.168.1.1:502",
            protocol="modbus",
            port=502,
            device_info={},
        )
        r = IoTAttackResult(
            target="192.168.1.1",
            host="192.168.1.1",
            port=502,
            protocols_found=["modbus"],
            attempts=[a],
            vulnerable_techniques=["modbus_scan"],
            issues=["Test issue"],
            overall_status="vulnerable",
        )
        print_results(r)
        output = capsys.readouterr().out
        assert "VULNERABLE" in output
        assert "Issues:" in output

    def test_multiple_categories(self, capsys: pytest.CaptureFixture[str]) -> None:
        a1 = IoTAttackAttempt(
            technique="modbus_scan",
            category="iot",
            description="d",
            vulnerable=True,
            details="found",
            error="",
            endpoint="e",
            protocol="modbus",
            port=502,
            device_info={},
        )
        a2 = IoTAttackAttempt(
            technique="mqtt_enum",
            category="iot",
            description="d",
            vulnerable=False,
            details="none",
            error="",
            endpoint="e",
            protocol="mqtt",
            port=1883,
            device_info={},
        )
        r = IoTAttackResult(
            target="t",
            host="h",
            port=502,
            protocols_found=["modbus"],
            attempts=[a1, a2],
            vulnerable_techniques=["modbus_scan"],
            issues=[],
            overall_status="vulnerable",
        )
        print_results(r)
        output = capsys.readouterr().out
        assert "VULNERABLE" in output


class TestCLI:
    def test_build_parser(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["192.168.1.1:502"])
        assert args.target == "192.168.1.1:502"

    def test_build_parser_with_categories(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["192.168.1.1:502", "-c", "iot"])
        assert args.categories == ["iot"]

    def test_build_parser_with_output(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["192.168.1.1:502", "-o", "results.json"])
        assert args.output == "results.json"


class TestFreezing:
    def test_attempt_slots(self) -> None:
        assert hasattr(IoTAttackAttempt, "__slots__")

    def test_result_slots(self) -> None:
        assert hasattr(IoTAttackResult, "__slots__")


# ─── SNMP encoding/parsing edge cases ───────────────────────────────────────


class TestSnmpEncodeOidEdges:
    def test_single_part(self) -> None:
        assert _snmp_encode_oid("1") == b"\x06\x01\x00"

    def test_large_part_multibyte(self) -> None:
        result = _snmp_encode_oid("1.3.6.1.4.1.9999")
        assert result[0:1] == b"\x06"
        assert b"\xce\x0f" in result


class TestSnmpParseValueEdges:
    def test_offset_out_of_range(self) -> None:
        val, off = _snmp_parse_value(b"", 0)
        assert val is None
        assert off == 0

    def test_multibyte_oid_sub_identifier(self) -> None:
        data = b"\x06\x07\x2b\x06\x01\x04\x01\xce\x0f"
        val, off = _snmp_parse_value(data, 0)
        assert val == "1.3.6.1.4.1.9999"
        assert off == len(data)

    def test_null_tag(self) -> None:
        val, off = _snmp_parse_value(b"\x05\x00", 0)
        assert val is None
        assert off == 2

    def test_other_tag(self) -> None:
        val, off = _snmp_parse_value(b"\x01\x01\xff", 0)
        assert val == b"\xff"
        assert off == 3

    def test_oid_zero_length(self) -> None:
        val, off = _snmp_parse_value(b"\x06\x00", 0)
        assert val == ""
        assert off == 2


def _snmp_response(
    *,
    pdu_tag: int = 0xA2,
    error_status: int = 0,
    error_index: int = 0,
    with_version: bool = True,
    with_community: bool = True,
    community: str = "public",
    include_varbinds: bool = True,
) -> bytes:
    oid = _snmp_encode_oid("1.3.6.1.2.1.1.5.0")
    value = b"\x04\x06router"
    varbind = b"\x30" + _snmp_encode_length(len(oid) + len(value)) + oid + value
    varbind_list = b"\x30" + _snmp_encode_length(len(varbind)) + varbind
    pdu_body = b"\x02\x04\x00\x00\x00\x01"
    pdu_body += b"\x02\x01" + bytes([error_status])
    pdu_body += b"\x02\x01" + bytes([error_index])
    if include_varbinds:
        pdu_body += varbind_list
    pdu = bytes([pdu_tag]) + _snmp_encode_length(len(pdu_body)) + pdu_body
    body = b""
    if with_version:
        body += b"\x02\x01\x01"
    if with_community:
        body += b"\x04" + _snmp_encode_length(len(community)) + community.encode()
    body += pdu
    return b"\x30" + _snmp_encode_length(len(body)) + body


class TestSnmpParseResponseEdges:
    def test_full_response_with_varbinds(self) -> None:
        data = _snmp_response(include_varbinds=True, error_status=0)
        result = _snmp_parse_response(data)
        assert result["version"] == 1
        assert result["community"] == "public"
        assert result["request_id"] == 1
        assert result["error_status"] == 0
        assert result["error_index"] == 0
        assert result["varbinds"]["1.3.6.1.2.1.1.5.0"] == "router"

    def test_getnext_pdu_with_error(self) -> None:
        data = _snmp_response(pdu_tag=0xA1, error_status=2, include_varbinds=False)
        result = _snmp_parse_response(data)
        assert result["error_status"] == 2
        assert "varbinds" not in result

    def test_response_without_version_community(self) -> None:
        data = _snmp_response(with_version=False, with_community=False)
        result = _snmp_parse_response(data)
        assert "raw" in result


class TestSnmpParseResponseBranches:
    def test_no_outer_sequence(self) -> None:
        result = _snmp_parse_response(b"\x00\x01")
        assert "raw" in result

    def test_pdu_without_inner_sequences(self) -> None:
        body = b"\x02\x01\x01" + b"\x04\x06public" + b"\xa2\x00" + b"\x01"
        data = b"\x30" + _snmp_encode_length(len(body)) + body
        result = _snmp_parse_response(data)
        assert result["community"] == "public"
        assert "varbinds" not in result

    def test_two_varbinds(self) -> None:
        oid1 = _snmp_encode_oid("1.3.6.1.2.1.1.5.0")
        value1 = b"\x04\x06router"
        oid2 = _snmp_encode_oid("1.3.6.1.2.1.1.1.0")
        value2 = b"\x04\x03ups"
        varbind1 = (
            b"\x30" + _snmp_encode_length(len(oid1) + len(value1)) + oid1 + value1
        )
        varbind2 = (
            b"\x30" + _snmp_encode_length(len(oid2) + len(value2)) + oid2 + value2
        )
        varbind_list = (
            b"\x30"
            + _snmp_encode_length(len(varbind1) + len(varbind2))
            + varbind1
            + varbind2
        )
        pdu_body = (
            b"\x02\x04\x00\x00\x00\x01"
            + b"\x02\x01\x00"
            + b"\x02\x01\x00"
            + varbind_list
        )
        pdu = b"\xa2" + _snmp_encode_length(len(pdu_body)) + pdu_body
        body = b"\x02\x01\x01" + b"\x04\x06public" + pdu
        data = b"\x30" + _snmp_encode_length(len(body)) + body
        result = _snmp_parse_response(data)
        assert len(result["varbinds"]) == 2
        assert result["varbinds"]["1.3.6.1.2.1.1.5.0"] == "router"
        assert result["varbinds"]["1.3.6.1.2.1.1.1.0"] == "ups"

    def test_malformed_varbind_spins(self) -> None:
        """Malformed varbind list with a trailing non-sequence byte.

        When the inner loop finds data[offset] != 0x30 it never advances
        ``offset``, so the parse spins.  We exercise the branch from a daemon
        thread and only observe that it did not return.
        """
        import threading

        oid = _snmp_encode_oid("1.3.6.1.2.1.1.5.0")
        value = b"\x04\x06router"
        varbind = b"\x30" + _snmp_encode_length(len(oid) + len(value)) + oid + value
        content = varbind + b"\xff"
        varbind_list = b"\x30" + _snmp_encode_length(len(content)) + content
        pdu_body = (
            b"\x02\x04\x00\x00\x00\x01"
            + b"\x02\x01\x00"
            + b"\x02\x01\x00"
            + varbind_list
        )
        pdu = b"\xa2" + _snmp_encode_length(len(pdu_body)) + pdu_body
        body = b"\x02\x01\x01" + b"\x04\x06public" + pdu
        data = b"\x30" + _snmp_encode_length(len(body)) + body

        t = threading.Thread(
            target=_snmp_parse_response,
            args=(data,),
            daemon=True,
        )
        t.start()
        t.join(timeout=1.0)
        assert t.is_alive(), "malformed varbind list should spin"


# ─── Network scanners (FakeSock) ────────────────────────────────────────────


def _fake_sock(
    *,
    recv_spec: object = b"",
    recvfrom_spec: object = None,
    raise_on: str | None = None,
    send_raiser: Callable[[bytes], bool] | None = None,
):
    """Cria uma classe FakeSock para patchear socket.socket do modulo.

    recv_spec/recvfrom_spec:
      - bytes/None: valor fixo (None -> TimeoutError)
      - list: fila, exaurida -> TimeoutError
      - callable: fn(call_count)
    raise_on: metodo que deve lancar OSError ("recv"/"recvfrom"/"connect"/"send"/"init")
    """

    def _next(spec: object, count: int):
        if spec is None:
            raise TimeoutError("timeout")
        if callable(spec):
            return spec(count)
        if isinstance(spec, list):
            if spec:
                return spec.pop(0)
            raise TimeoutError("timeout")
        return spec

    class _FakeSock:
        def __init__(self, *args: object, **kwargs: object) -> None:
            if raise_on == "init":
                raise OSError("socket init failed")
            self.sends: list[object] = []
            self._recv_n = 0
            self._recvfrom_n = 0

        def settimeout(self, t: object) -> None:
            self.timeout = t

        def connect(self, addr: object) -> None:
            if raise_on == "connect":
                raise OSError("connect failed")
            self.addr = addr

        def close(self) -> None:
            self.closed = True

        def send(self, data: bytes) -> int:
            self.sends.append(data)
            if send_raiser is not None and send_raiser(data):
                raise OSError("send failed")
            if raise_on == "send":
                raise OSError("send failed")
            return len(data)

        def sendall(self, data: bytes) -> None:
            self.send(data)

        def sendto(self, data: bytes, addr: object) -> int:
            self.sends.append((data, addr))
            if raise_on == "send":
                raise OSError("send failed")
            return len(data)

        def recv(self, n: int):
            self._recv_n += 1
            if raise_on == "recv":
                raise OSError("recv failed")
            return _next(recv_spec, self._recv_n)

        def recvfrom(self, n: int):
            self._recvfrom_n += 1
            if raise_on == "recvfrom":
                raise OSError("recvfrom failed")
            return _next(recvfrom_spec, self._recvfrom_n), ("1.2.3.4", 47808)

    return _FakeSock


class TestModbusScan:
    @pytest.mark.asyncio
    async def test_valid_register_response(self) -> None:
        valid = (
            struct.pack(">HHH", 1, 0, 6)
            + b"\x00"
            + bytes([0x03, 0x04])
            + struct.pack(">HH", 0x1234, 0x5678)
        )
        with patch(
            "mytools.web.iotattack.socket.socket",
            new=_fake_sock(recv_spec=[valid]),
        ):
            attempt = await iotattack_module._test_modbus_scan("10.0.0.1", 502, 2.0)
        assert attempt.vulnerable is True
        assert "Read Holding Registers" in attempt.details
        assert attempt.device_info["device_id"] == 0

    @pytest.mark.asyncio
    async def test_exception_response(self) -> None:
        exc = struct.pack(">HHH", 1, 0, 6) + b"\x00" + bytes([0x83, 0x02])
        with patch(
            "mytools.web.iotattack.socket.socket",
            new=_fake_sock(recv_spec=exc),
        ):
            attempt = await iotattack_module._test_modbus_scan("10.0.0.1", 502, 2.0)
        assert attempt.vulnerable is True
        assert "device(s) responded" in attempt.details
        assert len(attempt.device_info["devices"]) > 0

    @pytest.mark.asyncio
    async def test_short_response(self) -> None:
        with patch(
            "mytools.web.iotattack.socket.socket",
            new=_fake_sock(recv_spec=b"\x00\x01\x00\x00"),
        ):
            attempt = await iotattack_module._test_modbus_scan("10.0.0.1", 502, 2.0)
        assert attempt.vulnerable is False
        assert attempt.details == "No Modbus responses"

    @pytest.mark.asyncio
    async def test_connect_error(self) -> None:
        with patch(
            "mytools.web.iotattack.socket.socket",
            new=_fake_sock(raise_on="connect"),
        ):
            attempt = await iotattack_module._test_modbus_scan("10.0.0.1", 502, 2.0)
        assert attempt.vulnerable is False

    @pytest.mark.asyncio
    async def test_unknown_function_code(self) -> None:
        bad = struct.pack(">HHH", 1, 0, 6) + b"\x00" + bytes([0x11, 0x04])
        with patch(
            "mytools.web.iotattack.socket.socket",
            new=_fake_sock(recv_spec=[bad]),
        ):
            attempt = await iotattack_module._test_modbus_scan("10.0.0.1", 502, 2.0)
        assert attempt.vulnerable is False
        assert attempt.details == "No Modbus responses"


class TestOpcuaDiscovery:
    @pytest.mark.asyncio
    async def test_ack_received(self) -> None:
        ack = (
            b"ACK"
            + b"F"
            + struct.pack("<I", 32)
            + struct.pack("<II", 65536, 65536)
            + b"\x00" * 16
        )
        eps = b"MSG" + b"\x00" * 27
        with patch(
            "mytools.web.iotattack.socket.socket",
            new=_fake_sock(recv_spec=[ack, eps]),
        ):
            attempt = await iotattack_module._test_opcua_discovery(
                "10.0.0.1", 4840, 2.0
            )
        assert attempt.vulnerable is True
        assert "Server: detected" in attempt.details
        assert "Policies: 4" in attempt.details

    @pytest.mark.asyncio
    async def test_short_ack(self) -> None:
        with patch(
            "mytools.web.iotattack.socket.socket",
            new=_fake_sock(recv_spec=[b"short", b""]),
        ):
            attempt = await iotattack_module._test_opcua_discovery(
                "10.0.0.1", 4840, 2.0
            )
        assert attempt.vulnerable is True

    @pytest.mark.asyncio
    async def test_connect_error(self) -> None:
        with patch(
            "mytools.web.iotattack.socket.socket",
            new=_fake_sock(raise_on="connect"),
        ):
            attempt = await iotattack_module._test_opcua_discovery(
                "10.0.0.1", 4840, 2.0
            )
        assert attempt.vulnerable is False

    @pytest.mark.asyncio
    async def test_non_ack_header(self) -> None:
        err = b"ERR" + b"\x00" * 25
        with patch(
            "mytools.web.iotattack.socket.socket",
            new=_fake_sock(recv_spec=[err, b""]),
        ):
            attempt = await iotattack_module._test_opcua_discovery(
                "10.0.0.1", 4840, 2.0
            )
        assert attempt.vulnerable is True
        assert "Policies: 4" in attempt.details


class TestBacnetScan:
    @pytest.mark.asyncio
    async def test_device_found(self) -> None:
        i_am = bytearray(20)
        i_am[11] = 0x10
        i_am[14:18] = (1).to_bytes(4, "big")
        i_am[18:20] = (2).to_bytes(2, "big")
        with patch(
            "mytools.web.iotattack.socket.socket",
            new=_fake_sock(recvfrom_spec=[bytes(i_am)]),
        ):
            attempt = await iotattack_module._test_bacnet_scan("10.0.0.1", 47808, 2.0)
        assert attempt.vulnerable is True
        assert "Devices: 1" in attempt.details
        assert "(ID:1, Vendor:2)" in attempt.details

    @pytest.mark.asyncio
    async def test_no_devices_timeout(self) -> None:
        with patch(
            "mytools.web.iotattack.socket.socket",
            new=_fake_sock(recvfrom_spec=None),
        ):
            attempt = await iotattack_module._test_bacnet_scan("10.0.0.1", 47808, 2.0)
        assert attempt.vulnerable is False
        assert attempt.details == "No BACnet devices found"

    @pytest.mark.asyncio
    async def test_recvfrom_error(self) -> None:
        with patch(
            "mytools.web.iotattack.socket.socket",
            new=_fake_sock(raise_on="recvfrom"),
        ):
            attempt = await iotattack_module._test_bacnet_scan("10.0.0.1", 47808, 2.0)
        assert attempt.vulnerable is False

    @pytest.mark.asyncio
    async def test_full_loop_iterations(self) -> None:
        i_am = bytearray(20)
        i_am[11] = 0x10
        i_am[14:18] = (1).to_bytes(4, "big")
        i_am[18:20] = (2).to_bytes(2, "big")
        with patch(
            "mytools.web.iotattack.socket.socket",
            new=_fake_sock(recvfrom_spec=bytes(i_am)),
        ):
            attempt = await iotattack_module._test_bacnet_scan("10.0.0.1", 47808, 2.0)
        assert attempt.vulnerable is True
        assert "Devices: 5" in attempt.details

    @pytest.mark.asyncio
    async def test_short_and_non_i_am_data(self) -> None:
        bad_pdu = bytearray(20)
        bad_pdu[11] = 0x00
        exact = bytearray(14)
        exact[11] = 0x10
        with patch(
            "mytools.web.iotattack.socket.socket",
            new=_fake_sock(recvfrom_spec=[b"short", bytes(bad_pdu), bytes(exact)]),
        ):
            attempt = await iotattack_module._test_bacnet_scan("10.0.0.1", 47808, 2.0)
        assert attempt.vulnerable is False
        assert attempt.details == "No BACnet devices found"


class TestSnmpBrute:
    @pytest.mark.asyncio
    async def test_valid_communities(self) -> None:
        ok = _snmp_response(include_varbinds=True, error_status=0)
        with patch(
            "mytools.web.iotattack.socket.socket",
            new=_fake_sock(recvfrom_spec=ok),
        ):
            attempt = await iotattack_module._test_snmp_brute("10.0.0.1", 161, 2.0)
        assert attempt.vulnerable is True
        assert "Communities: public" in attempt.details
        assert "sysName: router" in attempt.details

    @pytest.mark.asyncio
    async def test_timeout_all(self) -> None:
        with patch(
            "mytools.web.iotattack.socket.socket",
            new=_fake_sock(recvfrom_spec=None),
        ):
            attempt = await iotattack_module._test_snmp_brute("10.0.0.1", 161, 2.0)
        assert attempt.vulnerable is False
        assert attempt.details == "No valid communities found"

    @pytest.mark.asyncio
    async def test_recvfrom_error_continues(self) -> None:
        with patch(
            "mytools.web.iotattack.socket.socket",
            new=_fake_sock(raise_on="recvfrom"),
        ):
            attempt = await iotattack_module._test_snmp_brute("10.0.0.1", 161, 2.0)
        assert attempt.vulnerable is False

    @pytest.mark.asyncio
    async def test_socket_init_error(self) -> None:
        with patch(
            "mytools.web.iotattack.socket.socket",
            new=_fake_sock(raise_on="init"),
        ):
            attempt = await iotattack_module._test_snmp_brute("10.0.0.1", 161, 2.0)
        assert attempt.vulnerable is False

    @pytest.mark.asyncio
    async def test_error_status_skips_community(self) -> None:
        bad = _snmp_response(error_status=2, include_varbinds=False)
        with patch(
            "mytools.web.iotattack.socket.socket",
            new=_fake_sock(recvfrom_spec=bad),
        ):
            attempt = await iotattack_module._test_snmp_brute("10.0.0.1", 161, 2.0)
        assert attempt.vulnerable is False
        assert attempt.details == "No valid communities found"

    @pytest.mark.asyncio
    async def test_non_sysname_varbind(self) -> None:
        oid = _snmp_encode_oid("1.3.6.1.2.1.1.1.0")
        value = b"\x04\x07APC UPS"
        varbind = b"\x30" + _snmp_encode_length(len(oid) + len(value)) + oid + value
        varbind_list = b"\x30" + _snmp_encode_length(len(varbind)) + varbind
        pdu_body = (
            b"\x02\x04\x00\x00\x00\x01"
            + b"\x02\x01\x00"
            + b"\x02\x01\x00"
            + varbind_list
        )
        pdu = b"\xa2" + _snmp_encode_length(len(pdu_body)) + pdu_body
        body = b"\x02\x01\x01" + b"\x04\x06public" + pdu
        data = b"\x30" + _snmp_encode_length(len(body)) + body
        with patch(
            "mytools.web.iotattack.socket.socket",
            new=_fake_sock(recvfrom_spec=data),
        ):
            attempt = await iotattack_module._test_snmp_brute("10.0.0.1", 161, 2.0)
        assert attempt.vulnerable is True
        assert "Communities: public" in attempt.details
        assert "sysName:" not in attempt.details


class TestMqttEnum:
    @pytest.mark.asyncio
    async def test_full_flow(self) -> None:
        connack = b"\x20\x02\x00\x01"
        suback = b"\x90\x02\x00\x00\x00"
        publish = b"\x30\x00\x03foohello"

        def _raise_on_subscribe(data: bytes) -> bool:
            return bool(data) and data[0] == 0x82

        with patch(
            "mytools.web.iotattack.socket.socket",
            new=_fake_sock(
                recv_spec=[connack, suback, publish],
                send_raiser=_raise_on_subscribe,
            ),
        ):
            attempt = await iotattack_module._test_mqtt_enum("10.0.0.1", 1883, 2.0)
        assert attempt.vulnerable is True
        assert "Topics: 1, Messages: 1" in attempt.details
        assert "Session: present" in attempt.details

    @pytest.mark.asyncio
    async def test_no_topics_timeout(self) -> None:
        with patch(
            "mytools.web.iotattack.socket.socket",
            new=_fake_sock(recv_spec=[b"\x20\x02\x00\x00"]),
        ):
            attempt = await iotattack_module._test_mqtt_enum("10.0.0.1", 1883, 2.0)
        assert attempt.vulnerable is False
        assert attempt.details == "No MQTT topics found"

    @pytest.mark.asyncio
    async def test_empty_data_breaks(self) -> None:
        with patch(
            "mytools.web.iotattack.socket.socket",
            new=_fake_sock(recv_spec=[b"\x20\x02\x00\x00", b""]),
        ):
            attempt = await iotattack_module._test_mqtt_enum("10.0.0.1", 1883, 2.0)
        assert attempt.vulnerable is False

    @pytest.mark.asyncio
    async def test_connect_error(self) -> None:
        with patch(
            "mytools.web.iotattack.socket.socket",
            new=_fake_sock(raise_on="connect"),
        ):
            attempt = await iotattack_module._test_mqtt_enum("10.0.0.1", 1883, 2.0)
        assert attempt.vulnerable is False

    @pytest.mark.asyncio
    async def test_short_connack(self) -> None:
        with patch(
            "mytools.web.iotattack.socket.socket",
            new=_fake_sock(recv_spec=[b"short"]),
        ):
            attempt = await iotattack_module._test_mqtt_enum("10.0.0.1", 1883, 2.0)
        assert attempt.vulnerable is False
        assert attempt.details == "No MQTT topics found"

    @pytest.mark.asyncio
    async def test_short_suback(self) -> None:
        with patch(
            "mytools.web.iotattack.socket.socket",
            new=_fake_sock(recv_spec=[b"\x20\x02\x00\x00", b"\x90\x00"]),
        ):
            attempt = await iotattack_module._test_mqtt_enum("10.0.0.1", 1883, 2.0)
        assert attempt.vulnerable is False

    @pytest.mark.asyncio
    async def test_other_msg_type(self) -> None:
        with patch(
            "mytools.web.iotattack.socket.socket",
            new=_fake_sock(recv_spec=[b"\x20\x02\x00\x00", b"\x20\x00"]),
        ):
            attempt = await iotattack_module._test_mqtt_enum("10.0.0.1", 1883, 2.0)
        assert attempt.vulnerable is False


# ─── _test_iot dispatcher ───────────────────────────────────────────────────


def _make_iot_attempt(tech: str) -> IoTAttackAttempt:
    return _make_attempt(
        tech,
        "iot",
        "desc",
        False,
        "details",
        "",
        "10.0.0.1:502",
        tech.split("_")[0],
        502,
    )


class TestTestIot:
    @pytest.mark.asyncio
    async def test_all_success(self) -> None:
        fns = [
            "_test_modbus_scan",
            "_test_opcua_discovery",
            "_test_bacnet_scan",
            "_test_snmp_brute",
            "_test_mqtt_enum",
        ]
        with patch.multiple(
            "mytools.web.iotattack",
            **{fn: AsyncMock(return_value=_make_iot_attempt(fn)) for fn in fns},
        ):
            r1 = await iotattack_module._test_iot("10.0.0.1", 502, 5.0)
            r2 = await iotattack_module._test_iot("10.0.0.1", 6000, 5.0)
        assert len(r1) == 5
        assert len(r2) == 5

    @pytest.mark.asyncio
    async def test_one_error(self) -> None:
        fns = [
            "_test_modbus_scan",
            "_test_opcua_discovery",
            "_test_bacnet_scan",
            "_test_snmp_brute",
            "_test_mqtt_enum",
        ]
        with patch.multiple(
            "mytools.web.iotattack",
            **{fn: AsyncMock(side_effect=Exception("boom")) for fn in fns},
        ):
            results = await iotattack_module._test_iot("10.0.0.1", 502, 5.0)
        assert len(results) == 5
        assert all(a.error == "boom" for a in results)


# ─── print_results branches ─────────────────────────────────────────────────


class TestPrintResultsSecureCategory:
    def test_secure_category(self, capsys: pytest.CaptureFixture[str]) -> None:
        a = IoTAttackAttempt(
            technique="modbus_scan",
            category="iot",
            description="d",
            vulnerable=False,
            details="none",
            error="",
            endpoint="e",
            protocol="modbus",
            port=502,
            device_info={},
        )
        r = IoTAttackResult(
            target="t",
            host="h",
            port=502,
            protocols_found=[],
            attempts=[a],
            vulnerable_techniques=[],
            issues=[],
            overall_status="secure",
        )
        print_results(r)
        output = capsys.readouterr().out
        assert "iot: secure" in output


# ─── run_scan ───────────────────────────────────────────────────────────────


class TestRunScan:
    @pytest.mark.asyncio
    async def test_secure_default_categories(self) -> None:
        with patch(
            "mytools.web.iotattack._CATEGORY_DISPATCH",
            {"iot": AsyncMock(return_value=[])},
        ):
            result = await iotattack_module.run_scan("10.0.0.1:502", None, 5.0, None)
        assert result.overall_status == "secure"
        assert result.port == 502

    @pytest.mark.asyncio
    async def test_vulnerable_protocols(self) -> None:
        attempt = _make_iot_attempt("modbus_scan")
        attempt = IoTAttackAttempt(
            technique="modbus_scan",
            category="iot",
            description="d",
            vulnerable=True,
            details="found",
            error="",
            endpoint="10.0.0.1:502",
            protocol="modbus",
            port=502,
            device_info={},
        )
        with patch(
            "mytools.web.iotattack._CATEGORY_DISPATCH",
            {"iot": AsyncMock(return_value=[attempt])},
        ):
            result = await iotattack_module.run_scan("10.0.0.1:502", ["iot"], 5.0, None)
        assert result.overall_status == "vulnerable"
        assert result.protocols_found == ["modbus"]
        assert result.vulnerable_techniques == ["modbus_scan"]

    @pytest.mark.asyncio
    async def test_unknown_category(self) -> None:
        result = await iotattack_module.run_scan("10.0.0.1:502", ["bogus"], 5.0, None)
        assert result.overall_status == "secure"
        assert result.attempts == []

    @pytest.mark.asyncio
    async def test_tester_error(self) -> None:
        with patch(
            "mytools.web.iotattack._CATEGORY_DISPATCH",
            {"iot": AsyncMock(side_effect=Exception("boom"))},
        ):
            result = await iotattack_module.run_scan("10.0.0.1:502", ["iot"], 5.0, None)
        assert result.issues == ["Errors: iot_error"]

    @pytest.mark.asyncio
    async def test_output_file(self) -> None:
        with (
            patch(
                "mytools.web.iotattack._CATEGORY_DISPATCH",
                {"iot": AsyncMock(return_value=[])},
            ),
            patch("mytools.web.iotattack.write_output") as mock_out,
        ):
            result = await iotattack_module.run_scan(
                "10.0.0.1:502", ["iot"], 5.0, "out.json"
            )
        mock_out.assert_called_once()
        assert result.overall_status == "secure"


class TestRunOnce:
    def test_vulnerable_returns_1(self) -> None:
        result = MagicMock()
        result.overall_status = "vulnerable"
        with patch(
            "mytools.web.iotattack.run_scan",
            new_callable=AsyncMock,
            return_value=result,
        ):
            assert iotattack_module.run_once(MagicMock()) == 1

    def test_secure_returns_0(self) -> None:
        result = MagicMock()
        result.overall_status = "secure"
        with patch(
            "mytools.web.iotattack.run_scan",
            new_callable=AsyncMock,
            return_value=result,
        ):
            assert iotattack_module.run_once(MagicMock()) == 0


class TestMain:
    def test_main(self) -> None:
        with patch("mytools.web.iotattack.run_main_loop", return_value=0):
            assert iotattack_module.main() == 0

    def test_main_guard(self) -> None:
        with (
            patch("mytools.core.utils.run_main_loop", side_effect=SystemExit(0)),
            pytest.raises(SystemExit) as exc_info,
        ):
            runpy.run_module("mytools.web.iotattack", run_name="__main__")
        assert exc_info.value.code == 0
