#!/usr/bin/env python3
"""Tests for iotattack.py."""

from __future__ import annotations

import inspect

import pytest

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
            technique="modbus_scan", category="iot",
            description="Modbus TCP scanner", vulnerable=False,
            details="test", error="", endpoint="192.168.1.1:502",
            protocol="modbus", port=502, device_info={},
        )
        assert a.technique == "modbus_scan"
        assert a.vulnerable is False
        assert a.port == 502

    def test_frozen(self) -> None:
        a = IoTAttackAttempt(
            technique="t", category="c", description="d",
            vulnerable=False, details="", error="", endpoint="e",
            protocol="p", port=1, device_info={},
        )
        with pytest.raises(AttributeError):
            a.technique = "changed"  # type: ignore[misc]


class TestIoTAttackResult:
    def test_creation(self) -> None:
        r = IoTAttackResult(
            target="192.168.1.1", host="192.168.1.1", port=502,
            protocols_found=[], attempts=[], vulnerable_techniques=[],
            issues=[], overall_status="secure",
        )
        assert r.overall_status == "secure"
        assert r.port == 502

    def test_frozen(self) -> None:
        r = IoTAttackResult(
            target="t", host="h", port=1, protocols_found=[],
            attempts=[], vulnerable_techniques=[], issues=[],
            overall_status="secure",
        )
        with pytest.raises(AttributeError):
            r.host = "changed"  # type: ignore[misc]


class TestCategoryMap:
    def test_all_categories_present(self) -> None:
        assert set(_CATEGORY_MAP.keys()) == {"iot"}

    def test_iot_techniques(self) -> None:
        assert set(_CATEGORY_MAP["iot"]) == {
            "modbus_scan", "opcua_discovery", "bacnet_scan", "snmp_brute", "mqtt_enum",
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
            "modbus_scan", "iot", "Modbus scanner", True,
            "details", "", "192.168.1.1:502", "modbus", 502,
        )
        assert a.vulnerable is True
        assert a.technique == "modbus_scan"

    def test_with_device_info(self) -> None:
        info = {"device_id": 1}
        a = _make_attempt(
            "opcua_discovery", "iot", "desc", False,
            "details", "", "endpoint", "opcua", 4840, info,
        )
        assert a.device_info == info


class TestPrintResults:
    def test_secure(self, capsys: pytest.CaptureFixture[str]) -> None:
        r = IoTAttackResult(
            target="192.168.1.1", host="192.168.1.1", port=502,
            protocols_found=[], attempts=[], vulnerable_techniques=[],
            issues=[], overall_status="secure",
        )
        print_results(r)
        output = capsys.readouterr().out
        assert "IoT & Industrial Attack Testing" in output
        assert "SECURE" in output

    def test_vulnerable(self, capsys: pytest.CaptureFixture[str]) -> None:
        a = IoTAttackAttempt(
            technique="modbus_scan", category="iot", description="desc",
            vulnerable=True, details="modbus found", error="",
            endpoint="192.168.1.1:502", protocol="modbus", port=502,
            device_info={},
        )
        r = IoTAttackResult(
            target="192.168.1.1", host="192.168.1.1", port=502,
            protocols_found=["modbus"], attempts=[a],
            vulnerable_techniques=["modbus_scan"],
            issues=["Test issue"], overall_status="vulnerable",
        )
        print_results(r)
        output = capsys.readouterr().out
        assert "VULNERABLE" in output
        assert "Issues:" in output

    def test_multiple_categories(self, capsys: pytest.CaptureFixture[str]) -> None:
        a1 = IoTAttackAttempt(
            technique="modbus_scan", category="iot", description="d",
            vulnerable=True, details="found", error="",
            endpoint="e", protocol="modbus", port=502, device_info={},
        )
        a2 = IoTAttackAttempt(
            technique="mqtt_enum", category="iot", description="d",
            vulnerable=False, details="none", error="",
            endpoint="e", protocol="mqtt", port=1883, device_info={},
        )
        r = IoTAttackResult(
            target="t", host="h", port=502,
            protocols_found=["modbus"], attempts=[a1, a2],
            vulnerable_techniques=["modbus_scan"], issues=[],
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
