"""
tests/test_detector.py
Unit tests for drift detection logic.
No real devices or API keys required.
"""

import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.detector import (
    DriftDetector, DriftResult, DriftItem,
    CiscoParser, PaloAltoParser, ArubaParser,
    MOCK_LIVE_CONFIGS,
)


GOLDEN_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "golden_configs")


class TestCiscoParser:

    def test_extracts_hostname(self):
        config = "hostname my-router"
        s = CiscoParser.extract_sections(config)
        assert s["hostname"] == "my-router"

    def test_extracts_ntp_servers(self):
        config = "ntp server 10.0.0.1\nntp server 10.0.0.2"
        s = CiscoParser.extract_sections(config)
        assert s["ntp_servers"] == ["10.0.0.1", "10.0.0.2"]

    def test_extracts_snmp_community(self):
        config = "snmp-server community SECRET RO"
        s = CiscoParser.extract_sections(config)
        assert s["snmp_community"] == "SECRET"

    def test_detects_password_encryption(self):
        config = "service password-encryption"
        s = CiscoParser.extract_sections(config)
        assert s["password_encryption"] is True

    def test_detects_http_disabled(self):
        config = "no ip http server\nno ip http secure-server"
        s = CiscoParser.extract_sections(config)
        assert s["http_server_disabled"] is True
        assert s["https_server_disabled"] is True


class TestPaloAltoParser:

    def test_extracts_hostname(self):
        config = "<hostname>pa-fw-01</hostname>"
        s = PaloAltoParser.extract_sections(config)
        assert s["hostname"] == "pa-fw-01"

    def test_extracts_dns(self):
        config = "<primary>8.8.8.8</primary><secondary>8.8.4.4</secondary>"
        s = PaloAltoParser.extract_sections(config)
        assert s["dns_primary"] == "8.8.8.8"
        assert s["dns_secondary"] == "8.8.4.4"

    def test_extracts_ntp(self):
        config = "<ntp-server-address>10.0.0.1</ntp-server-address>"
        s = PaloAltoParser.extract_sections(config)
        assert s["ntp_primary"] == "10.0.0.1"


class TestArubaParser:

    def test_extracts_hostname(self):
        config = "hostname aruba-sw-01"
        s = ArubaParser.extract_sections(config)
        assert s["hostname"] == "aruba-sw-01"

    def test_extracts_vlans(self):
        config = "vlan 1\nvlan 10\nvlan 20"
        s = ArubaParser.extract_sections(config)
        assert "1" in s["vlans"]
        assert "10" in s["vlans"]

    def test_detects_ssh_v2(self):
        config = "ip ssh version 2"
        s = ArubaParser.extract_sections(config)
        assert s["ssh_v2"] is True

    def test_detects_telnet_disabled(self):
        config = "no ip telnet"
        s = ArubaParser.extract_sections(config)
        assert s["telnet_disabled"] is True

    def test_extracts_radius_key(self):
        config = "radius-server host 10.0.0.1 key MYKEY"
        s = ArubaParser.extract_sections(config)
        assert s["radius_key"] == "MYKEY"


class TestDriftDetector:

    def setup_method(self):
        self.detector = DriftDetector(golden_dir=GOLDEN_DIR)

    def test_cisco_mock_has_drift(self):
        result = self.detector.check_mock("cisco")
        assert isinstance(result, DriftResult)
        assert result.has_drift is True

    def test_paloalto_mock_has_drift(self):
        result = self.detector.check_mock("paloalto")
        assert isinstance(result, DriftResult)
        assert result.has_drift is True

    def test_aruba_mock_has_drift(self):
        result = self.detector.check_mock("aruba")
        assert isinstance(result, DriftResult)
        assert result.has_drift is True

    def test_drift_items_are_list(self):
        result = self.detector.check_mock("cisco")
        assert isinstance(result.drift_items, list)
        assert len(result.drift_items) > 0

    def test_drift_item_has_severity(self):
        result = self.detector.check_mock("cisco")
        for item in result.drift_items:
            assert item.severity in ("critical", "warning", "info")

    def test_critical_drift_detected_cisco(self):
        result = self.detector.check_mock("cisco")
        severities = [d.severity for d in result.drift_items]
        assert "critical" in severities

    def test_no_drift_when_configs_match(self):
        golden = self.detector._load_golden("cisco")
        result = self.detector._compare("cisco", "test-device", golden, golden)
        assert result.has_drift is False
        assert result.drift_items == []

    def test_device_name_set(self):
        result = self.detector.check_mock("cisco")
        assert result.device_name == "mock-cisco-01"

    def test_checked_at_populated(self):
        result = self.detector.check_mock("cisco")
        assert result.checked_at != ""

    def test_missing_golden_raises_error(self):
        detector = DriftDetector(golden_dir="/nonexistent/path")
        with pytest.raises(FileNotFoundError):
            detector.check_mock("cisco")
