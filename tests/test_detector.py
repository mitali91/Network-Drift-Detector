"""
tests/test_detector.py
Unit tests for drift detection logic.
No real devices, AWS credentials, or API keys required.
"""

import json
import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.detector import (
    DriftDetector, DriftResult, DriftItem,
    CiscoParser, PaloAltoParser, AWSParser,
    MOCK_LIVE_CONFIGS,
)

GOLDEN_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "golden_configs")


class TestCiscoParser:

    def test_extracts_hostname(self):
        s = CiscoParser.extract_sections("hostname my-router")
        assert s["hostname"] == "my-router"

    def test_extracts_ntp_servers(self):
        s = CiscoParser.extract_sections("ntp server 10.0.0.1\nntp server 10.0.0.2")
        assert s["ntp_servers"] == ["10.0.0.1", "10.0.0.2"]

    def test_extracts_snmp_community(self):
        s = CiscoParser.extract_sections("snmp-server community SECRET RO")
        assert s["snmp_community"] == "SECRET"

    def test_detects_password_encryption(self):
        s = CiscoParser.extract_sections("service password-encryption")
        assert s["password_encryption"] is True

    def test_detects_http_disabled(self):
        s = CiscoParser.extract_sections("no ip http server\nno ip http secure-server")
        assert s["http_server_disabled"] is True
        assert s["https_server_disabled"] is True


class TestPaloAltoParser:

    def test_extracts_hostname(self):
        s = PaloAltoParser.extract_sections("<hostname>pa-fw-01</hostname>")
        assert s["hostname"] == "pa-fw-01"

    def test_extracts_dns(self):
        s = PaloAltoParser.extract_sections("<primary>8.8.8.8</primary><secondary>8.8.4.4</secondary>")
        assert s["dns_primary"] == "8.8.8.8"
        assert s["dns_secondary"] == "8.8.4.4"

    def test_extracts_ntp(self):
        s = PaloAltoParser.extract_sections("<ntp-server-address>10.0.0.1</ntp-server-address>")
        assert s["ntp_primary"] == "10.0.0.1"


class TestAWSParser:

    def setup_method(self):
        self.golden = json.dumps({
            "vpc_cidr": "10.0.0.0/16",
            "flow_logs_enabled": True,
            "dns_hostnames_enabled": True,
            "dns_support_enabled": True,
            "default_sg_ingress_restricted": True,
            "internet_gateway_attached": True,
            "nacl_default_deny": True,
            "public_subnets": ["10.0.1.0/24"],
            "private_subnets": ["10.0.10.0/24"],
            "security_groups": {
                "sg-web": {"allowed_inbound_ports": [80, 443], "ssh_open_to_world": False}
            }
        })

    def test_extracts_vpc_cidr(self):
        s = AWSParser.extract_sections(self.golden)
        assert s["vpc_cidr"] == "10.0.0.0/16"

    def test_extracts_flow_logs(self):
        s = AWSParser.extract_sections(self.golden)
        assert s["flow_logs_enabled"] is True

    def test_extracts_sg_ports(self):
        s = AWSParser.extract_sections(self.golden)
        assert s["sg_sg-web_inbound_ports"] == [80, 443]

    def test_extracts_sg_ssh(self):
        s = AWSParser.extract_sections(self.golden)
        assert s["sg_sg-web_ssh_open"] is False

    def test_extracts_subnets(self):
        s = AWSParser.extract_sections(self.golden)
        assert "10.0.1.0/24" in s["public_subnets"]
        assert "10.0.10.0/24" in s["private_subnets"]

    def test_invalid_json_handled(self):
        s = AWSParser.extract_sections("not json")
        assert "parse_error" in s


class TestDriftDetector:

    def setup_method(self):
        self.detector = DriftDetector(golden_dir=GOLDEN_DIR)

    def test_cisco_mock_has_drift(self):
        result = self.detector.check_mock("cisco")
        assert isinstance(result, DriftResult)
        assert result.has_drift is True

    def test_paloalto_mock_has_drift(self):
        result = self.detector.check_mock("paloalto")
        assert result.has_drift is True

    def test_aws_mock_has_drift(self):
        result = self.detector.check_mock("aws")
        assert isinstance(result, DriftResult)
        assert result.has_drift is True

    def test_aws_drift_includes_critical(self):
        result = self.detector.check_mock("aws")
        severities = [d.severity for d in result.drift_items]
        assert "critical" in severities

    def test_aws_detects_ssh_open(self):
        result = self.detector.check_mock("aws")
        ssh_items = [d for d in result.drift_items if "ssh_open" in d.section]
        assert len(ssh_items) > 0
        assert ssh_items[0].severity == "critical"

    def test_aws_detects_flow_logs_off(self):
        result = self.detector.check_mock("aws")
        fl_items = [d for d in result.drift_items if "flow_logs" in d.section]
        assert len(fl_items) > 0

    def test_drift_items_are_list(self):
        result = self.detector.check_mock("cisco")
        assert isinstance(result.drift_items, list)

    def test_drift_item_severity_valid(self):
        result = self.detector.check_mock("cisco")
        for item in result.drift_items:
            assert item.severity in ("critical", "warning", "info")

    def test_no_drift_when_configs_match(self):
        golden = self.detector._load_golden("cisco")
        result = self.detector._compare("cisco", "test-device", golden, golden)
        assert result.has_drift is False
        assert result.drift_items == []

    def test_aws_no_drift_when_configs_match(self):
        golden = self.detector._load_golden("aws")
        result = self.detector._compare("aws", "vpc-test", golden, golden)
        assert result.has_drift is False

    def test_missing_golden_raises_error(self):
        detector = DriftDetector(golden_dir="/nonexistent/path")
        with pytest.raises(FileNotFoundError):
            detector.check_mock("cisco")

    def test_device_name_set(self):
        result = self.detector.check_mock("aws")
        assert result.device_name == "mock-aws-01"
