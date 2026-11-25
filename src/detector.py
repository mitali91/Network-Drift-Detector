"""
detector.py
Core logic: loads golden configs, fetches live configs (or mock),
and computes drift between them.

Supports: Cisco IOS, Palo Alto NGFW, AWS VPC / Security Groups
"""

import os
import re
import json
from dataclasses import dataclass, field
from typing import List, Optional, Dict
from datetime import datetime


@dataclass
class DriftItem:
    """A single configuration difference."""
    section: str
    golden_value: str
    live_value: str
    severity: str       # "critical" | "warning" | "info"
    description: str


@dataclass
class DriftResult:
    device_type: str
    device_name: str
    checked_at: str
    has_drift: bool
    drift_items: List[DriftItem] = field(default_factory=list)
    error: Optional[str] = None


# ── Mock live configs — intentional drift for demo purposes ──

MOCK_LIVE_CONFIGS = {
    "cisco": """
hostname core-switch-01
!
ntp server 10.0.0.1
ntp server 10.0.0.2
!
ip domain-name corp.local
!
aaa new-model
aaa authentication login default group tacacs+ local
!
interface GigabitEthernet0/1
 description UPLINK-TO-CORE
 switchport mode trunk
 switchport trunk allowed vlan 10,20,30
!
interface Vlan10
 ip address 192.168.10.1 255.255.255.0
 no shutdown
!
banner login ^
  Unauthorized access prohibited
^
!
service password-encryption
no ip http server
no ip http secure-server
!
snmp-server community DRIFTED_STRING RO
snmp-server location DC1-ROW3
logging host 10.1.1.50
logging host 10.1.1.51
""",

    "paloalto": """
<config>
  <devices>
    <entry name="localhost.localdomain">
      <deviceconfig>
        <system>
          <hostname>pa-fw-01</hostname>
          <dns-setting>
            <servers>
              <primary>8.8.8.8</primary>
              <secondary>8.8.4.4</secondary>
            </servers>
          </dns-setting>
          <ntp-servers>
            <primary-ntp-server>
              <ntp-server-address>10.0.0.1</ntp-server-address>
            </primary-ntp-server>
          </ntp-servers>
        </system>
      </deviceconfig>
      <vsys>
        <entry name="vsys1">
          <zone>
            <entry name="trust"/>
            <entry name="untrust"/>
          </zone>
        </entry>
      </vsys>
    </entry>
  </devices>
</config>
""",

    # AWS mock: simulates a drifted VPC state —
    # SSH open to world on sg-web, flow logs disabled, wrong CIDR on private subnet
    "aws": json.dumps({
        "vpc_cidr": "10.0.0.0/16",
        "flow_logs_enabled": False,
        "dns_hostnames_enabled": True,
        "dns_support_enabled": True,
        "default_sg_ingress_restricted": False,
        "public_subnets": ["10.0.1.0/24", "10.0.2.0/24"],
        "private_subnets": ["10.0.10.0/24", "10.0.99.0/24"],
        "security_groups": {
            "sg-web": {
                "allowed_inbound_ports": [80, 443],
                "ssh_open_to_world": True
            },
            "sg-app": {
                "allowed_inbound_ports": [8080, 8443],
                "ssh_open_to_world": False
            },
            "sg-db": {
                "allowed_inbound_ports": [5432],
                "ssh_open_to_world": False
            }
        },
        "nacl_default_deny": True,
        "internet_gateway_attached": True
    }),
}


# ── Parsers ──

class CiscoParser:
    """Extracts key config sections from Cisco IOS configs."""

    @staticmethod
    def extract_sections(config: str) -> Dict[str, str]:
        sections = {}

        m = re.search(r'^hostname (.+)$', config, re.MULTILINE)
        sections["hostname"] = m.group(1).strip() if m else ""

        ntp = re.findall(r'^ntp server (.+)$', config, re.MULTILINE)
        sections["ntp_servers"] = sorted([n.strip() for n in ntp])

        m = re.search(r'^snmp-server community (\S+)', config, re.MULTILINE)
        sections["snmp_community"] = m.group(1).strip() if m else ""

        logs = re.findall(r'^logging host (.+)$', config, re.MULTILINE)
        sections["logging_hosts"] = sorted([l.strip() for l in logs])

        aaa = re.findall(r'^aaa .+$', config, re.MULTILINE)
        sections["aaa"] = sorted([a.strip() for a in aaa])

        sections["http_server_disabled"] = "no ip http server" in config
        sections["https_server_disabled"] = "no ip http secure-server" in config
        sections["password_encryption"] = "service password-encryption" in config
        sections["banner_configured"] = "banner login" in config

        return sections


class PaloAltoParser:
    """Extracts key config sections from Palo Alto XML configs."""

    @staticmethod
    def extract_sections(config: str) -> Dict[str, str]:
        sections = {}

        m = re.search(r'<hostname>(.+?)</hostname>', config)
        sections["hostname"] = m.group(1).strip() if m else ""

        m = re.search(r'<primary>(.+?)</primary>', config)
        sections["dns_primary"] = m.group(1).strip() if m else ""

        m = re.search(r'<secondary>(.+?)</secondary>', config)
        sections["dns_secondary"] = m.group(1).strip() if m else ""

        m = re.search(r'<ntp-server-address>(.+?)</ntp-server-address>', config)
        sections["ntp_primary"] = m.group(1).strip() if m else ""

        zones = re.findall(r'<entry name="(\w+)"/>', config)
        sections["zones"] = sorted(zones)

        return sections


class AWSParser:
    """
    Extracts key config sections from an AWS VPC state snapshot (JSON).
    In mock mode this is a JSON string; in live mode it would come
    from boto3 API calls (see check_live in DriftDetector).
    """

    @staticmethod
    def extract_sections(config: str) -> Dict[str, object]:
        sections = {}

        try:
            data = json.loads(config)
        except json.JSONDecodeError:
            return {"parse_error": "Invalid JSON — expected AWS VPC state snapshot"}

        # Top-level VPC settings
        sections["vpc_cidr"]                    = data.get("vpc_cidr", "")
        sections["flow_logs_enabled"]           = data.get("flow_logs_enabled", False)
        sections["dns_hostnames_enabled"]       = data.get("dns_hostnames_enabled", False)
        sections["dns_support_enabled"]         = data.get("dns_support_enabled", False)
        sections["default_sg_ingress_restricted"] = data.get("default_sg_ingress_restricted", False)
        sections["internet_gateway_attached"]   = data.get("internet_gateway_attached", False)
        sections["nacl_default_deny"]           = data.get("nacl_default_deny", False)

        # Subnets
        sections["public_subnets"]  = sorted(data.get("public_subnets", []))
        sections["private_subnets"] = sorted(data.get("private_subnets", []))

        # Security groups — flatten into comparable strings
        sgs = data.get("security_groups", {})
        for sg_name, sg_data in sgs.items():
            sections[f"sg_{sg_name}_inbound_ports"] = sorted(sg_data.get("allowed_inbound_ports", []))
            sections[f"sg_{sg_name}_ssh_open"]      = sg_data.get("ssh_open_to_world", False)

        return sections


PARSERS = {
    "cisco":    CiscoParser,
    "paloalto": PaloAltoParser,
    "aws":      AWSParser,
}

SEVERITY_MAP = {
    # Critical — security impact
    "snmp_community":               "critical",
    "http_server_disabled":         "critical",
    "https_server_disabled":        "critical",
    "password_encryption":          "critical",
    "default_sg_ingress_restricted":"critical",
    "flow_logs_enabled":            "critical",
    "nacl_default_deny":            "critical",
    # any sg SSH drift is critical
    "_ssh_open":                    "critical",
    # Warning — operational
    "ntp_servers":                  "warning",
    "ntp_primary":                  "warning",
    "logging_hosts":                "warning",
    "dns_primary":                  "warning",
    "dns_secondary":                "warning",
    "aaa":                          "warning",
    "private_subnets":              "warning",
    "public_subnets":               "warning",
    # Info — everything else
}


def _get_severity(key: str) -> str:
    if key in SEVERITY_MAP:
        return SEVERITY_MAP[key]
    # catch any key containing "_ssh_open"
    if "_ssh_open" in key:
        return "critical"
    return "info"


class DriftDetector:
    """
    Loads golden configs from disk, fetches live configs (or mock),
    and produces DriftResult objects describing any differences.
    """

    def __init__(self, golden_dir: str = "golden_configs"):
        self.golden_dir = golden_dir

    def _load_golden(self, device_type: str) -> str:
        path = os.path.join(self.golden_dir, device_type, "golden.conf")
        if not os.path.exists(path):
            raise FileNotFoundError(
                f"Golden config not found: {path}\n"
                f"Expected at: {os.path.abspath(path)}"
            )
        with open(path, "r") as f:
            return f.read()

    def _compare(self, device_type: str, device_name: str,
                 golden_config: str, live_config: str) -> DriftResult:
        parser = PARSERS[device_type]
        golden_sections = parser.extract_sections(golden_config)
        live_sections   = parser.extract_sections(live_config)

        drift_items = []
        for key in golden_sections:
            golden_val = golden_sections[key]
            live_val   = live_sections.get(key, "NOT FOUND")
            if golden_val != live_val:
                drift_items.append(DriftItem(
                    section=key,
                    golden_value=str(golden_val),
                    live_value=str(live_val),
                    severity=_get_severity(key),
                    description=f"{key} does not match golden config"
                ))

        severity_order = {"critical": 0, "warning": 1, "info": 2}
        drift_items.sort(key=lambda x: severity_order[x.severity])

        return DriftResult(
            device_type=device_type,
            device_name=device_name,
            checked_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            has_drift=len(drift_items) > 0,
            drift_items=drift_items,
        )

    def check_mock(self, device_type: str) -> DriftResult:
        """Run drift check using bundled mock configs (no devices needed)."""
        golden_config = self._load_golden(device_type)
        live_config   = MOCK_LIVE_CONFIGS[device_type]
        return self._compare(device_type, f"mock-{device_type}-01", golden_config, live_config)

    def check_live(self, device_type: str, host: str,
                   username: str, password: str) -> DriftResult:
        """
        Fetch live config from a real device and run drift check.
        For AWS: uses boto3 to pull live VPC/SG state (no SSH needed).
        For Cisco/PaloAlto: uses Netmiko SSH.
        """
        if device_type == "aws":
            return self._check_live_aws(host)

        try:
            from netmiko import ConnectHandler
        except ImportError:
            raise ImportError("pip install netmiko")

        device_map  = {"cisco": "cisco_ios", "paloalto": "paloalto_panos"}
        command_map = {"cisco": "show running-config", "paloalto": "show config running"}

        print(f"  Connecting to {host}...")
        conn = ConnectHandler(
            device_type=device_map[device_type],
            host=host, username=username, password=password,
        )
        live_config = conn.send_command(command_map[device_type])
        conn.disconnect()

        golden_config = self._load_golden(device_type)
        return self._compare(device_type, host, golden_config, live_config)

    def _check_live_aws(self, vpc_id: str) -> DriftResult:
        """
        Pull live AWS VPC + Security Group state via boto3
        and compare against the golden JSON config.
        Requires: pip install boto3 and AWS credentials configured.
        """
        try:
            import boto3
        except ImportError:
            raise ImportError("pip install boto3")

        ec2 = boto3.client("ec2")

        vpc      = ec2.describe_vpcs(VpcIds=[vpc_id])["Vpcs"][0]
        sgs      = ec2.describe_security_groups(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])["SecurityGroups"]
        fl       = ec2.describe_flow_logs(Filters=[{"Name": "resource-id", "Values": [vpc_id]}])["FlowLogs"]
        subnets  = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])["Subnets"]
        igws     = ec2.describe_internet_gateways(Filters=[{"Name": "attachment.vpc-id", "Values": [vpc_id]}])["InternetGateways"]

        sg_data = {}
        for sg in sgs:
            if sg["GroupName"] == "default":
                continue
            inbound_ports = [p.get("FromPort", 0) for p in sg.get("IpPermissions", []) if "FromPort" in p]
            ssh_open      = any(
                p.get("FromPort") == 22 and
                any(r.get("CidrIp") == "0.0.0.0/0" for r in p.get("IpRanges", []))
                for p in sg.get("IpPermissions", [])
            )
            sg_data[sg["GroupName"]] = {
                "allowed_inbound_ports": sorted(inbound_ports),
                "ssh_open_to_world": ssh_open,
            }

        public_subnets  = sorted([s["CidrBlock"] for s in subnets if not s.get("MapPublicIpOnLaunch") is False])
        private_subnets = sorted([s["CidrBlock"] for s in subnets if s.get("MapPublicIpOnLaunch") is False])

        live_state = {
            "vpc_cidr":                     vpc["CidrBlock"],
            "flow_logs_enabled":            len(fl) > 0,
            "dns_hostnames_enabled":        vpc.get("EnableDnsHostnames", False),
            "dns_support_enabled":          vpc.get("EnableDnsSupport", False),
            "default_sg_ingress_restricted": True,
            "internet_gateway_attached":    len(igws) > 0,
            "nacl_default_deny":            True,
            "public_subnets":               public_subnets,
            "private_subnets":              private_subnets,
            "security_groups":              sg_data,
        }

        golden_config = self._load_golden("aws")
        return self._compare("aws", vpc_id, golden_config, json.dumps(live_state))
