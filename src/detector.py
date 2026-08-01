"""
detector.py
Core logic: loads golden configs, fetches live configs (or mock),
and computes drift between them.
"""

import os
import re
from dataclasses import dataclass, field
from typing import List, Optional, Dict
from datetime import datetime


@dataclass
class DriftItem:
    """A single configuration difference."""
    section: str        # e.g. "ntp", "bgp", "aaa"
    golden_value: str   # what it should be
    live_value: str     # what it actually is
    severity: str       # "critical" | "warning" | "info"
    description: str    # human-readable explanation


@dataclass
class DriftResult:
    device_type: str
    device_name: str
    checked_at: str
    has_drift: bool
    drift_items: List[DriftItem] = field(default_factory=list)
    error: Optional[str] = None


# ── Mock live configs — simulating real devices with intentional drift ──

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
    "aruba": """
hostname aruba-sw-01
!
ntp server 10.0.0.1
!
vlan 1
vlan 10
   name CORP
vlan 20
   name GUEST
vlan 99
!
interface 1/1/1
   no shutdown
   description UPLINK
   vlan trunk native 1
   vlan trunk allowed 10,20
!
aaa authentication login privilege-mode
aaa authorization commands all default local
!
radius-server host 10.2.0.10 key WRONG_KEY
!
ip ssh version 2
no ip telnet
!
logging 10.1.1.50
""",
}

# ── Golden config section parsers ──

class CiscoParser:
    """Extracts key config sections from Cisco IOS configs."""

    @staticmethod
    def extract_sections(config: str) -> Dict[str, str]:
        sections = {}

        # Hostname
        m = re.search(r'^hostname (.+)$', config, re.MULTILINE)
        sections["hostname"] = m.group(1).strip() if m else ""

        # NTP servers
        ntp = re.findall(r'^ntp server (.+)$', config, re.MULTILINE)
        sections["ntp_servers"] = sorted([n.strip() for n in ntp])

        # SNMP community
        m = re.search(r'^snmp-server community (\S+)', config, re.MULTILINE)
        sections["snmp_community"] = m.group(1).strip() if m else ""

        # Logging hosts
        logs = re.findall(r'^logging host (.+)$', config, re.MULTILINE)
        sections["logging_hosts"] = sorted([l.strip() for l in logs])

        # AAA
        aaa = re.findall(r'^aaa .+$', config, re.MULTILINE)
        sections["aaa"] = sorted([a.strip() for a in aaa])

        # HTTP server status
        sections["http_server_disabled"] = "no ip http server" in config
        sections["https_server_disabled"] = "no ip http secure-server" in config

        # Password encryption
        sections["password_encryption"] = "service password-encryption" in config

        # Banner
        sections["banner_configured"] = "banner login" in config

        return sections


class PaloAltoParser:
    """Extracts key config sections from Palo Alto XML configs."""

    @staticmethod
    def extract_sections(config: str) -> Dict[str, str]:
        sections = {}

        # Hostname
        m = re.search(r'<hostname>(.+?)</hostname>', config)
        sections["hostname"] = m.group(1).strip() if m else ""

        # DNS primary
        m = re.search(r'<primary>(.+?)</primary>', config)
        sections["dns_primary"] = m.group(1).strip() if m else ""

        # DNS secondary
        m = re.search(r'<secondary>(.+?)</secondary>', config)
        sections["dns_secondary"] = m.group(1).strip() if m else ""

        # NTP primary
        m = re.search(r'<ntp-server-address>(.+?)</ntp-server-address>', config)
        sections["ntp_primary"] = m.group(1).strip() if m else ""

        # Zones
        zones = re.findall(r'<entry name="(\w+)"/>', config)
        sections["zones"] = sorted(zones)

        return sections


class ArubaParser:
    """Extracts key config sections from Aruba/AOS-CX configs."""

    @staticmethod
    def extract_sections(config: str) -> Dict[str, str]:
        sections = {}

        # Hostname
        m = re.search(r'^hostname (.+)$', config, re.MULTILINE)
        sections["hostname"] = m.group(1).strip() if m else ""

        # NTP
        ntp = re.findall(r'^ntp server (.+)$', config, re.MULTILINE)
        sections["ntp_servers"] = sorted([n.strip() for n in ntp])

        # VLANs
        vlans = re.findall(r'^vlan (\d+)', config, re.MULTILINE)
        sections["vlans"] = sorted([v.strip() for v in vlans])

        # RADIUS key
        m = re.search(r'radius-server host \S+ key (\S+)', config)
        sections["radius_key"] = m.group(1).strip() if m else ""

        # SSH/Telnet
        sections["ssh_v2"] = "ip ssh version 2" in config
        sections["telnet_disabled"] = "no ip telnet" in config

        # Logging
        logs = re.findall(r'^logging (.+)$', config, re.MULTILINE)
        sections["logging_hosts"] = sorted([l.strip() for l in logs])

        # AAA
        aaa = re.findall(r'^aaa .+$', config, re.MULTILINE)
        sections["aaa"] = sorted([a.strip() for a in aaa])

        return sections


PARSERS = {
    "cisco": CiscoParser,
    "paloalto": PaloAltoParser,
    "aruba": ArubaParser,
}


class DriftDetector:
    """
    Loads golden configs from disk, fetches live configs (or mock),
    and produces DriftResult objects describing any differences.
    """

    def __init__(self, golden_dir: str = "golden_configs"):
        self.golden_dir = golden_dir

    def _load_golden(self, device_type: str) -> str:
        """Load golden config file for a given device type."""
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
        """Compare golden vs live config and return a DriftResult."""
        parser = PARSERS[device_type]
        golden_sections = parser.extract_sections(golden_config)
        live_sections = parser.extract_sections(live_config)

        drift_items = []

        for key in golden_sections:
            golden_val = golden_sections[key]
            live_val = live_sections.get(key, "NOT FOUND")

            if golden_val != live_val:
                # Determine severity based on section type
                if key in ("snmp_community", "radius_key", "password_encryption",
                           "http_server_disabled", "https_server_disabled",
                           "ssh_v2", "telnet_disabled"):
                    severity = "critical"
                elif key in ("ntp_servers", "ntp_primary", "logging_hosts",
                             "dns_primary", "dns_secondary", "aaa"):
                    severity = "warning"
                else:
                    severity = "info"

                drift_items.append(DriftItem(
                    section=key,
                    golden_value=str(golden_val),
                    live_value=str(live_val),
                    severity=severity,
                    description=f"{key} does not match golden config"
                ))

        # Sort: critical first, then warning, then info
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
        live_config = MOCK_LIVE_CONFIGS[device_type]
        device_name = f"mock-{device_type}-01"
        return self._compare(device_type, device_name, golden_config, live_config)

    def check_live(self, device_type: str, host: str,
                   username: str, password: str) -> DriftResult:
        """
        Fetch live config from a real device via SSH and run drift check.
        Requires netmiko and network access to the device.
        """
        try:
            from netmiko import ConnectHandler
        except ImportError:
            raise ImportError("netmiko is required for live mode: pip install netmiko")

        device_map = {
            "cisco": "cisco_ios",
            "paloalto": "paloalto_panos",
            "aruba": "aruba_aoscx",
        }

        command_map = {
            "cisco": "show running-config",
            "paloalto": "show config running",
            "aruba": "show running-config",
        }

        print(f"  Connecting to {host}...")
        connection = ConnectHandler(
            device_type=device_map[device_type],
            host=host,
            username=username,
            password=password,
        )
        live_config = connection.send_command(command_map[device_type])
        connection.disconnect()

        golden_config = self._load_golden(device_type)
        return self._compare(device_type, host, golden_config, live_config)
