#!/usr/bin/env python3
"""
network-drift-detector: Detects configuration drift between live network
devices and golden configs stored in Git.

Supports Cisco IOS, Palo Alto NGFW, and AWS VPC/MIST devices.
Runs in mock mode out of the box — no devices required.

Usage:
    python detect.py --mock                          # demo with sample configs
    python detect.py --device cisco --host 10.0.0.1 # live Cisco device
    python detect.py --all --mock                    # check all device types
    python detect.py --mock --save reports/drift.json
"""

import argparse
import sys
import os
from src.detector import DriftDetector
from src.formatter import print_report, save_report


def parse_args():
    parser = argparse.ArgumentParser(
        description="Network config drift detector — compares live device configs against golden configs",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python detect.py --mock                              # run demo with sample configs
  python detect.py --mock --device cisco               # mock Cisco only
  python detect.py --mock --device paloalto            # mock Palo Alto only
  python detect.py --mock --device aws               # mock AWS VPC only
  python detect.py --device cisco --host 10.0.0.1 --username admin --password secret
  python detect.py --mock --save reports/drift.json    # save report to JSON
        """
    )
    parser.add_argument(
        "--device", "-d",
        choices=["cisco", "paloalto", "aws", "all"],
        default="all",
        help="Device type to check (default: all)"
    )
    parser.add_argument(
        "--mock",
        action="store_true",
        help="Run in mock mode using sample configs (no real devices needed)"
    )
    parser.add_argument(
        "--host",
        type=str,
        help="Device IP or hostname (live mode only)"
    )
    parser.add_argument(
        "--username",
        type=str,
        help="Device username (live mode only)"
    )
    parser.add_argument(
        "--password",
        type=str,
        help="Device password (live mode only)"
    )
    parser.add_argument(
        "--golden-dir",
        type=str,
        default="golden_configs",
        help="Path to golden configs directory (default: golden_configs/)"
    )
    parser.add_argument(
        "--save", "-s",
        type=str,
        help="Save drift report to JSON file"
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable colored terminal output"
    )
    return parser.parse_args()


def main():
    args = parse_args()

    if not args.mock and not args.host:
        print("\nError: Either --mock or --host is required.")
        print("  Run a demo:   python detect.py --mock")
        print("  Live device:  python detect.py --device cisco --host 10.0.0.1 --username admin --password secret\n")
        sys.exit(1)

    device_types = (
        ["cisco", "paloalto", "aws"]
        if args.device == "all"
        else [args.device]
    )

    detector = DriftDetector(golden_dir=args.golden_dir)
    all_results = []

    for device_type in device_types:
        print(f"\n🔍  Checking {device_type.upper()} config...")

        if args.mock:
            result = detector.check_mock(device_type)
        else:
            if not args.username or not args.password:
                print(f"Error: --username and --password required for live mode.")
                sys.exit(1)
            result = detector.check_live(
                device_type=device_type,
                host=args.host,
                username=args.username,
                password=args.password,
            )
        all_results.append(result)

    print_report(all_results, use_color=not args.no_color)

    if args.save:
        save_report(all_results, args.save)
        print(f"\n✅  Report saved to: {args.save}")

    # Exit with non-zero code if drift detected (useful for CI/CD pipelines)
    has_drift = any(r.has_drift for r in all_results)
    sys.exit(1 if has_drift else 0)


if __name__ == "__main__":
    main()
