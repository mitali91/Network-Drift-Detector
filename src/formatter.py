"""
formatter.py
Handles all output: colored terminal drift report and JSON file export.
"""

import json
from datetime import datetime
from typing import List, TYPE_CHECKING

if TYPE_CHECKING:
    from .detector import DriftResult

# ANSI color codes
RESET  = "\033[0m"
BOLD   = "\033[1m"
RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
BLUE   = "\033[94m"
GRAY   = "\033[90m"
WHITE  = "\033[97m"

SEVERITY_COLORS = {
    "critical": RED,
    "warning":  YELLOW,
    "info":     BLUE,
}


def c(text: str, color: str, use_color: bool = True) -> str:
    if not use_color:
        return text
    return f"{color}{text}{RESET}"


def severity_label(severity: str, use_color: bool = True) -> str:
    color = SEVERITY_COLORS.get(severity, WHITE)
    label = f"[{severity.upper():^8}]"
    return c(label, BOLD + color, use_color)


def print_report(results: List["DriftResult"], use_color: bool = True) -> None:
    """Print formatted drift report for all devices."""
    sep_thick = c("═" * 64, GRAY, use_color)
    sep_thin  = c("─" * 64, GRAY, use_color)

    print(f"\n{sep_thick}")
    print(c("  NETWORK CONFIG DRIFT REPORT", BOLD + WHITE, use_color))
    print(c(f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", GRAY, use_color))
    print(sep_thick)

    total_drift   = sum(1 for r in results if r.has_drift)
    total_clean   = len(results) - total_drift
    total_critical = sum(
        1 for r in results
        for d in r.drift_items
        if d.severity == "critical"
    )

    # Summary line
    print(f"\n  Devices checked : {c(str(len(results)), BOLD + WHITE, use_color)}")
    print(f"  Drift detected  : {c(str(total_drift), BOLD + RED if total_drift else BOLD + GREEN, use_color)}")
    print(f"  Clean           : {c(str(total_clean), BOLD + GREEN, use_color)}")
    print(f"  Critical issues : {c(str(total_critical), BOLD + RED if total_critical else BOLD + GREEN, use_color)}")

    for result in results:
        print(f"\n{sep_thin}")
        status = (
            c("✗  DRIFT DETECTED", BOLD + RED, use_color)
            if result.has_drift
            else c("✓  CLEAN", BOLD + GREEN, use_color)
        )
        print(f"  {c(result.device_type.upper(), BOLD + CYAN, use_color)}  {result.device_name}  —  {status}")
        print(f"  {c('Checked at:', GRAY, use_color)} {result.checked_at}")

        if result.error:
            print(f"\n  {c('ERROR:', BOLD + RED, use_color)} {result.error}")
            continue

        if not result.has_drift:
            print(f"\n  {c('All sections match golden config.', GREEN, use_color)}")
            continue

        print(f"\n  {c(f'{len(result.drift_items)} drift item(s) found:', BOLD, use_color)}\n")

        for item in result.drift_items:
            print(f"  {severity_label(item.severity, use_color)}  {c(item.section, BOLD, use_color)}")
            print(f"    {c('Golden :', GRAY, use_color)} {c(str(item.golden_value), GREEN, use_color)}")
            print(f"    {c('Live   :', GRAY, use_color)} {c(str(item.live_value),   RED,   use_color)}")
            print()

    print(sep_thick)

    if total_drift > 0:
        print(c("\n  ⚠️   Drift detected — review and remediate before next change window.\n", BOLD + YELLOW, use_color))
    else:
        print(c("\n  ✅  All devices match golden config.\n", BOLD + GREEN, use_color))


def save_report(results: List["DriftResult"], filepath: str) -> None:
    """Save drift report to JSON file."""
    output = {
        "generated_at": datetime.now().isoformat(),
        "summary": {
            "total_devices": len(results),
            "drift_detected": sum(1 for r in results if r.has_drift),
            "clean": sum(1 for r in results if not r.has_drift),
            "critical_issues": sum(
                1 for r in results
                for d in r.drift_items
                if d.severity == "critical"
            ),
        },
        "results": [
            {
                "device_type": r.device_type,
                "device_name": r.device_name,
                "checked_at": r.checked_at,
                "has_drift": r.has_drift,
                "error": r.error,
                "drift_items": [
                    {
                        "section": d.section,
                        "severity": d.severity,
                        "description": d.description,
                        "golden_value": d.golden_value,
                        "live_value": d.live_value,
                    }
                    for d in r.drift_items
                ],
            }
            for r in results
        ],
    }
    with open(filepath, "w") as f:
        json.dump(output, f, indent=2)
