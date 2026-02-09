"""Output formatters for scan results."""

from __future__ import annotations

import csv
import json
from pathlib import Path

from bigr.models import ScanResult


def write_json(result: ScanResult, path: str = "assets.json") -> Path:
    """Write scan results to JSON file."""
    output_path = Path(path)
    with output_path.open("w", encoding="utf-8") as f:
        json.dump(result.to_dict(), f, indent=2, ensure_ascii=False)
    return output_path


def write_csv(result: ScanResult, path: str = "assets.csv") -> Path:
    """Write scan results to CSV file."""
    output_path = Path(path)
    fieldnames = [
        "ip", "mac", "hostname", "vendor", "open_ports",
        "os_hint", "bigr_category", "bigr_category_tr",
        "confidence_score", "confidence_level", "scan_method",
    ]

    with output_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for asset in result.assets:
            row = asset.to_dict()
            row["open_ports"] = ",".join(str(p) for p in row["open_ports"])
            writer.writerow({k: row[k] for k in fieldnames})

    return output_path
