"""Analyze CSV or JSON files and report amount of PII-like data.

PII fields analyzed:
- name
- age
- gender
- city

Usage examples:
  python pii_analyzer.py --file data.csv
  python pii_analyzer.py --file data.json --pretty
"""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Any, Dict, List, Tuple

PII_FIELDS: Tuple[str, ...] = ("name", "age", "gender", "city")


class DataFormatError(ValueError):
    """Raised when input data cannot be interpreted as row-based records."""


def _normalize_key(key: str) -> str:
    return key.strip().lower()


def _has_value(value: Any) -> bool:
    if value is None:
        return False
    if isinstance(value, str):
        return value.strip() != ""
    return True


def load_csv(path: Path) -> List[Dict[str, Any]]:
    with path.open("r", newline="", encoding="utf-8") as csv_file:
        reader = csv.DictReader(csv_file)
        if reader.fieldnames is None:
            raise DataFormatError("CSV file has no header row.")
        records = [dict(row) for row in reader]
    return records


def _coerce_json_to_records(raw: Any) -> List[Dict[str, Any]]:
    if isinstance(raw, dict):
        return [raw]

    if isinstance(raw, list):
        if not raw:
            return []
        if not all(isinstance(item, dict) for item in raw):
            raise DataFormatError("JSON list must contain only objects/records.")
        return list(raw)

    raise DataFormatError("JSON must be an object or a list of objects.")


def load_json(path: Path) -> List[Dict[str, Any]]:
    with path.open("r", encoding="utf-8") as json_file:
        raw = json.load(json_file)
    return _coerce_json_to_records(raw)


def load_records(path: Path) -> List[Dict[str, Any]]:
    suffix = path.suffix.lower()
    if suffix == ".csv":
        return load_csv(path)
    if suffix == ".json":
        return load_json(path)

    raise DataFormatError(
        f"Unsupported file extension '{path.suffix}'. Use .csv or .json files."
    )


def analyze_pii(records: List[Dict[str, Any]]) -> Dict[str, Any]:
    total_records = len(records)
    field_presence = {field: 0 for field in PII_FIELDS}
    records_with_any_pii = 0

    for record in records:
        normalized_record = {_normalize_key(k): v for k, v in record.items()}
        has_any = False

        for field in PII_FIELDS:
            value = normalized_record.get(field)
            if _has_value(value):
                field_presence[field] += 1
                has_any = True

        if has_any:
            records_with_any_pii += 1

    pii_values_total = sum(field_presence.values())
    possible_pii_values = total_records * len(PII_FIELDS)
    coverage_pct = (pii_values_total / possible_pii_values * 100) if possible_pii_values else 0.0

    return {
        "total_records": total_records,
        "records_with_any_pii": records_with_any_pii,
        "records_with_any_pii_pct": round(
            (records_with_any_pii / total_records * 100) if total_records else 0.0,
            2,
        ),
        "field_presence": field_presence,
        "pii_values_total": pii_values_total,
        "possible_pii_values": possible_pii_values,
        "coverage_pct": round(coverage_pct, 2),
    }


def print_report(report: Dict[str, Any], pretty: bool = False) -> None:
    if pretty:
        print(json.dumps(report, indent=2))
        return

    print("PII Analysis Report")
    print("===================")
    print(f"Total records: {report['total_records']}")
    print(
        f"Records with any PII: {report['records_with_any_pii']} "
        f"({report['records_with_any_pii_pct']}%)"
    )
    print("\nField-level presence:")

    for field, count in report["field_presence"].items():
        pct = (count / report["total_records"] * 100) if report["total_records"] else 0.0
        print(f"- {field}: {count} records ({pct:.2f}%)")

    print("\nOverall PII density:")
    print(
        f"- Populated PII values: {report['pii_values_total']} / "
        f"{report['possible_pii_values']} ({report['coverage_pct']}%)"
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Analyze a CSV or JSON file for PII fields (name, age, gender, city)."
    )
    parser.add_argument("--file", required=True, help="Path to CSV or JSON file")
    parser.add_argument(
        "--pretty",
        action="store_true",
        help="Print report in JSON format",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    path = Path(args.file)

    if not path.exists() or not path.is_file():
        raise SystemExit(f"Input file does not exist: {path}")

    try:
        records = load_records(path)
    except json.JSONDecodeError as exc:
        raise SystemExit(f"Invalid JSON format: {exc}") from exc
    except DataFormatError as exc:
        raise SystemExit(str(exc)) from exc

    report = analyze_pii(records)
    print_report(report, pretty=args.pretty)


if __name__ == "__main__":
    main()
