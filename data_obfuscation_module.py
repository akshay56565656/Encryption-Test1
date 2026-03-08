"""Data obfuscation module for process/static/time-series style tabular data.

Technique implemented from the provided methodology:
1) Core columns are renamed (tag obfuscation).
2) Core numeric values are transformed with per-column affine mapping:
      obfuscated = original * scale + offset
3) Non-core columns can pass through unchanged.
4) A protected manifest (encrypted with a shared secret) enables controlled
   de-obfuscation by trusted parties.

Security note:
- This materially raises reverse-engineering difficulty when the manifest and
  secret key are protected.
- No obfuscation method can *guarantee* absolute impossibility of reverse
  engineering in every adversarial setting.
"""

from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import hmac
import json
import math
import secrets
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, MutableMapping, Optional, Sequence, Tuple


Row = Dict[str, Any]


@dataclass(frozen=True)
class ColumnTransform:
    """Reversible affine transform for one core numeric column."""

    original_name: str
    obfuscated_name: str
    scale: float
    offset: float

    def forward(self, value: float) -> float:
        return value * self.scale + self.offset

    def reverse(self, value: float) -> float:
        if self.scale == 0:
            raise ValueError(f"Invalid transform for '{self.original_name}': scale is zero.")
        return (value - self.offset) / self.scale


class DataObfuscator:
    """Obfuscates/de-obfuscates tabular data via tag rename + affine transforms."""

    def __init__(self, secret_key: str):
        if not secret_key:
            raise ValueError("secret_key must be a non-empty string")
        self._secret_key = secret_key

    # ----------------------------- Public API ----------------------------- #

    def obfuscate_records(
        self,
        records: Sequence[Row],
        core_columns: Sequence[str],
        keep_columns: Optional[Sequence[str]] = None,
        alias_prefix: str = "signal",
        alias_start: int = 1,
    ) -> Tuple[List[Row], str]:
        """Obfuscate records and return (obfuscated_records, encrypted_manifest)."""
        if not records:
            raise ValueError("records must contain at least one row")

        keep_columns_set = set(keep_columns or [])
        transforms = self._build_transforms(records, core_columns, alias_prefix, alias_start)

        obfuscated_rows: List[Row] = []
        for row in records:
            out: Row = {}

            # Pass through requested non-core columns.
            for key in keep_columns_set:
                if key in row:
                    out[key] = row[key]

            # Obfuscate core columns.
            for t in transforms:
                if t.original_name not in row:
                    continue
                out[t.obfuscated_name] = self._obfuscate_numeric_value(row[t.original_name], t)

            obfuscated_rows.append(out)

        manifest = {
            "version": 1,
            "algorithm": "affine_rename_v1",
            "transforms": [
                {
                    "original_name": t.original_name,
                    "obfuscated_name": t.obfuscated_name,
                    "scale": t.scale,
                    "offset": t.offset,
                }
                for t in transforms
            ],
            "keep_columns": list(keep_columns_set),
        }
        encrypted_manifest = self._encrypt_manifest(manifest)
        return obfuscated_rows, encrypted_manifest

    def deobfuscate_records(self, obfuscated_records: Sequence[Row], encrypted_manifest: str) -> List[Row]:
        """Restore obfuscated records using a valid encrypted manifest."""
        manifest = self._decrypt_manifest(encrypted_manifest)
        transforms = [
            ColumnTransform(
                original_name=item["original_name"],
                obfuscated_name=item["obfuscated_name"],
                scale=float(item["scale"]),
                offset=float(item["offset"]),
            )
            for item in manifest["transforms"]
        ]

        restore_map = {t.obfuscated_name: t for t in transforms}
        keep_columns = set(manifest.get("keep_columns", []))

        deobfuscated_rows: List[Row] = []
        for row in obfuscated_records:
            out: Row = {}

            for key in keep_columns:
                if key in row:
                    out[key] = row[key]

            for obf_name, transform in restore_map.items():
                if obf_name not in row:
                    continue
                out[transform.original_name] = self._deobfuscate_numeric_value(row[obf_name], transform)

            deobfuscated_rows.append(out)

        return deobfuscated_rows

    # ----------------------------- Internals ----------------------------- #

    def _build_transforms(
        self,
        records: Sequence[Row],
        core_columns: Sequence[str],
        alias_prefix: str,
        alias_start: int,
    ) -> List[ColumnTransform]:
        rng = secrets.SystemRandom()
        transforms: List[ColumnTransform] = []

        for index, col in enumerate(core_columns, start=alias_start):
            values = [self._to_float(row[col]) for row in records if col in row and self._is_number_like(row[col])]
            if not values:
                raise ValueError(f"Core column '{col}' missing or non-numeric in provided records")

            std = self._std(values)
            spread = max(std, 1.0)

            # Keep positive scale to preserve monotonic behavior/trends.
            scale = rng.uniform(0.35, 2.75)
            # Offset tied to data spread but not too small.
            offset = rng.uniform(-4.0 * spread, 4.0 * spread)

            transforms.append(
                ColumnTransform(
                    original_name=col,
                    obfuscated_name=f"{alias_prefix}_{index}",
                    scale=scale,
                    offset=offset,
                )
            )

        return transforms

    def _obfuscate_numeric_value(self, value: Any, transform: ColumnTransform) -> Any:
        if not self._is_number_like(value):
            return value
        return transform.forward(self._to_float(value))

    def _deobfuscate_numeric_value(self, value: Any, transform: ColumnTransform) -> Any:
        if not self._is_number_like(value):
            return value
        return transform.reverse(self._to_float(value))

    @staticmethod
    def _is_number_like(value: Any) -> bool:
        try:
            float(value)
            return True
        except (TypeError, ValueError):
            return False

    @staticmethod
    def _to_float(value: Any) -> float:
        return float(value)

    @staticmethod
    def _std(values: Sequence[float]) -> float:
        if not values:
            return 0.0
        mean = sum(values) / len(values)
        variance = sum((v - mean) ** 2 for v in values) / len(values)
        return math.sqrt(variance)

    def _encrypt_manifest(self, manifest: Mapping[str, Any]) -> str:
        plain = json.dumps(manifest, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        nonce = secrets.token_bytes(16)
        stream = self._keystream(nonce, len(plain))
        cipher = bytes(p ^ s for p, s in zip(plain, stream))
        tag = hmac.new(self._key_material(), nonce + cipher, hashlib.sha256).digest()
        payload = nonce + tag + cipher
        return base64.urlsafe_b64encode(payload).decode("utf-8")

    def _decrypt_manifest(self, encrypted_manifest: str) -> MutableMapping[str, Any]:
        payload = base64.urlsafe_b64decode(encrypted_manifest.encode("utf-8"))
        if len(payload) < 48:
            raise ValueError("Invalid encrypted manifest")

        nonce = payload[:16]
        tag = payload[16:48]
        cipher = payload[48:]

        expected = hmac.new(self._key_material(), nonce + cipher, hashlib.sha256).digest()
        if not hmac.compare_digest(tag, expected):
            raise ValueError("Manifest authentication failed (wrong key or tampered manifest)")

        stream = self._keystream(nonce, len(cipher))
        plain = bytes(c ^ s for c, s in zip(cipher, stream))
        return json.loads(plain.decode("utf-8"))

    def _key_material(self) -> bytes:
        return hashlib.sha256(self._secret_key.encode("utf-8")).digest()

    def _keystream(self, nonce: bytes, length: int) -> bytes:
        key = self._key_material()
        out = bytearray()
        counter = 0
        while len(out) < length:
            block = hashlib.sha256(key + nonce + counter.to_bytes(8, "big")).digest()
            out.extend(block)
            counter += 1
        return bytes(out[:length])


def load_table(path: Path) -> List[Row]:
    suffix = path.suffix.lower()
    if suffix == ".json":
        with path.open("r", encoding="utf-8") as f:
            raw = json.load(f)
        if isinstance(raw, dict):
            return [raw]
        if isinstance(raw, list) and all(isinstance(r, dict) for r in raw):
            return raw
        raise ValueError("JSON input must be an object or list of objects")

    if suffix == ".csv":
        with path.open("r", encoding="utf-8", newline="") as f:
            reader = csv.DictReader(f)
            if reader.fieldnames is None:
                raise ValueError("CSV file has no header")
            return [dict(row) for row in reader]

    raise ValueError("Unsupported file extension. Use .csv or .json")


def write_table(path: Path, rows: Sequence[Row]) -> None:
    suffix = path.suffix.lower()
    if suffix == ".json":
        with path.open("w", encoding="utf-8") as f:
            json.dump(list(rows), f, indent=2, ensure_ascii=False)
        return

    if suffix == ".csv":
        if not rows:
            raise ValueError("Cannot write empty rows to CSV")
        fieldnames = list(rows[0].keys())
        with path.open("w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)
        return

    raise ValueError("Unsupported output extension. Use .csv or .json")


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Data obfuscation module (rename + affine transform)")
    p.add_argument("mode", choices=["obfuscate", "deobfuscate"])
    p.add_argument("--in", dest="input_path", required=True, help="Input CSV/JSON path")
    p.add_argument("--out", dest="output_path", required=True, help="Output CSV/JSON path")
    p.add_argument("--key", required=True, help="Shared secret key")
    p.add_argument("--core-columns", nargs="*", default=[], help="Columns to obfuscate (obfuscate mode)")
    p.add_argument("--keep-columns", nargs="*", default=[], help="Columns to copy unchanged (obfuscate mode)")
    p.add_argument("--manifest-out", default="obfuscation_manifest.enc", help="Encrypted manifest output (obfuscate mode)")
    p.add_argument("--manifest-in", default="obfuscation_manifest.enc", help="Encrypted manifest input (deobfuscate mode)")
    p.add_argument("--alias-prefix", default="signal", help="Obfuscated tag prefix (obfuscate mode)")
    return p.parse_args()


def main() -> None:
    args = parse_args()
    engine = DataObfuscator(secret_key=args.key)

    input_path = Path(args.input_path)
    output_path = Path(args.output_path)

    if args.mode == "obfuscate":
        if not args.core_columns:
            raise SystemExit("--core-columns is required in obfuscate mode")

        records = load_table(input_path)
        obfuscated, encrypted_manifest = engine.obfuscate_records(
            records=records,
            core_columns=args.core_columns,
            keep_columns=args.keep_columns,
            alias_prefix=args.alias_prefix,
        )
        write_table(output_path, obfuscated)
        Path(args.manifest_out).write_text(encrypted_manifest, encoding="utf-8")
        print(f"Obfuscated {len(obfuscated)} records -> {output_path}")
        print(f"Encrypted manifest written to {args.manifest_out}")
        return

    # deobfuscate
    encrypted_manifest = Path(args.manifest_in).read_text(encoding="utf-8").strip()
    records = load_table(input_path)
    restored = engine.deobfuscate_records(records, encrypted_manifest)
    write_table(output_path, restored)
    print(f"De-obfuscated {len(restored)} records -> {output_path}")


if __name__ == "__main__":
    main()
