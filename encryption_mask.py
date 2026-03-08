"""Simple personal-information masking + encryption utility.

This script lets you:
1) Select personal information fields (name, age, gender, city)
2) Mask selected fields
3) Encrypt the masked result using a simple key-based XOR cipher

Usage example:
python encryption_mask.py \
  --name "Alice Johnson" \
  --age 29 \
  --gender "Female" \
  --city "Seattle" \
  --mask-fields name city \
  --key "my-secret-key"
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
from typing import Dict, Iterable, List


PII_FIELDS = ("name", "age", "gender", "city")


def mask_value(value: str) -> str:
    """Mask a value while keeping a small amount of readability."""
    value = str(value)
    if len(value) <= 1:
        return "*"
    if len(value) == 2:
        return value[0] + "*"
    return value[0] + ("*" * (len(value) - 2)) + value[-1]


def mask_personal_data(data: Dict[str, str], fields_to_mask: Iterable[str]) -> Dict[str, str]:
    """Return a copy of `data` with selected fields masked."""
    masked = data.copy()
    for field in fields_to_mask:
        if field in masked:
            masked[field] = mask_value(masked[field])
    return masked


def _keystream(key: str, length: int) -> bytes:
    """Build a pseudo-random byte stream derived from the key."""
    seed = hashlib.sha256(key.encode("utf-8")).digest()
    stream = bytearray()
    counter = 0

    while len(stream) < length:
        block = hashlib.sha256(seed + counter.to_bytes(4, "big")).digest()
        stream.extend(block)
        counter += 1

    return bytes(stream[:length])


def encrypt_text(plain_text: str, key: str) -> str:
    """Encrypt text using XOR + key-derived keystream, output URL-safe base64."""
    raw = plain_text.encode("utf-8")
    stream = _keystream(key, len(raw))
    cipher = bytes(b ^ k for b, k in zip(raw, stream))
    return base64.urlsafe_b64encode(cipher).decode("utf-8")


def decrypt_text(cipher_text: str, key: str) -> str:
    """Decrypt text produced by `encrypt_text`."""
    cipher = base64.urlsafe_b64decode(cipher_text.encode("utf-8"))
    stream = _keystream(key, len(cipher))
    plain = bytes(b ^ k for b, k in zip(cipher, stream))
    return plain.decode("utf-8")


def process_record(record: Dict[str, str], fields_to_mask: List[str], key: str) -> Dict[str, str]:
    """Mask selected fields and encrypt the resulting JSON payload."""
    masked = mask_personal_data(record, fields_to_mask)
    payload = json.dumps(masked, separators=(",", ":"), ensure_ascii=False)
    encrypted_payload = encrypt_text(payload, key)
    return {
        "masked_data": masked,
        "encrypted_payload": encrypted_payload,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Mask and encrypt personal information.")
    parser.add_argument("--name", required=True, help="Person's name")
    parser.add_argument("--age", required=True, help="Person's age")
    parser.add_argument("--gender", required=True, help="Person's gender")
    parser.add_argument("--city", required=True, help="Person's city")
    parser.add_argument(
        "--mask-fields",
        nargs="+",
        choices=PII_FIELDS,
        default=list(PII_FIELDS),
        help="Fields to mask before encryption",
    )
    parser.add_argument("--key", required=True, help="Encryption key")
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    record = {
        "name": args.name,
        "age": str(args.age),
        "gender": args.gender,
        "city": args.city,
    }

    result = process_record(record, args.mask_fields, args.key)
    print("Masked Data:")
    print(json.dumps(result["masked_data"], indent=2, ensure_ascii=False))
    print("\nEncrypted Payload:")
    print(result["encrypted_payload"])

    # Optional verification output so users can see round-trip decryption.
    decrypted = decrypt_text(result["encrypted_payload"], args.key)
    print("\nDecrypted Payload (for verification):")
    print(decrypted)


if __name__ == "__main__":
    main()
