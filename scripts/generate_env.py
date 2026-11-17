"""Create a .env file from .env.example with strong random secrets.

Usage:  python scripts/generate_env.py [--force]
Secrets are generated with the `secrets` module (CSPRNG) and are never printed.
"""
from __future__ import annotations

import re
import secrets
import string
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def token(n: int = 24) -> str:
    return secrets.token_hex(n)


def misp_key() -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(40))


def main() -> int:
    target = ROOT / ".env"
    if target.exists() and "--force" not in sys.argv:
        print(".env already exists (use --force to overwrite)")
        return 1
    text = (ROOT / ".env.example").read_text(encoding="utf-8")
    values = {
        "POSTGRES_PASSWORD": token(),
        "ORG_A_API_KEY": "cti_a_" + secrets.token_urlsafe(32),
        "ORG_B_API_KEY": "cti_b_" + secrets.token_urlsafe(32),
        "ORG_C_API_KEY": "cti_c_" + secrets.token_urlsafe(32),
        "MISP_KEY": misp_key(),
        "MISP_ADMIN_PASSWORD": "Aa1!" + token(12),
        "MISP_DB_PASSWORD": token(),
        "MISP_DB_ROOT_PASSWORD": token(),
        "MISP_REDIS_PASSWORD": token(),
    }
    for key, value in values.items():
        text, n = re.subn(rf"^{key}=.*$", f"{key}={value}", text, flags=re.MULTILINE)
        if n != 1:
            raise SystemExit(f"{key} not found in .env.example")
    target.write_text(text, encoding="utf-8")
    print(f".env written with fresh secrets ({len(values)} values). Keep it private.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
