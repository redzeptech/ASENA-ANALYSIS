#!/usr/bin/env python3
"""
requirements.lock.txt üretir: önce requirements.txt kurulur, ardından pip freeze çıktısı yazılır.

Kullanım (repo kökünden):
  python scripts/lock_requirements.py
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REQ = ROOT / "requirements.txt"
LOCK = ROOT / "requirements.lock.txt"


def main() -> int:
    if not REQ.is_file():
        print(f"Hata: {REQ} yok.", file=sys.stderr)
        return 2
    print(f"[*] Kurulum: {REQ}")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", str(REQ)])
    out = subprocess.check_output([sys.executable, "-m", "pip", "freeze"], text=True)
    LOCK.write_text(out, encoding="utf-8")
    n = len(out.strip().splitlines())
    print(f"[*] Yazıldı: {LOCK} ({n} paket)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
