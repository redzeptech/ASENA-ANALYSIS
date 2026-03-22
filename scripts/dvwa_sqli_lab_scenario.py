#!/usr/bin/env python3
"""
DVWA SQLi lab — dört aşamalı senaryo (http://127.0.0.1:8081).

Tarayıcıda DVWA → SQL Injection sayfasında uygulayın; ardından:
  python asena.py analyze --log docker/logs/apache2/access.log --i-accept
veya canlı izleme:  python asena.py watch --i-accept

Not: Varsayılan Apache combined logunda yanıt süresi (ms) yoktur; Aşama 4’teki
SLEEP yine de URL’de yakalanır, fakat “yanıt süresi artışı” access.log satırında
otomatik tutulmaz (CustomLog’a %D eklenmesi gerekir).
"""

from __future__ import annotations

# Örnek istek yolları (DVWA GET parametresi genelde `id`)
PHASES = [
    ("1. Keşif", "id=1'"),
    ("2. ORDER BY", "id=1' ORDER BY 1--"),
    ("3. UNION exfil", "id=1' UNION SELECT user, password FROM users --"),
    ("4. Blind / time", "id=1' AND SLEEP(5) --"),
]


def main() -> None:
    print("🐺 ASENA — DVWA SQLi lab senaryosu (127.0.0.1:8081)\n")
    for title, q in PHASES:
        print(f"  {title}:  ?{q}")
    print("\nHer adımdan sonra: data/timeline.csv veya canlı watch çıktısını kontrol edin.\n")


if __name__ == "__main__":
    main()
