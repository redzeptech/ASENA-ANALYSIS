# =============================================================================
# ASENA-ANALYSIS — Yerel operasyonel sayaçlar (LinkedIn Executive Summary için)
# =============================================================================
"""Twilio / Telegram gönderim sayıları ``data/asena_metrics.json`` içinde tutulur."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

_DEFAULT: dict[str, int] = {
    "twilio_sms_total": 0,
    "twilio_whatsapp_total": 0,
    "telegram_kvkk_alerts": 0,
    "telegram_http_notifications": 0,
    "initial_salute_sms": 0,
    "initial_salute_whatsapp": 0,
}


def _project_data_dir() -> Path:
    return Path(__file__).resolve().parent.parent.parent / "data"


def metrics_path() -> Path:
    return _project_data_dir() / "asena_metrics.json"


def load_metrics() -> dict[str, Any]:
    p = metrics_path()
    if not p.is_file():
        return dict(_DEFAULT)
    try:
        raw = json.loads(p.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return dict(_DEFAULT)
    out = dict(_DEFAULT)
    for k, v in raw.items():
        if isinstance(v, int):
            out[k] = v
    return out


def bump(key: str, n: int = 1) -> None:
    if n <= 0:
        return
    m = load_metrics()
    m[key] = int(m.get(key, 0)) + n
    p = metrics_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(m, ensure_ascii=False, indent=2), encoding="utf-8")
