# =============================================================================
# ASENA-ANALYSIS — Hukuki şerh: Defansif analiz; yetkisiz kullanım yasaktır. LEGAL.md
# =============================================================================
"""
Töre (sqli_rules.yaml): IP/zaman penceresi ve anahtar kelime korelasyonu.

``response_delay`` Apache combined logunda yanıt süresi olmadığı için varsayılan olarak
yok sayılır; CustomLog ile ``%D`` eklenirse genişletilebilir.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import yaml

from .parser import ParsedAlert


@dataclass(frozen=True)
class ToreRuleHit:
    rule_id: str
    name: str
    action: str
    detail: str


def default_tore_rules_path() -> Path:
    return Path(__file__).resolve().parent.parent / "rules" / "sqli_rules.yaml"


def _load_tore_yaml(path: Path) -> list[dict[str, Any]]:
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    return list(raw.get("rules") or [])


def _keywords_match(
    scan_text: str,
    keywords: list[str],
    *,
    mode: str,
) -> bool:
    t = scan_text.upper()
    keys = [k.upper() for k in keywords]
    if mode == "any":
        return any(k in t for k in keys)
    return all(k in t for k in keys)


def _eval_001(
    rule: dict[str, Any],
    alerts: list[ParsedAlert],
) -> ToreRuleHit | None:
    cond = rule.get("condition") or {}
    threshold = int(cond.get("threshold", 5))
    window_s = int(cond.get("time_window", 60))
    window = timedelta(seconds=window_s)

    by_ip: dict[str, list[ParsedAlert]] = {}
    for a in alerts:
        by_ip.setdefault(a.ip, []).append(a)
    for ip, lst in by_ip.items():
        lst.sort(key=lambda x: x.timestamp)
        for i, start in enumerate(lst):
            end_t = start.timestamp + window
            n = sum(1 for x in lst[i:] if x.timestamp <= end_t)
            if n >= threshold:
                return ToreRuleHit(
                    rule_id=str(rule["id"]),
                    name=str(rule.get("name", "")),
                    action=str(rule.get("action", "")),
                    detail=f"{n} deneme / {window_s}s penceresi (IP zinciri)",
                )
    return None


def _eval_002(rule: dict[str, Any], alerts: list[ParsedAlert]) -> list[ToreRuleHit]:
    cond = rule.get("condition") or {}
    keywords = list(cond.get("keywords") or [])
    match_mode = str(cond.get("keyword_match", "all")).lower()
    want_status = cond.get("http_status")
    out: list[ToreRuleHit] = []
    for a in alerts:
        if want_status is not None and a.status_code != int(want_status):
            continue
        if not keywords:
            continue
        if not _keywords_match(a.scan_text, keywords, mode=match_mode):
            continue
        out.append(
            ToreRuleHit(
                rule_id=str(rule["id"]),
                name=str(rule.get("name", "")),
                action=str(rule.get("action", "")),
                detail=f"HTTP {a.status_code}, eşleşen payload",
            )
        )
    return out


def _eval_003(rule: dict[str, Any], alerts: list[ParsedAlert]) -> list[ToreRuleHit]:
    cond = rule.get("condition") or {}
    keywords = list(cond.get("keywords") or [])
    match_mode = str(cond.get("keyword_match", "any")).lower()
    delay_s = cond.get("response_delay")

    out: list[ToreRuleHit] = []
    for a in alerts:
        if not keywords:
            continue
        if not _keywords_match(a.scan_text, keywords, mode=match_mode):
            continue
        detail = "SLEEP/BENCHMARK imzası"
        if delay_s is not None:
            detail += (
                f"; response_delay>={delay_s}s (Apache combined’da süre yok — "
                f"CustomLog %D ile genişletilebilir)"
            )
        out.append(
            ToreRuleHit(
                rule_id=str(rule["id"]),
                name=str(rule.get("name", "")),
                action=str(rule.get("action", "")),
                detail=detail,
            )
        )
    return out


def evaluate_tore_rules(
    alerts: list[ParsedAlert],
    rules_path: Path,
) -> list[ToreRuleHit]:
    """
    ``sqli_rules.yaml`` içindeki ASENA-* kurallarını uygular.
    """
    if not rules_path.is_file():
        return []
    raw_rules = _load_tore_yaml(rules_path)
    hits: list[ToreRuleHit] = []

    for rule in raw_rules:
        rid = str(rule.get("id", ""))
        if rid == "ASENA-001":
            h = _eval_001(rule, alerts)
            if h:
                hits.append(h)
        elif rid == "ASENA-002":
            hits.extend(_eval_002(rule, alerts))
        elif rid == "ASENA-003":
            hits.extend(_eval_003(rule, alerts))

    return hits
