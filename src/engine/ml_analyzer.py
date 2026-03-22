# =============================================================================
# ASENA-ANALYSIS — Hukuki şerh: Defansif analiz; ham PII özellik olarak kullanılmaz. LEGAL.md
# =============================================================================
"""
Özellik çıkarımı (feature engineering): log / uyarı satırlarını sayısal vektörlere dönüştürür.

Amaç: ML / istatistik / dış AI araçlarına beslenebilir tablo üretmek.
Ham IP adresi özellik olarak **kullanılmaz**; yalnızca maskeli string uzunluğu gibi güvenli türevler.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import asdict, dataclass, fields
from datetime import datetime
from typing import Any, Iterable

from .correlator import StoryTimelineRow
from .parser import LogLine, ParsedAlert, RuleHit

_SEVERITY_SCORE = {"low": 1, "medium": 2, "high": 3}

# SQL / enjeksiyon ile ilişkili alt dizgeler (sayım için; büyük/küçük harf duyarsız)
_SQL_TOKENS = (
    "UNION",
    "SELECT",
    "INSERT",
    "DROP",
    "SLEEP",
    "BENCHMARK",
    "ORDER BY",
    "OR 1=1",
    "AND 1=1",
    "INFORMATION_SCHEMA",
    "--",
    "/*",
)


def _shannon_entropy(text: str) -> float:
    """0..~8 aralığında kabaca dağılım çeşitliliği (yüksek = daha rastgele/uzun payload)."""
    if not text:
        return 0.0
    counts = Counter(text)
    n = len(text)
    ent = 0.0
    for c in counts.values():
        p = c / n
        ent -= p * math.log2(p)
    return float(ent)


def _method_code(method: str) -> int:
    m = (method or "GET").upper()
    return {"GET": 1, "POST": 2, "PUT": 3, "DELETE": 4, "HEAD": 5, "OPTIONS": 6, "PATCH": 7}.get(
        m,
        0,
    )


def _status_bucket(code: int) -> tuple[int, int, int]:
    """2xx, 4xx, 5xx göstergeleri (tek sıcak kodlaması)."""
    if 200 <= code < 300:
        return 1, 0, 0
    if 400 <= code < 500:
        return 0, 1, 0
    if code >= 500:
        return 0, 0, 1
    return 0, 0, 0


def _count_sql_tokens(scan_text: str) -> int:
    u = scan_text.upper()
    return sum(1 for t in _SQL_TOKENS if t in u)


def _max_rule_severity(hits: tuple[RuleHit, ...]) -> int:
    if not hits:
        return 0
    return max(_SEVERITY_SCORE.get(h.severity.lower(), 0) for h in hits)


@dataclass(frozen=True)
class FeatureVector:
    """Tek satır / tek uyarı için sayısal özellikler (PII içermez)."""

    # Zaman
    unix_ts: float
    hour_of_day: float  # 0–23
    weekday: float  # 0–6 (Pazartesi=0)

    # HTTP
    http_status: float
    is_2xx: float
    is_4xx: float
    is_5xx: float
    method_code: float

    # Payload / istek metni
    payload_length: float
    payload_entropy: float
    digit_ratio: float
    upper_ratio: float
    sql_token_hits: float
    special_char_ratio: float  # %XX, &, =, ', " vb.

    # Kurallar
    rule_hit_count: float
    max_severity_score: float  # 0–3
    unique_rule_ids: float

    # Timeline / ek (opsiyonel doldurulur)
    phase_attack: float  # 1.0 attack, 0.0 değilse
    priority: float
    tore_critical: float  # 1.0 ise CRITICAL


def features_from_parsed_alert(a: ParsedAlert) -> FeatureVector:
    """``ParsedAlert`` üzerinden özellik vektörü."""
    ts = a.timestamp
    unix_ts = ts.timestamp()
    hour = float(ts.hour)
    weekday = float(ts.weekday())

    st2, st4, st5 = _status_bucket(a.status_code)
    scan = a.scan_text or ""
    digits = sum(1 for c in scan if c.isdigit())
    uppers = sum(1 for c in scan if c.isupper())
    n = max(len(scan), 1)
    special = sum(1 for c in scan if c in "%&='\"<>;()[]{}\\")

    rules = list(a.hits)
    unique_ids = len({h.rule_id for h in rules})

    return FeatureVector(
        unix_ts=unix_ts,
        hour_of_day=hour,
        weekday=weekday,
        http_status=float(a.status_code),
        is_2xx=st2,
        is_4xx=st4,
        is_5xx=st5,
        method_code=float(_method_code(a.method)),
        payload_length=float(len(scan)),
        payload_entropy=_shannon_entropy(scan),
        digit_ratio=digits / n,
        upper_ratio=uppers / n,
        sql_token_hits=float(_count_sql_tokens(scan)),
        special_char_ratio=special / n,
        rule_hit_count=float(len(rules)),
        max_severity_score=float(_max_rule_severity(a.hits)),
        unique_rule_ids=float(unique_ids),
        phase_attack=1.0,
        priority=0.0,
        tore_critical=0.0,
    )


def features_from_log_line(ln: LogLine) -> FeatureVector:
    """Kural bilgisi olmadan temel özellikler (ön-işleme)."""
    ts = ln.timestamp
    scan = (ln.path or "") + ("?" + ln.query if ln.query else "")
    n = max(len(scan), 1)
    digits = sum(1 for c in scan if c.isdigit())
    uppers = sum(1 for c in scan if c.isupper())
    st2, st4, st5 = _status_bucket(ln.status_code)
    special = sum(1 for c in scan if c in "%&='\"<>;()[]{}")

    return FeatureVector(
        unix_ts=ts.timestamp(),
        hour_of_day=float(ts.hour),
        weekday=float(ts.weekday()),
        http_status=float(ln.status_code),
        is_2xx=st2,
        is_4xx=st4,
        is_5xx=st5,
        method_code=float(_method_code(ln.method)),
        payload_length=float(len(scan)),
        payload_entropy=_shannon_entropy(scan),
        digit_ratio=digits / n,
        upper_ratio=uppers / n,
        sql_token_hits=float(_count_sql_tokens(scan)),
        special_char_ratio=special / n,
        rule_hit_count=0.0,
        max_severity_score=0.0,
        unique_rule_ids=0.0,
        phase_attack=0.0,
        priority=0.0,
        tore_critical=0.0,
    )


def _parse_ts(ts: str) -> datetime:
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return datetime.min


def features_from_timeline_row(row: StoryTimelineRow) -> FeatureVector:
    """``StoryTimelineRow`` (timeline.csv satırı) için özellikler."""
    ts = _parse_ts(row.timestamp)
    unix_ts = ts.timestamp() if ts != datetime.min else 0.0
    scan = row.payload or ""
    n = max(len(scan), 1)
    digits = sum(1 for c in scan if c.isdigit())
    uppers = sum(1 for c in scan if c.isupper())
    st2, st4, st5 = _status_bucket(row.http_status)
    special = sum(1 for c in scan if c in "%&='\"<>;()[]{}")

    phase_attack = 1.0 if (row.phase or "").lower() == "attack" else 0.0
    tore_c = 1.0 if (row.tore_status or "").upper() == "CRITICAL" else 0.0

    # timeline’da kural sayısı: pipe ile ayrılmış
    rules = [x for x in (row.rules_matched or "").split("|") if x.strip()]
    rule_count = float(len(rules))

    return FeatureVector(
        unix_ts=float(unix_ts),
        hour_of_day=float(ts.hour) if ts != datetime.min else 0.0,
        weekday=float(ts.weekday()) if ts != datetime.min else 0.0,
        http_status=float(row.http_status),
        is_2xx=st2,
        is_4xx=st4,
        is_5xx=st5,
        method_code=float(_method_code(row.method)),
        payload_length=float(len(scan)),
        payload_entropy=_shannon_entropy(scan),
        digit_ratio=digits / n,
        upper_ratio=uppers / n,
        sql_token_hits=float(_count_sql_tokens(scan)),
        special_char_ratio=special / n,
        rule_hit_count=rule_count,
        max_severity_score=0.0,
        unique_rule_ids=rule_count,
        phase_attack=phase_attack,
        priority=float(row.priority),
        tore_critical=tore_c,
    )


def feature_vector_to_dict(fv: FeatureVector) -> dict[str, float]:
    """Sklearn / pandas için düz sözlük."""
    return {field.name: float(getattr(fv, field.name)) for field in fields(FeatureVector)}


def feature_vectors_to_records(rows: Iterable[FeatureVector]) -> list[dict[str, float]]:
    return [feature_vector_to_dict(r) for r in rows]


def dataframe_from_parsed_alerts(alerts: list[ParsedAlert]) -> Any:
    """``pandas.DataFrame`` döndürür; pandas yoksa ``ImportError``."""
    import pandas as pd

    recs = feature_vectors_to_records(features_from_parsed_alert(a) for a in alerts)
    return pd.DataFrame(recs)


def dataframe_from_timeline(rows: list[StoryTimelineRow]) -> Any:
    import pandas as pd

    recs = feature_vectors_to_records(features_from_timeline_row(r) for r in rows)
    return pd.DataFrame(recs)


def _url_length_and_special_ratio(scan_text: str) -> tuple[float, float]:
    """İstek URL/payload metni: uzunluk ve özel karakter oranı (Isolation Forest girdisi)."""
    if not scan_text:
        return 0.0, 0.0
    n = len(scan_text)
    special = sum(1 for c in scan_text if c in "%&='\"<>;()[]{}\\")
    return float(n), special / float(n)


def isolation_forest_predict(
    scan_texts: list[str],
    *,
    contamination: float = 0.1,
    random_state: int = 42,
) -> list[int]:
    """
    ``sklearn.ensemble.IsolationForest``: URL/payload **uzunluğu** ve **özel karakter yoğunluğu**
    ile anomali (``-1``) / normal (``1``) — sklearn sözleşmesi.

    Örnek sayısı ``< 3`` ise tüm satırlar ``1`` (normal) döner (istatistik yetersiz).
    """
    if len(scan_texts) < 3:
        return [1] * len(scan_texts)
    try:
        import numpy as np
        from sklearn.ensemble import IsolationForest
    except ImportError as e:
        raise ImportError("scikit-learn gerekli: pip install scikit-learn") from e

    lengths: list[float] = []
    ratios: list[float] = []
    for t in scan_texts:
        ln, r = _url_length_and_special_ratio(t)
        lengths.append(ln)
        ratios.append(r)
    X = np.column_stack([np.array(lengths, dtype=np.float64), np.array(ratios, dtype=np.float64)])
    c = min(max(contamination, 0.01), 0.5)
    model = IsolationForest(contamination=c, random_state=random_state, n_estimators=100)
    pred = model.fit_predict(X)
    return [int(x) for x in pred]


def isolation_forest_ai_scores(scan_texts: list[str], **kwargs: Any) -> list[int]:
    """
    Panel / CSV uyumu: anomali ``-1``, normal ``0`` (``AI_Score`` sütunu ile uyumlu).
    """
    raw = isolation_forest_predict(scan_texts, **kwargs)
    return [-1 if x == -1 else 0 for x in raw]


def fit_isolation_forest_on_parsed_alerts(alerts: list[ParsedAlert], **kwargs: Any) -> list[int]:
    """``ParsedAlert`` listesi üzerinden IF skorları (``scan_text``)."""
    return isolation_forest_ai_scores([a.scan_text or "" for a in alerts], **kwargs)
