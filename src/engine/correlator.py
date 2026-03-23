# =============================================================================
# ASENA-ANALYSIS — Hukuki şerh: Defansif analiz; yetkisiz kullanım yasaktır. LEGAL.md
# =============================================================================
"""
🐺 Asena Correlator & Timeline Generator

ASENA-ANALYSIS — Korelasyon ve olay kronolojisi: ``parser`` çıktısından IP zinciri,
“Bozkurt” hikâyesi (önce / saldırı / sonra) ve özet cümleler (“şu IP, şu aralıkta,
kaç deneme, yanıt profili”). Dışa aktarımda ``privacy_shield`` zorunludur (maskeleme).

Hukuk notu: KVKK/GDPR uyumlu raporlama; ham PII zaman çizelgesinde tutulmaz.

İz sürme: zincir korelasyonu + Bozkurt hikayesi (önce / saldırı / arada / sonra).
"""

from __future__ import annotations

import os
import time
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Literal, Optional

import pandas as pd

from utils.notifier import AsenaMessenger, AsenaNotifier

from .parser import LogLine, ParsedAlert, RuleHit, payload_display

_SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3}
_HYBRID_NUMERIC_THRESHOLD = 90
_PAYLOAD_IF_WINDOW_MAX = 64


@dataclass(frozen=True)
class CorrelatedEvent:
    chain_id: str
    timestamp: str
    ip: str
    method: str
    path: str
    status_code: int
    categories: str
    rules_matched: str
    severity_max: str
    raw_request: str


def _story_id_sort_key(story_id: str) -> int:
    try:
        return int(story_id.split("-")[1])
    except (IndexError, ValueError):
        return 0


@dataclass(frozen=True)
class AttackChainNarrative:
    """
    Tek saldırı zinciri özeti: IP (maskeli), zaman penceresi, deneme sayısı, olası sonuç.
    """

    story_id: str
    source_ip: str
    started_at: str
    ended_at: str
    attack_attempts: int
    outcome: Literal["success_likely", "blocked_likely", "mixed"]
    summary_tr: str


@dataclass(frozen=True)
class StoryTimelineRow:
    """timeline.csv — tek satır: bağlam veya saldırı anı."""

    story_id: str
    sequence: int
    phase: str
    timestamp: str
    attack_started_at: str
    attack_ended_at: str
    source_ip: str
    payload: str
    http_status: int
    success: str
    method: str
    path: str
    rules_matched: str
    priority: int = 0
    tore_status: str = ""


def _max_severity(hits: tuple[RuleHit, ...]) -> str:
    if not hits:
        return "low"
    return max(hits, key=lambda h: _SEVERITY_ORDER.get(h.severity, 0)).severity


def _categories(hits: tuple[RuleHit, ...]) -> str:
    seen: list[str] = []
    for h in hits:
        if h.category not in seen:
            seen.append(h.category)
    return "|".join(seen)


def _rules_csv(hits: tuple[RuleHit, ...]) -> str:
    return "|".join(h.rule_id for h in hits)


def http_success_label(status: int) -> str:
    """Kapı açıldı mı? 2xx = evet, 5xx = hayır, diğer = diğer."""
    if 200 <= status < 300:
        return "yes"
    if status >= 500:
        return "no"
    return "other"


def _chain_ids_for_alerts(
    alerts: list[ParsedAlert],
    *,
    window: timedelta,
) -> list[tuple[ParsedAlert, str]]:
    if not alerts:
        return []
    ordered = sorted(alerts, key=lambda a: a.timestamp)
    out: list[tuple[ParsedAlert, str]] = []
    chain_seq = 0
    last_ts_by_ip: dict[str, datetime] = {}
    chain_id_by_ip: dict[str, str] = {}
    for a in ordered:
        prev = last_ts_by_ip.get(a.ip)
        if prev is None or (a.timestamp - prev) > window:
            chain_seq += 1
            cid = f"chain-{chain_seq:04d}"
            chain_id_by_ip[a.ip] = cid
        else:
            cid = chain_id_by_ip[a.ip]
        last_ts_by_ip[a.ip] = a.timestamp
        out.append((a, cid))
    return out


def _group_alerts_by_chain(
    chain_ids: list[tuple[ParsedAlert, str]],
) -> dict[str, list[ParsedAlert]]:
    d: dict[str, list[ParsedAlert]] = defaultdict(list)
    for a, cid in chain_ids:
        d[cid].append(a)
    return dict(d)


def _match_alert(line: LogLine, chain_alerts: list[ParsedAlert]) -> Optional[ParsedAlert]:
    for a in chain_alerts:
        if a.ip != line.ip:
            continue
        if a.timestamp.replace(microsecond=0) != line.timestamp.replace(microsecond=0):
            continue
        if a.raw_request != line.request_line:
            continue
        return a
    return None


def _phase_for_line(
    line: LogLine,
    first_ts: datetime,
    last_ts: datetime,
    matched: Optional[ParsedAlert],
) -> str:
    if matched is not None:
        return "attack"
    if line.timestamp < first_ts:
        return "before"
    if line.timestamp > last_ts:
        return "after"
    return "between"


def build_story_timeline(
    alerts: list[ParsedAlert],
    all_lines: list[LogLine],
    *,
    window: timedelta,
    context: timedelta,
) -> list[StoryTimelineRow]:
    """
    Aynı kaynak IP için zincir zaman penceresinin öncesi + sonrası (context) ile
    tüm trafiği sıraya dizer; saldırı satırlarında payload ve kurallar dolu.
    """
    if not alerts:
        return []

    chain_pairs = _chain_ids_for_alerts(alerts, window=window)
    groups = _group_alerts_by_chain(chain_pairs)

    rows: list[StoryTimelineRow] = []

    for story_id in sorted(groups.keys(), key=_story_id_sort_key):
        chain_alerts = sorted(groups[story_id], key=lambda a: a.timestamp)
        first_ts = chain_alerts[0].timestamp
        last_ts = chain_alerts[-1].timestamp
        ip = chain_alerts[0].ip
        win_start = first_ts - context
        win_end = last_ts + context

        attack_started_at = first_ts.isoformat(sep=" ", timespec="seconds")
        attack_ended_at = last_ts.isoformat(sep=" ", timespec="seconds")

        window_lines = [
            ln
            for ln in all_lines
            if ln.ip == ip and win_start <= ln.timestamp <= win_end
        ]
        window_lines.sort(key=lambda x: x.timestamp)

        seq = 0
        for ln in window_lines:
            seq += 1
            matched = _match_alert(ln, chain_alerts)
            phase = _phase_for_line(ln, first_ts, last_ts, matched)
            if matched is not None:
                payload = matched.scan_text[:4096]
                rules = _rules_csv(matched.hits)
            else:
                payload = payload_display(ln)
                rules = ""

            rows.append(
                StoryTimelineRow(
                    story_id=story_id,
                    sequence=seq,
                    phase=phase,
                    timestamp=ln.timestamp.isoformat(sep=" ", timespec="seconds"),
                    attack_started_at=attack_started_at,
                    attack_ended_at=attack_ended_at,
                    source_ip=ln.ip,
                    payload=payload,
                    http_status=ln.status_code,
                    success=http_success_label(ln.status_code),
                    method=ln.method,
                    path=ln.path,
                    rules_matched=rules,
                )
            )

    return rows


def summarize_attack_chains_from_timeline(rows: list[StoryTimelineRow]) -> list[AttackChainNarrative]:
    """
    ``build_story_timeline`` çıktısından zincir başına tek cümlelik hikâye üretir:
    başlangıç/bitiş zamanı, deneme sayısı, HTTP yanıt profiline göre olası sızıntı / blok.
    """
    if not rows:
        return []

    by_story: dict[str, list[StoryTimelineRow]] = defaultdict(list)
    for r in rows:
        by_story[r.story_id].append(r)

    out: list[AttackChainNarrative] = []
    for sid in sorted(by_story.keys(), key=_story_id_sort_key):
        group = sorted(by_story[sid], key=lambda x: x.timestamp)
        attacks = [x for x in group if x.phase == "attack"]
        if not attacks:
            continue
        ip = attacks[0].source_ip
        started = attacks[0].attack_started_at
        ended = attacks[-1].attack_ended_at
        n = len(attacks)
        any_yes = any(a.success == "yes" for a in attacks)
        any_no = any(a.success == "no" for a in attacks)
        if any_yes and not any_no:
            outcome: Literal["success_likely", "blocked_likely", "mixed"] = "success_likely"
            summary_tr = (
                f"{ip}, {started} ile {ended} arasında {n} saldırı denemesi yaptı; "
                f"yanıtların tamamı veya çoğu 2xx — uygulama katmanında veri döndü "
                f"(olası sızıntı / başarılı enjeksiyon riski, ortam doğrulaması gerekir)."
            )
        elif any_no and not any_yes:
            outcome = "blocked_likely"
            summary_tr = (
                f"{ip}, {started} ile {ended} arasında {n} saldırı denemesi yaptı; "
                f"yanıtlar 5xx veya hata profili — zincir genelde engellenmiş veya başarısız görünüyor."
            )
        else:
            outcome = "mixed"
            summary_tr = (
                f"{ip}, {started} ile {ended} arasında {n} saldırı denemesi yaptı; "
                f"2xx ve 5xx/diğer yanıtlar karışık — sonuç ortam ve uygulamaya göre netleştirilmeli."
            )

        out.append(
            AttackChainNarrative(
                story_id=sid,
                source_ip=ip,
                started_at=started,
                ended_at=ended,
                attack_attempts=n,
                outcome=outcome,
                summary_tr=summary_tr,
            )
        )
    return out


def _env_correlator_initial_salute() -> bool:
    """``ASENA_CORRELATOR_INITIAL_SALUTE=1``: ilk olayda Twilio selamı (``main`` ile ikili gönderimi önlemek için varsayılan kapalı)."""
    return os.environ.get("ASENA_CORRELATOR_INITIAL_SALUTE", "").strip().lower() in ("1", "true", "yes", "on")


class AsenaCorrelator:
    """
    Laboratuvar / demo: maskeli IP başına zaman damgası hafızası + korelasyon zinciri.

    **Hibrit karar:** kural tabanlı risk + Isolation Forest (payload penceresi).
    Uyarılar Twilio/Telegram’a yalnızca KVKK uyumlu özet (tip + skor) gider.

    ``ip_history``: her IP için ``time.time()`` ile son istekler (60 s penceresi).
    ``critical_events``: CRITICAL eşiklerinin özeti.

    Üretim zaman çizelgesi için ``build_story_timeline`` + ``export_timeline_csv`` kullanın;
    bu sınıf ayrı ``correlator_events.csv`` yazar.
    """

    _WINDOW_SEC = 60
    _RATE_THRESHOLD = 5
    _CRITICAL_ATTACK_TYPE_KVKK = "SQL Injection (UNION/SELECT, HTTP 2xx)"
    _HYBRID_AI_ATTACK_TYPE = "Hibrit: Kural + AI (Isolation Forest)"
    _HYBRID_SCORE_ATTACK_TYPE = "Hibrit: Yüksek risk skoru (kural)"

    def __init__(
        self,
        output_file: str | Path = "data/correlator_events.csv",
        *,
        notifier: AsenaNotifier | None = None,
        messenger: Any | None = None,
    ) -> None:
        self.output_file = Path(output_file)
        self.events: list[dict[str, Any]] = []
        self.ip_history: defaultdict[str, list[float]] = defaultdict(list)
        self.critical_events: list[dict[str, Any]] = []
        self._payload_if_window: list[str] = []
        self._notifier = notifier if notifier is not None else AsenaNotifier()
        self._messenger: Any = messenger if messenger is not None else AsenaMessenger()
        self._is_system_ready = False

    @staticmethod
    def _is_http_200(status: int | str) -> bool:
        if isinstance(status, int):
            return status == 200
        return str(status).strip() == "200"

    @staticmethod
    def _coerce_status_int(status: int | str) -> int:
        if isinstance(status, int):
            return status
        head = str(status).strip().split()[0]
        try:
            return int(head)
        except ValueError:
            return 0

    def _append_payload_if_window(self, payload: str) -> None:
        self._payload_if_window.append(payload[:4096])
        if len(self._payload_if_window) > _PAYLOAD_IF_WINDOW_MAX:
            self._payload_if_window = self._payload_if_window[-_PAYLOAD_IF_WINDOW_MAX :]

    def _ai_if_last_payload(self) -> int:
        """0 = normal, -1 = IF anomali (``isolation_forest_ai_scores``). Pencere ``< 3`` ise 0."""
        if len(self._payload_if_window) < 3:
            return 0
        try:
            from engine.ml_analyzer import isolation_forest_ai_scores

            scores = isolation_forest_ai_scores(self._payload_if_window)
            return int(scores[-1])
        except Exception:
            return 0

    def _dispatch_hybrid_alerts(
        self,
        *,
        masked_ip: str,
        reason: str,
        risk_score: int,
        attack_type: str,
    ) -> None:
        """Telegram + Twilio — yalnızca KVKK özet; IP/payload uzak metinde yok."""
        print(f"[ASENA] Uyarı (yerel): {reason} | Kaynak (maskeli): {masked_ip}")
        self._notifier.send_kvkk_safe_alert(attack_type=attack_type, risk_score=risk_score)
        try:
            self._messenger.send_whatsapp(attack_type=attack_type, risk_score=risk_score)
            self._messenger.send_sms(attack_type=attack_type, risk_score=risk_score)
        except ImportError:
            pass
        except Exception as e:
            print(f"[-] Twilio bildirimi atlandı: {e}")

    def track_request(self, masked_ip: str) -> None:
        """Her erişim satırında çağrılır; son 60 s penceresinde IP hafızasını günceller."""
        current_time = time.time()
        hist = self.ip_history[masked_ip]
        hist.append(current_time)
        self.ip_history[masked_ip] = [t for t in hist if current_time - t < self._WINDOW_SEC]

    def check_correlation(
        self,
        masked_ip: str,
        payload: str,
        status: int | str,
    ) -> tuple[str, str]:
        """
        ``track_request`` sonrası çağrılır.

        **Hibrit:** kural (hız, UNION/SELECT, HTTP 200) + AI (Isolation Forest, payload penceresi ≥3).
        ``numeric_risk >= 90`` veya ``ai == -1`` ise (SQL CRITICAL dışında) ek hibrit alarmı tetiklenebilir.

        Dönüş: (risk_level, reason) — Low / Medium / High / CRITICAL
        """
        current_time = time.time()
        recent_requests = self.ip_history[masked_ip]
        recent_requests = [t for t in recent_requests if current_time - t < self._WINDOW_SEC]
        self.ip_history[masked_ip] = recent_requests

        if not self._is_system_ready:
            self._is_system_ready = True
            if _env_correlator_initial_salute():
                try:
                    ch = os.environ.get("ASENA_INITIAL_SALUTE_CHANNEL", "whatsapp").strip().lower()
                    if ch not in ("whatsapp", "sms", "both"):
                        ch = "whatsapp"
                    self._messenger.send_initial_salute(channel=ch)  # type: ignore[arg-type]
                except Exception as e:
                    print(f"[-] Correlator töre selamı atlandı: {e}")

        st_code = self._coerce_status_int(status)
        self._append_payload_if_window(payload)
        numeric_risk = self._calculate_risk(st_code, payload)
        ai_flag = self._ai_if_last_payload()

        risk_level = "Low"
        reason = "Normal Activity"

        if len(recent_requests) > self._RATE_THRESHOLD:
            risk_level = "Medium"
            reason = "Hızlı tarama (Scanning) tespiti."

        sql_critical = False
        if any(key in payload.upper() for key in ("UNION", "SELECT")):
            risk_level = "High"
            reason = "SQL Sızdırma (Exfiltration) girişimi."
            if self._is_http_200(status):
                sql_critical = True
                risk_level = "CRITICAL"
                reason = "BAŞARILI SQL Injection ihtimali! Kapı açıldı."
                self.critical_events.append(
                    {
                        "masked_ip": masked_ip,
                        "payload_snip": payload[:512],
                        "reason": reason,
                        "ts": current_time,
                    }
                )

        hybrid_trigger = numeric_risk >= _HYBRID_NUMERIC_THRESHOLD or ai_flag == -1

        if sql_critical:
            self._dispatch_hybrid_alerts(
                masked_ip=masked_ip,
                reason=reason,
                risk_score=numeric_risk,
                attack_type=self._CRITICAL_ATTACK_TYPE_KVKK,
            )
        elif hybrid_trigger:
            if ai_flag == -1:
                atk = self._HYBRID_AI_ATTACK_TYPE
                reason = "Hibrit: Isolation Forest anomali + kural."
            else:
                atk = self._HYBRID_SCORE_ATTACK_TYPE
                reason = "Hibrit: Sayısal risk eşiği (≥90) + kural."
            if risk_level in ("Low", "Medium"):
                risk_level = "High"
            self._dispatch_hybrid_alerts(
                masked_ip=masked_ip,
                reason=reason,
                risk_score=numeric_risk,
                attack_type=atk,
            )

        return risk_level, reason

    def process_event(self, event_data: dict[str, Any]) -> str:
        """
        Test / entegrasyon API: ``risk_score`` ve ``ai_is_anomaly`` dışarıdan verilebilir.

        Uzak bildirimde IP/payload **yok** (KVKK); yalnızca özet tip + skor.
        """
        masked_ip = str(event_data.get("masked_ip", "") or "0.0.0.0")
        payload = str(event_data.get("payload", "") or "")
        status = event_data.get("http_status", event_data.get("status", 200))
        risk_score = int(event_data.get("risk_score", 0) or 0)
        ai_is_anomaly = int(event_data.get("ai_is_anomaly", 0) or 0)

        if not self._is_system_ready:
            self._is_system_ready = True
            if _env_correlator_initial_salute():
                try:
                    self._messenger.send_initial_salute(channel="whatsapp")  # type: ignore[arg-type]
                except Exception:
                    pass

        self.track_request(masked_ip)
        self._append_payload_if_window(payload)

        if risk_score >= _HYBRID_NUMERIC_THRESHOLD or ai_is_anomaly == -1:
            atk = (
                self._HYBRID_AI_ATTACK_TYPE
                if ai_is_anomaly == -1
                else self._HYBRID_SCORE_ATTACK_TYPE
            )
            self._dispatch_hybrid_alerts(
                masked_ip=masked_ip,
                reason="process_event: hibrit eşik",
                risk_score=min(999, max(0, risk_score)),
                attack_type=atk,
            )
            return "ALARM GÖNDERİLDİ"
        return "İZLENDİ"

    def add_event(
        self,
        masked_ip: str,
        timestamp: str,
        payload: str,
        status_code: int,
        *,
        risk_level: str | None = None,
        corr_reason: str | None = None,
    ) -> None:
        """
        Laboratuvar CSV satırı. ``risk_level`` verilmişse tekrar korelasyon hesaplanmaz
        (parser zaten ``track_request`` + ``check_correlation`` yapmış olabilir).
        """
        if risk_level is None or corr_reason is None:
            self.track_request(masked_ip)
            risk_level, corr_reason = self.check_correlation(masked_ip, payload, status_code)
        else:
            pass
        event = {
            "Tarih_Saat": timestamp,
            "Maskelenmiş_IP": masked_ip,
            "Kullanılan_Pusat": payload,
            "HTTP_Durum": status_code,
            "Risk_Seviyesi": risk_level,
            "Korelasyon": corr_reason,
            "Risk_Skoru": self._calculate_risk(status_code, payload),
            "Hukuki_Durum": "Eğitim/Lab",
        }
        self.events.append(event)
        self._export_to_csv()

    def _calculate_risk(self, status: int, payload: str) -> int:
        """Basit sayısal skor (CSV ile uyum); korelasyon metni ``Korelasyon`` sütununda."""
        score = 50
        if 200 <= status < 300:
            score += 40
        if "UNION" in payload.upper():
            score += 10
        return score

    def _export_to_csv(self) -> None:
        if not self.events:
            return
        df = pd.DataFrame(self.events)
        self.output_file.parent.mkdir(parents=True, exist_ok=True)
        df.to_csv(self.output_file, index=False, encoding="utf-8-sig")


def correlate(
    alerts: list[ParsedAlert],
    *,
    window: timedelta = timedelta(minutes=5),
) -> list[CorrelatedEvent]:
    """Yalnızca uyarı satırları (özet); hikaye için build_story_timeline kullanın."""
    if not alerts:
        return []

    out: list[CorrelatedEvent] = []
    for a, cid in _chain_ids_for_alerts(alerts, window=window):
        out.append(
            CorrelatedEvent(
                chain_id=cid,
                timestamp=a.timestamp.isoformat(sep=" ", timespec="seconds"),
                ip=a.ip,
                method=a.method,
                path=a.path,
                status_code=a.status_code,
                categories=_categories(a.hits),
                rules_matched=_rules_csv(a.hits),
                severity_max=_max_severity(a.hits),
                raw_request=a.raw_request,
            )
        )

    return out
