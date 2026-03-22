# =============================================================================
# ASENA-ANALYSIS — Hukuki şerh: Defansif analiz; yetkisiz kullanım yasaktır. LEGAL.md
# Giriş kapısı: dışa aktarımın tamamı bu modülden geçer (maske + minimizasyon).
# =============================================================================
"""
ASENA-ANALYSIS — Gizlilik katmanı (merkez).

parser logları okur; timeline/JSON öncesi veri burada AsenaPrivacyShield ile işlenir.
"""

from __future__ import annotations

import hashlib
import logging
import os
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Literal
from urllib.parse import parse_qsl, unquote, urlencode

if TYPE_CHECKING:
    from engine.correlator import StoryTimelineRow

# SQLi süzgeci: URL-decode + büyük harf üzerinde defansif imza eşlemesi
_SQLI_SIEVE_RULES: list[tuple[str, str, str, re.Pattern[str]]] = [
    (
        "sqli_sieve_union",
        "high",
        "UNION tabanlı imza (süzgeç)",
        re.compile(r"(?i)\bUNION\s+SELECT\b"),
    ),
    (
        "sqli_sieve_boolean",
        "medium",
        "Boolean koşul (OR/AND 1=1) — süzgeç",
        re.compile(r"(?i)(?:\bor\b|\band\b)\s*['\"]?\d+['\"]?\s*=\s*['\"]?\d+"),
    ),
    (
        "sqli_sieve_comment",
        "low",
        "SQL yorum (-- / #) — süzgeç",
        re.compile(r"(?:--|#|%23)(?:\s|$|['\"])"),
    ),
    (
        "sqli_sieve_sleep",
        "high",
        "Zaman tabanlı (SLEEP) — süzgeç",
        re.compile(r"(?i)\bSLEEP\s*\("),
    ),
    (
        "sqli_sieve_order_by",
        "low",
        "ORDER BY — süzgeç",
        re.compile(r"(?i)\bORDER\s+BY\b"),
    ),
    (
        "sqli_sieve_select",
        "medium",
        "SELECT anahtar kelimesi — süzgeç",
        re.compile(r"(?i)\bSELECT\b"),
    ),
    (
        "sqli_sieve_benchmark",
        "high",
        "BENCHMARK — süzgeç",
        re.compile(r"(?i)\bBENCHMARK\s*\("),
    ),
    (
        "sqli_sieve_drop_table",
        "high",
        "DROP TABLE — süzgeç",
        re.compile(r"(?i)\bDROP\s+TABLE\b"),
    ),
]

_LOG = logging.getLogger("asena.legal_audit")
_LOG.propagate = False
_audit_configured = False


def _ensure_audit_logger() -> logging.Logger:
    global _audit_configured
    if not _audit_configured:
        log_dir = Path(__file__).resolve().parent.parent.parent / "logs"
        log_dir.mkdir(parents=True, exist_ok=True)
        log_path = log_dir / "asena_audit.log"
        fh = logging.FileHandler(log_path, encoding="utf-8")
        fh.setFormatter(logging.Formatter("%(asctime)s - LEGAL_AUDIT - %(message)s"))
        _LOG.setLevel(logging.INFO)
        _LOG.addHandler(fh)
        _audit_configured = True
    return _LOG


def resolve_salt(cfg_salt: str) -> str | None:
    """Boşsa AsenaPrivacyShield kendi varsayılan tuzunu kullanır."""
    s = (cfg_salt or "").strip() or (os.environ.get("ASENA_SALT") or "").strip()
    return s or None


_SESSION_PARAM_KEYS = frozenset(
    {
        "phpsessid",
        "jsessionid",
        "sessionid",
        "session_id",
        "sid",
        "asp.net_sessionid",
        "csrftoken",
        "csrf_token",
        "authenticity_token",
        "nonce",
        "state",
    }
)

_PII_PARAM_KEYS = frozenset(
    {
        "user",
        "username",
        "login",
        "email",
        "mail",
        "password",
        "passwd",
        "pass",
        "token",
        "access_token",
        "refresh_token",
    }
)

_EMAIL_RE = re.compile(r"[^@\s]+@[^@\s]+\.[^@\s]+")
_UA_INLINE = re.compile(r"\bUser-Agent\s*:\s*[^\n\r;]+", re.IGNORECASE)


@dataclass(frozen=True)
class PrivacyConfig:
    mode: Literal["subnet", "hash", "none"] = "subnet"
    salt: str = ""


class AsenaPrivacyShield:
    """
    ASENA-ANALYSIS Veri Gizliliği ve Hukuki Uyum Modülü.
    Görev: PII (Kişisel Veri) maskeleme ve işlem dökümü (Logging).

    IPv4 maskeleme: ``a.b.c.d`` → ``a.b.0.0`` (ör. ``192.168.1.5`` → ``192.168.0.0``).
    Her dışa aktarıma ``legal_header()`` ile KVKK/GDPR uyarısı eklenir.
    """

    def __init__(self, salt: str | None = None) -> None:
        self.salt = salt or os.getenv("ASENA_SALT", "BOZKURT_PENÇESİ_2026")
        self._setup_audit_log()

    def _setup_audit_log(self) -> None:
        _ensure_audit_logger()

    def audit(self, message: str) -> None:
        _ensure_audit_logger()
        _LOG.info(message)

    def mask_ip(self, ip_address: str) -> str:
        """IPv4: /16 alt ağ maskesi (``192.168.0.0`` biçimi). IPv6: ilk blokları genelleştirir."""
        s = (ip_address or "").strip()
        try:
            parts = s.split(".")
            if len(parts) == 4 and all(p.isdigit() for p in parts):
                return f"{parts[0]}.{parts[1]}.0.0"
        except Exception:
            return "0.0.0.0"
        if ":" in s:
            hextets = s.split(":")
            if len(hextets) >= 2:
                return f"{hextets[0]}:{hextets[1]}::"
        return s or "0.0.0.0"

    def anonymize_id(self, raw_data: str) -> str:
        hash_input = f"{raw_data}{self.salt}".encode("utf-8")
        return hashlib.sha256(hash_input).hexdigest()[:16]

    def anonymize_user(self, user_data: str) -> str:
        return self.anonymize_id(user_data)

    def legal_header(self) -> str:
        return (
            f"# ASENA-ANALYSIS PROJESİ - HUKUKİ BİLGİLENDİRME\n"
            f"# Rapor Tarihi: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            f"# Bu veriler KVKK/GDPR uyumlu olarak maskelenmiştir.\n"
            f"# Sadece eğitim ve defansif analiz amaçlıdır. İzinsiz kullanımı TCK 243 uyarınca suçtur.\n"
            f"{'-' * 60}\n"
        )

    def legal_disclaimer(self) -> str:
        return (
            "UYARI: Bu araç sadece eğitim ve defansif analiz amaçlıdır. "
            "İzinsiz ağlarda kullanımı TCK ve bilişim hukukuna göre suç teşkil edebilir."
        )

    def legal_notice_external_channel_brief(self) -> str:
        """
        SMS / WhatsApp / Telegram gibi üçüncü taraf kanallar: minimize edilmiş KVKK özeti.
        Gönderilen veri yalnızca saldırı tipi etiketi ve risk skoru olmalıdır; PII taşınmaz.
        """
        return "KVKK: yalnızca özet (saldırı tipi + risk skoru); ham IP/payload/kimlik yok."

    def sqli_sieve_scan(self, scan_text: str) -> list[tuple[str, str, str]]:
        """
        İstek metninde (path veya path?sorgu) SQLi işaretlerini süzgeçten geçirir.
        URL decode + büyük harf ile UNION, SELECT, OR 1=1 vb. defansif tespit.
        Dönüş: (rule_id, severity, description) listesi.
        """
        blob = unquote(scan_text.replace("+", " ")).upper()
        hits: list[tuple[str, str, str]] = []
        for rule_id, sev, desc, rx in _SQLI_SIEVE_RULES:
            if rx.search(blob):
                hits.append((rule_id, sev, desc))
        return hits


def _mask_ipv6_subnet(ip: str) -> str:
    if ":" not in ip:
        return ip
    g = ip.split(":")
    if len(g) >= 2:
        return f"{g[0]}:{g[1]}:xxxx::xxxx"
    return "xxxx::xxxx"


def mask_ip_with_shield(
    shield: AsenaPrivacyShield,
    ip: str,
    *,
    mode: Literal["subnet", "hash", "none"],
) -> str:
    if mode == "none" or not ip or ip == "-":
        return ip
    if mode == "subnet":
        if "." in ip and ip.count(".") == 3:
            return shield.mask_ip(ip)
        if ":" in ip:
            return _mask_ipv6_subnet(ip)
        return shield.mask_ip(ip)
    if mode == "hash":
        return f"h:{shield.anonymize_id(ip)}"
    return ip


def _strip_user_agent_noise(text: str) -> str:
    return _UA_INLINE.sub("[UA_REMOVED]", text)


def redact_query_string(qs: str, shield: AsenaPrivacyShield) -> str:
    pairs = parse_qsl(qs, keep_blank_values=True)
    out: list[tuple[str, str]] = []
    for k, v in pairs:
        lk = k.lower()
        if lk in _SESSION_PARAM_KEYS:
            continue
        if lk in _PII_PARAM_KEYS:
            out.append((k, f"u:{shield.anonymize_id(v)}"))
            continue
        if _EMAIL_RE.search(v):
            out.append((k, f"u:{shield.anonymize_id(v)}"))
            continue
        out.append((k, v))
    return urlencode(out, doseq=True)


def minimize_redact_request_text(text: str, shield: AsenaPrivacyShield) -> str:
    """path?query — UA temizliği, oturum minimizasyonu, PII hash."""
    t = _strip_user_agent_noise(text)
    if "?" not in t:
        return t
    path, q = t.split("?", 1)
    new_q = redact_query_string(q, shield)
    return f"{path}?{new_q}" if new_q else path


def redact_path(path: str) -> str:
    if not path or "@" not in path:
        return path
    return _EMAIL_RE.sub("[REDACTED]", path)


def apply_privacy_to_story(
    rows: list[StoryTimelineRow],
    cfg: PrivacyConfig,
) -> list[StoryTimelineRow]:
    """
    timeline / JSON çıktısı — AsenaPrivacyShield ile maskeleme + minimizasyon.
    Ham IP timeline'da asla yazılmaz (mode=none olsa bile subnet).
    """
    from engine.correlator import StoryTimelineRow as _ST

    shield = AsenaPrivacyShield(salt=resolve_salt(cfg.salt))
    out: list[StoryTimelineRow] = []
    for r in rows:
        if cfg.mode == "none":
            ip_out = mask_ip_with_shield(shield, r.source_ip, mode="subnet")
            out.append(
                _ST(
                    story_id=r.story_id,
                    sequence=r.sequence,
                    phase=r.phase,
                    timestamp=r.timestamp,
                    attack_started_at=r.attack_started_at,
                    attack_ended_at=r.attack_ended_at,
                    source_ip=ip_out,
                    payload=r.payload,
                    http_status=r.http_status,
                    success=r.success,
                    method=r.method,
                    path=r.path,
                    rules_matched=r.rules_matched,
                    priority=r.priority,
                    tore_status=r.tore_status,
                )
            )
            continue
        out.append(
            _ST(
                story_id=r.story_id,
                sequence=r.sequence,
                phase=r.phase,
                timestamp=r.timestamp,
                attack_started_at=r.attack_started_at,
                attack_ended_at=r.attack_ended_at,
                source_ip=mask_ip_with_shield(shield, r.source_ip, mode=cfg.mode),
                payload=minimize_redact_request_text(r.payload, shield),
                http_status=r.http_status,
                success=r.success,
                method=r.method,
                path=redact_path(r.path),
                rules_matched=r.rules_matched,
                priority=r.priority,
                tore_status=r.tore_status,
            )
        )
    shield.audit(f"privacy_export rows={len(out)} mode={cfg.mode}")
    return out


if __name__ == "__main__":
    shield = AsenaPrivacyShield()
    test_ip = "172.20.10.5"
    print(f"Orijinal IP: {test_ip} -> Maskelenmiş: {shield.mask_ip(test_ip)}")
