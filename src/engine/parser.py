# =============================================================================
# ASENA-ANALYSIS — Hukuki şerh: Defansif analiz; yetkisiz kullanım yasaktır. LEGAL.md
# Akış: access.log satır satır → AsenaPrivacyShield (anında IP maskesi + SQLi süzgeci) → uyarılar.
# =============================================================================
"""
ASENA-ANALYSIS - Log Parser & SQLi Detector

HUKUKİ UYARI: Bu yazılım sadece eğitim ve savunma amaçlıdır.
KVKK/GDPR uyumlu maskeleme içerir.

Koku alma: log dosyaları **satır satır** okunur; IP ``AsenaPrivacyShield.mask_ip`` ile maskelenir;
SQLi ``AsenaPrivacyShield.sqli_sieve_scan`` (Töre/süzgeç) ile tespit edilir.
YAML ``hunting_rules.yaml`` ile XSS vb. ek kurallar birleştirilir.
"""

from __future__ import annotations

import logging
import os
import re
import sys
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, Iterator, Optional
from urllib.parse import unquote, urlparse

import pandas as pd
import yaml

from engine.privacy_shield import AsenaPrivacyShield, PrivacyConfig

if TYPE_CHECKING:
    from engine.correlator import StoryTimelineRow

# Yerel lab: yalnızca bu istemci IP’leri analize alınır (varsayılan).
_LOCALHOST_CLIENTS = frozenset({"127.0.0.1", "::1"})

# AsenaCorrelator risk → timeline önceliği (yüksek = kritik)
_RISK_PRIORITY = {"CRITICAL": 100, "High": 70, "Medium": 40, "Low": 10}


def _print_tore_violation(masked_ip: str) -> None:
    msg = f"TÖRE İHLAL EDİLDİ: {masked_ip} SALDIRI ALTINDA"
    if sys.stdout.isatty():
        print(f"\033[91m{msg}\033[0m")
    else:
        print(msg)


def is_localhost_client_ip(ip: str) -> bool:
    """Güvenli laboratuvar: istemci 127.0.0.1 veya ::1 mi?"""
    return ip.strip() in _LOCALHOST_CLIENTS


_LOG = logging.getLogger("asena.parser.follow")


def _normalize_path_key(p: str | Path) -> str:
    try:
        return os.path.normcase(str(Path(p).resolve()))
    except OSError:
        return os.path.normcase(os.path.abspath(str(p)))


def _watch_changes_touch_file(changes: set[tuple[object, str]], log_file: Path) -> bool:
    """watchgod çıktısındaki (Change, path) öğeleri hedef log dosyasına denk mi?"""
    want = _normalize_path_key(log_file)
    try:
        parent_key = _normalize_path_key(log_file.parent)
    except OSError:
        parent_key = ""
    name = log_file.name
    for _, raw in changes:
        if _normalize_path_key(raw) == want:
            return True
        try:
            rp = Path(raw)
            if rp.name == name and parent_key and _normalize_path_key(rp.parent) == parent_key:
                return True
        except OSError:
            continue
    return False


def _iter_follow_log_lines(path: Path, *, read_existing: bool) -> Iterator[str]:
    """
    ``tail -f`` benzeri: dosyayı açık tutar; yeni satırlar eklendikçe üretir.

    Varsayılan: ``watchgod`` ile üst dizin izlenir; dosyaya yazım olunca okuma uyanır.
    ``ASENA_USE_POLL=1`` veya ``watchgod`` yoksa: kısa aralıklı polling (yedek).
    ``read_existing=False`` ise mevcut içerik atlanır (yalnızca sonradan yazılanlar).
    Log truncate olursa okuma konumu sıfırlanır.
    """
    use_poll = os.environ.get("ASENA_USE_POLL", "").strip().lower() in (
        "1",
        "true",
        "yes",
        "on",
    )
    watch_dir: str | None = None
    if not use_poll:
        try:
            from watchgod import watch as _watchgod_watch  # type: ignore[import-untyped]

            watch_dir = str(path.parent.resolve())
        except ImportError:
            use_poll = True
            _LOG.warning("watchgod yüklü değil; polling ile izleme kullanılıyor.")

    def _truncate_fixup(fh: object) -> None:
        try:
            size = path.stat().st_size
            pos = fh.tell()  # type: ignore[attr-defined]
            if pos > size:
                fh.seek(0)  # type: ignore[attr-defined]
        except OSError:
            pass

    with path.open(encoding="utf-8", errors="replace") as fh:
        if not read_existing:
            fh.seek(0, os.SEEK_END)
        while True:
            line = fh.readline()
            while line:
                yield line
                line = fh.readline()

            _truncate_fixup(fh)

            if use_poll or watch_dir is None:
                time.sleep(0.2)
                continue

            try:
                for changes in _watchgod_watch(
                    watch_dir,
                    debounce=50,
                    normal_sleep=80,
                    min_sleep=20,
                ):
                    if _watch_changes_touch_file(changes, path):
                        break
            except (KeyboardInterrupt, SystemExit):
                raise
            except Exception as e:
                _LOG.debug("watchgod uyarısı, polling’e düşülüyor: %s", e)
                time.sleep(0.2)


# Apache / Nginx combined (yedek eşleştirici)
_COMBINED_RE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<request_target>[^\s]+)(?: (?P<proto>HTTP/[\d.]+))?" '
    r"(?P<status>\d{3}) (?P<size>\S+|-)"
)


@dataclass(frozen=True)
class LogLine:
    raw: str
    ip: str  # maskelemiş istemci (AsenaPrivacyShield.mask_ip)
    timestamp: datetime
    method: str
    path: str
    query: str
    status_code: int
    request_line: str


@dataclass(frozen=True)
class RuleHit:
    rule_id: str
    category: str
    severity: str
    description: str


@dataclass(frozen=True)
class ParsedAlert:
    """Tek log satırından çıkan uyarı (korelasyon öncesi); IP maskelenmiş."""

    timestamp: datetime
    ip: str
    method: str
    path: str
    status_code: int
    raw_request: str
    scan_text: str
    hits: tuple[RuleHit, ...]


class AsenaParser:
    """
    Apache access log satırlarını parçalar; ``AsenaPrivacyShield`` ile maskeleme ve SQLi süzgeci.
    ``start_hunting()`` ``tail -f`` gibi canlı izler; tespitleri ``data/timeline.csv`` içine ekler.
    """

    # Apache Access Log (combined/common) — istek satırı
    _ACCESS_PATTERN = (
        r'(?P<ip>\S+) \S+ \S+ \[(?P<time>.*?)\] '
        r'"(?P<method>\S+) (?P<url>\S+) \S+" '
        r"(?P<status>\d+) (?P<size>\S+)"
    )

    def __init__(
        self,
        log_path: str | Path | None = None,
        *,
        timeline_csv: str | Path | None = None,
        rules_yaml: str | Path | None = None,
        privacy_cfg: PrivacyConfig | None = None,
        localhost_only: bool = True,
        read_existing: bool = False,
        lab_correlator: Any | None = None,
    ) -> None:
        from engine.correlator import AsenaCorrelator

        self.log_path = Path(log_path) if log_path else Path("logs/apache2/access.log")
        self.timeline_csv = Path(timeline_csv) if timeline_csv else Path("data/timeline.csv")
        self.rules_yaml = Path(rules_yaml) if rules_yaml else default_rules_path()
        self.privacy_cfg = privacy_cfg or PrivacyConfig()
        self.localhost_only = localhost_only
        self.read_existing = read_existing
        self.correlator = lab_correlator or AsenaCorrelator()
        self._live_story_seq = 0
        self.shield = AsenaPrivacyShield()
        self.regex = self._ACCESS_PATTERN
        self._log_re = re.compile(self.regex)

    def decode_and_clean(self, raw_url: str) -> str:
        """URL'deki %27 gibi kodları çözer ve analiz için büyük harfe çevirir."""
        return unquote(raw_url.replace("+", " ")).upper()

    def detect_sqli(self, scan_text: str) -> tuple[bool, Optional[str]]:
        """
        Töre (kurallar): SQL Injection imzalarını ``privacy_shield`` süzgecinden geçirir.
        Dönüş: (tespit edildi mi, ilk eşleşen kural kimliği veya None).
        """
        hits = self.shield.sqli_sieve_scan(scan_text)
        if not hits:
            return False, None
        return True, hits[0][0]

    def start_hunting(self) -> None:
        """
        ``tail -f`` gibi logu anlık izler; YAML + SQLi süzgeci ile eşleşen satırları
        ``finalize_timeline_for_export`` sonrası ``timeline_csv`` dosyasına ekler (Ctrl+C ile çıkış).
        """
        log_file = self.log_path
        if not log_file.is_file():
            print(f"[-] Hata: {log_file} bulunamadı. Önce Docker'ı çalıştırın veya log yolunu verin.")
            return
        if not self.rules_yaml.is_file():
            print(f"[-] Hata: kurallar dosyası yok: {self.rules_yaml}")
            return

        compiled = load_compiled_rules(self.rules_yaml)
        mode_note = "baştan + yeni satırlar" if self.read_existing else "yalnızca yeni satırlar (dosya sonundan)"
        print(f"[*] Canlı izleme: {log_file} ({mode_note}) -> {self.timeline_csv}")
        print("[*] Durdurmak için Ctrl+C")

        try:
            for line in _iter_follow_log_lines(log_file, read_existing=self.read_existing):
                self._observe_and_hunt_line(line, compiled)
        except KeyboardInterrupt:
            print("\n[*] Canlı izleme sonlandırıldı.")

    def _observe_and_hunt_line(
        self,
        line: str,
        compiled: list[tuple[dict[str, Any], re.Pattern[str]]],
    ) -> None:
        """
        Her satırda IP hafızası (``correlator.track_request``); av kuralları eşleşirse
        ``check_correlation`` ile son 60 s analizi ve timeline + kritik uyarı.
        """
        from engine.correlator import StoryTimelineRow, http_success_label
        from utils.exporter import append_timeline_csv_rows, resort_timeline_csv_by_priority

        parsed = self.parse_line(line)
        if not parsed:
            return
        if self.localhost_only and not is_localhost_client_ip(parsed.ip):
            return

        masked_ip = self.shield.mask_ip(parsed.ip)
        self.correlator.track_request(masked_ip)

        combined = decode_query_for_scan(parsed.query)
        scan_text = f"{parsed.path}?{combined}" if combined else parsed.path

        hits = scan_with_rules(scan_text, compiled)
        for rule_id, sev, desc in self.shield.sqli_sieve_scan(scan_text):
            hits.append(
                RuleHit(
                    rule_id=rule_id,
                    category="sqli",
                    severity=sev,
                    description=desc,
                )
            )
        hits = _dedupe_rule_hits(hits)
        if not hits:
            return

        risk_level, corr_reason = self.correlator.check_correlation(
            masked_ip, scan_text, parsed.status_code
        )
        priority = _RISK_PRIORITY.get(risk_level, 10)
        if risk_level == "CRITICAL":
            _print_tore_violation(masked_ip)

        self._live_story_seq += 1
        story_id = (
            f"tore-CRITICAL-{self._live_story_seq:04d}"
            if risk_level == "CRITICAL"
            else f"live-{self._live_story_seq:04d}"
        )
        ts_str = parsed.timestamp.isoformat(sep=" ", timespec="seconds")
        rules_matched = "|".join(h.rule_id for h in hits)

        row = StoryTimelineRow(
            story_id=story_id,
            sequence=1,
            phase="attack",
            timestamp=ts_str,
            attack_started_at=ts_str,
            attack_ended_at=ts_str,
            source_ip=masked_ip,
            payload=scan_text[:4096],
            http_status=parsed.status_code,
            success=http_success_label(parsed.status_code),
            method=parsed.method,
            path=parsed.path,
            rules_matched=rules_matched,
            priority=priority,
            tore_status=risk_level,
        )
        finalized = finalize_timeline_for_export([row], self.privacy_cfg)
        append_timeline_csv_rows(
            finalized,
            self.timeline_csv,
            legal_header=self.shield.legal_header(),
        )
        if risk_level == "CRITICAL":
            resort_timeline_csv_by_priority(self.timeline_csv)

        first_rule = hits[0].rule_id
        print(f"[!] SALDIRI TESPİT EDİLDİ: {finalized[0].source_ip} -> {first_rule} (timeline'a eklendi)")

        self.correlator.add_event(
            finalized[0].source_ip,
            finalized[0].timestamp,
            finalized[0].payload[:2048],
            parsed.status_code,
            risk_level=risk_level,
            corr_reason=corr_reason,
        )

    def parse_line(self, line: str) -> Optional[LogLine]:
        """Ham satırdan alanları çıkarır; IP henüz maskelenmez (çağıran maskeler)."""
        line = line.strip()
        if not line:
            return None
        m = self._log_re.match(line)
        if not m:
            return _parse_combined_fallback(line)
        g = m.groupdict()
        url = g.get("url") or ""
        base = "http://_"
        parsed = urlparse(base + url if url.startswith("/") else base + "/" + url)
        path = parsed.path or "/"
        query = parsed.query or ""
        try:
            ts = _parse_ts(g["time"])
        except ValueError:
            ts = datetime.min
        status = int(g["status"])
        return LogLine(
            raw=line,
            ip=g["ip"],
            timestamp=ts,
            method=g["method"],
            path=path,
            query=query,
            status_code=status,
            request_line=url,
        )

    def read_log_as_dataframe(self, path: Path) -> pd.DataFrame:
        content = path.read_text(encoding="utf-8", errors="replace")
        rows = [ln for ln in content.splitlines() if ln.strip()]
        return pd.DataFrame({"raw_line": rows})


def _parse_ts(ts: str) -> datetime:
    main = ts.split(" ", 1)[0]
    return datetime.strptime(main, "%d/%b/%Y:%H:%M:%S")


def _parse_combined_fallback(line: str) -> Optional[LogLine]:
    m = _COMBINED_RE.match(line)
    if not m:
        return None
    g = m.groupdict()
    target = g.get("request_target") or ""
    path_query = target.split(" ", 1)[0] if target else ""
    base = "http://_"
    parsed = urlparse(base + path_query if path_query.startswith("/") else base + "/" + path_query)
    path = parsed.path or "/"
    query = parsed.query or ""
    try:
        ts = _parse_ts(g["time"])
    except ValueError:
        ts = datetime.min
    status = int(g["status"])
    return LogLine(
        raw=line,
        ip=g["ip"],
        timestamp=ts,
        method=g["method"],
        path=path,
        query=query,
        status_code=status,
        request_line=target,
    )


def _with_masked_ip(line: LogLine, masked: str) -> LogLine:
    return LogLine(
        raw=line.raw,
        ip=masked,
        timestamp=line.timestamp,
        method=line.method,
        path=line.path,
        query=line.query,
        status_code=line.status_code,
        request_line=line.request_line,
    )


def parse_combined_line(line: str) -> Optional[LogLine]:
    p = AsenaParser().parse_line(line)
    if not p:
        return None
    shield = AsenaPrivacyShield()
    return _with_masked_ip(p, shield.mask_ip(p.ip))


def parse_all_lines(log_path: Path, *, localhost_only: bool = True) -> list[LogLine]:
    """Dosyayı satır satır okur; her satırda IP anında ``AsenaPrivacyShield`` ile maskelenir."""
    parser = AsenaParser()
    shield = parser.shield
    out: list[LogLine] = []
    with log_path.open(encoding="utf-8", errors="replace") as fh:
        for line in fh:
            p = parser.parse_line(line)
            if not p:
                continue
            if localhost_only and not is_localhost_client_ip(p.ip):
                continue
            out.append(_with_masked_ip(p, shield.mask_ip(p.ip)))
    out.sort(key=lambda x: x.timestamp)
    return out


def payload_display(line: LogLine) -> str:
    q = decode_query_for_scan(line.query)
    if q:
        return f"{line.path}?{q}"
    return line.path


def decode_query_for_scan(query: str) -> str:
    if not query:
        return ""
    return unquote(query.replace("+", " "))


def default_rules_path() -> Path:
    return Path(__file__).resolve().parent.parent / "rules" / "hunting_rules.yaml"


def load_compiled_rules(path: Path) -> list[tuple[dict[str, Any], re.Pattern[str]]]:
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    rules = raw.get("rules") or []
    out: list[tuple[dict[str, Any], re.Pattern[str]]] = []
    for r in rules:
        pat = r.get("pattern")
        if not pat:
            continue
        out.append((r, re.compile(pat)))
    return out


def scan_with_rules(scan_text: str, compiled: list[tuple[dict[str, Any], re.Pattern[str]]]) -> list[RuleHit]:
    hits: list[RuleHit] = []
    for meta, rx in compiled:
        if rx.search(scan_text):
            hits.append(
                RuleHit(
                    rule_id=str(meta["id"]),
                    category=str(meta.get("category", "unknown")),
                    severity=str(meta.get("severity", "low")),
                    description=str(meta.get("description", "")),
                )
            )
    return hits


def _dedupe_rule_hits(hits: list[RuleHit]) -> list[RuleHit]:
    seen: set[str] = set()
    out: list[RuleHit] = []
    for h in hits:
        if h.rule_id in seen:
            continue
        seen.add(h.rule_id)
        out.append(h)
    return out


def parse_log_file(
    log_path: Path,
    rules_yaml: Path,
    *,
    localhost_only: bool = True,
) -> list[ParsedAlert]:
    """
    ``access.log`` dosyasını satır satır okur; IP anında maskelenir, SQLi ``sqli_sieve_scan`` ile tespit edilir.
    """
    parser = AsenaParser()
    shield = parser.shield
    compiled = load_compiled_rules(rules_yaml)
    alerts: list[ParsedAlert] = []
    with log_path.open(encoding="utf-8", errors="replace") as fh:
        for line in fh:
            parsed = parser.parse_line(line)
            if not parsed:
                continue
            if localhost_only and not is_localhost_client_ip(parsed.ip):
                continue
            masked_ip = shield.mask_ip(parsed.ip)
            combined = decode_query_for_scan(parsed.query)
            scan_text = f"{parsed.path}?{combined}" if combined else parsed.path

            hits = scan_with_rules(scan_text, compiled)
            for rule_id, sev, desc in shield.sqli_sieve_scan(scan_text):
                hits.append(
                    RuleHit(
                        rule_id=rule_id,
                        category="sqli",
                        severity=sev,
                        description=desc,
                    )
                )
            hits = _dedupe_rule_hits(hits)
            if not hits:
                continue
            alerts.append(
                ParsedAlert(
                    timestamp=parsed.timestamp,
                    ip=masked_ip,
                    method=parsed.method,
                    path=parsed.path,
                    status_code=parsed.status_code,
                    raw_request=parsed.request_line[:2048],
                    scan_text=scan_text[:4096],
                    hits=tuple(hits),
                )
            )
    alerts.sort(key=lambda a: a.timestamp)
    return alerts


def finalize_timeline_for_export(
    rows: list[StoryTimelineRow],
    cfg: PrivacyConfig,
) -> list[StoryTimelineRow]:
    """
    parser/correlator çıktısı timeline.csv veya JSON'a yazılmadan önce zorunlu
    gizlilik kapısı: ``engine.privacy_shield.apply_privacy_to_story``.
    """
    from .privacy_shield import apply_privacy_to_story

    return apply_privacy_to_story(rows, cfg)


def sanitize_scan_text_for_export(scan_text: str, salt: str | None = None) -> str:
    """
    İstek metnini AsenaPrivacyShield üzerinden geçirir (dışa aktarım/denetim için temiz metin).
    """
    from .privacy_shield import AsenaPrivacyShield, minimize_redact_request_text

    shield = AsenaPrivacyShield(salt=salt)
    return minimize_redact_request_text(scan_text, shield)
