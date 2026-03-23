#!/usr/bin/env python3
# =============================================================================
# ASENA-ANALYSIS — Hukuki şerh: Bu yazılım defansif güvenlik analizi içindir;
# saldırı üretimi veya yetkisiz erişim için kullanılmamalıdır. Ayrıntı: LEGAL.md
# Kullanım: eğitim, izinli lab (DVWA/localhost) veya yetkili ortamlar. TCK 243-244.
# =============================================================================
"""
ASENA — Savunma ve log analizi aracı (yerel / izinli lab ortamı için).

Ana giriş noktası: ``python asena.py <komut>`` veya kurulumdan sonra ``asena`` (``pip install -e .``).

Yetkisiz sistemlere karşı kullanılmamalıdır; üretilen raporlar KVKK/GDPR için
maskeleme ile sınırlandırılır.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from datetime import timedelta
from pathlib import Path

__version__ = "1.0.0"

ROOT = Path(__file__).resolve().parent
# Geliştirme: repo kökünde ``src/engine``; kurulum: ``site-packages/engine`` ile yan yana
if (ROOT / "src" / "engine").is_dir():
    _code_root = ROOT / "src"
elif (ROOT / "engine").is_dir():
    _code_root = ROOT
else:
    _code_root = ROOT / "src"
if str(_code_root) not in sys.path:
    sys.path.insert(0, str(_code_root))

from engine.correlator import AsenaCorrelator, build_story_timeline  # noqa: E402
from engine.parser import (  # noqa: E402
    AsenaParser,
    default_rules_path,
    finalize_timeline_for_export,
    parse_all_lines,
    parse_log_file,
)
from engine.tore_evaluator import default_tore_rules_path, evaluate_tore_rules  # noqa: E402
from utils.exporter import (  # noqa: E402
    export_asena_report_pdf,
    export_executive_summary_md,
    export_timeline_csv,
    start_periodic_linkedin_refresh,
)
from utils.privacy import AsenaPrivacyShield, PrivacyConfig  # noqa: E402


def _require_consent(args: argparse.Namespace) -> bool:
    """Yasal uyarı + kullanıcı onayı; analiz onaysız başlamaz."""
    if getattr(args, "i_accept", False):
        return True
    if os.environ.get("ASENA_I_ACCEPT", "").strip().lower() in ("1", "yes", "true", "evet"):
        return True
    shield = AsenaPrivacyShield()
    print(shield.legal_header(), end="")
    print(shield.legal_disclaimer())
    print()
    if not sys.stdin.isatty():
        print(
            "Hata: Etkileşimli onay mümkün değil. --i-accept veya ASENA_I_ACCEPT=1 kullanın.",
            file=sys.stderr,
        )
        return False
    ans = input("Analize devam etmek için 'evet' veya 'yes' yazın (iptal: Enter): ").strip().lower()
    return ans in ("evet", "yes", "e", "y")


def _cmd_analyze(args: argparse.Namespace) -> int:
    log_path = Path(args.log)
    rules_path = Path(args.rules) if args.rules else default_rules_path()
    out_csv = Path(args.out)

    if not log_path.is_file():
        print(f"Hata: log dosyası yok: {log_path}", file=sys.stderr)
        return 2
    if not rules_path.is_file():
        print(f"Hata: kurallar dosyası yok: {rules_path}", file=sys.stderr)
        return 2

    if not _require_consent(args):
        print("Aborted: yasal onay verilmedi.", file=sys.stderr)
        return 3

    window = timedelta(minutes=args.window_minutes)
    context = timedelta(seconds=args.context_seconds)
    localhost_only = not getattr(args, "allow_remote_ips", False)
    alerts = parse_log_file(log_path, rules_path, localhost_only=localhost_only)

    tore_hits: list = []
    if not getattr(args, "no_tore", False):
        tore_path = Path(args.tore_rules) if args.tore_rules else default_tore_rules_path()
        if tore_path.is_file():
            tore_hits = evaluate_tore_rules(alerts, tore_path)
            for h in tore_hits:
                print(f"[Töre] {h.rule_id} {h.name}: {h.action} — {h.detail}")

    all_lines = parse_all_lines(log_path, localhost_only=localhost_only)
    story = build_story_timeline(
        alerts,
        all_lines,
        window=window,
        context=context,
    )
    salt = args.salt or os.environ.get("ASENA_SALT", "")
    if args.privacy_mode == "hash" and not salt and not os.environ.get("ASENA_SALT"):
        print(
            "Uyarı: hash modunda özel salt yok; varsayılan AsenaPrivacyShield tuzu kullanılıyor. "
            "Üretimde ASENA_SALT veya --salt ayarlayın.",
            file=sys.stderr,
        )
    privacy_cfg = PrivacyConfig(mode=args.privacy_mode, salt=salt)
    # Zorunlu: timeline.csv öncesi AsenaPrivacyShield (parser.finalize_timeline_for_export)
    story_out = finalize_timeline_for_export(story, privacy_cfg)
    export_timeline_csv(
        story_out,
        out_csv,
        legal_header=AsenaPrivacyShield().legal_header(),
    )

    if args.json:
        payload = {
            "version": __version__,
            "legal_notice": AsenaPrivacyShield().legal_header(),
            "log": str(log_path),
            "rules": str(rules_path),
            "tore_rules": str(Path(args.tore_rules)) if args.tore_rules else str(default_tore_rules_path()),
            "tore_hits": [
                {
                    "rule_id": h.rule_id,
                    "name": h.name,
                    "action": h.action,
                    "detail": h.detail,
                }
                for h in tore_hits
            ],
            "context_seconds": args.context_seconds,
            "privacy_mode": args.privacy_mode,
            "row_count": len(story_out),
            "timeline": [
                {
                    "story_id": r.story_id,
                    "sequence": r.sequence,
                    "phase": r.phase,
                    "timestamp": r.timestamp,
                    "attack_started_at": r.attack_started_at,
                    "attack_ended_at": r.attack_ended_at,
                    "source_ip": r.source_ip,
                    "payload": r.payload,
                    "http_status": r.http_status,
                    "success": r.success,
                    "method": r.method,
                    "path": r.path,
                    "rules_matched": [x for x in r.rules_matched.split("|") if x]
                    if r.rules_matched
                    else [],
                    "priority": r.priority,
                    "tore_status": r.tore_status,
                }
                for r in story_out
            ],
        }
        json_path = Path(args.json)
        json_path.parent.mkdir(parents=True, exist_ok=True)
        json_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"JSON: {json_path}")

    print(f"Timeline CSV: {out_csv} ({len(story_out)} satır, privacy={args.privacy_mode})")
    return 0


def _cmd_watch(args: argparse.Namespace) -> int:
    """
    Docker / lab erişim logunu ``tail -f`` gibi izler; tespitler ``timeline.csv`` ve isteğe bağlı
    laboratuvar özet CSV'ye yazılır.
    """
    log_path = Path(args.log)
    rules_path = Path(args.rules) if args.rules else default_rules_path()

    if not log_path.is_file():
        print(f"Hata: log dosyası yok: {log_path}", file=sys.stderr)
        return 2
    if not rules_path.is_file():
        print(f"Hata: kurallar dosyası yok: {rules_path}", file=sys.stderr)
        return 2

    if not getattr(args, "_asena_consent_done", False):
        if not _require_consent(args):
            print("Aborted: yasal onay verilmedi.", file=sys.stderr)
            return 3

    salt = args.salt or os.environ.get("ASENA_SALT", "")
    privacy_cfg = PrivacyConfig(mode=args.privacy_mode, salt=salt)

    lab: AsenaCorrelator | None = None
    if not getattr(args, "no_correlator", False):
        lab = AsenaCorrelator(output_file=Path(args.correlator_out))

    print("🐺 ASENA-ANALYSIS — canlı izleme")
    print("⚖️ Hukuki uyarı: Yalnızca izinli laboratuvar / yetkili ortamda kullanın.")
    timeline_path = Path(args.out)
    if os.environ.get("ASENA_SKIP_LINKEDIN_REFRESH", "").strip().lower() not in (
        "1",
        "true",
        "yes",
        "on",
    ):
        try:
            refresh_sec = int(os.environ.get("ASENA_LINKEDIN_REFRESH_SEC", "300"))
        except ValueError:
            refresh_sec = 300
        start_periodic_linkedin_refresh(timeline_path, interval_sec=max(60, refresh_sec))
        linkedin_post = (ROOT / "data" / "linkedin_post.txt").resolve()
        print(f"[*] LinkedIn özeti her {max(60, refresh_sec)} sn güncellenir: {linkedin_post}")
    print(f"[*] {log_path} izleniyor (Ctrl+C ile çıkış). Av başlasın…\n")

    parser = AsenaParser(
        log_path=log_path,
        timeline_csv=Path(args.out),
        rules_yaml=rules_path,
        privacy_cfg=privacy_cfg,
        localhost_only=not getattr(args, "allow_remote_ips", False),
        read_existing=args.read_existing,
        lab_correlator=lab,
    )
    parser.start_hunting()
    return 0


_streamlit_proc: subprocess.Popen | None = None


def _terminate_streamlit() -> None:
    global _streamlit_proc
    p = _streamlit_proc
    if p is None or p.poll() is not None:
        return
    p.terminate()
    try:
        p.wait(timeout=8)
    except subprocess.TimeoutExpired:
        p.kill()


def _cmd_serve(args: argparse.Namespace) -> int:
    """Yalnızca Streamlit panosu (canlı grafikler)."""
    dash = ROOT / "src" / "dashboard.py"
    if not dash.is_file():
        print(f"Hata: panel dosyası yok: {dash}", file=sys.stderr)
        return 2
    env = os.environ.copy()
    src = str(ROOT / "src")
    env["PYTHONPATH"] = src + os.pathsep + env.get("PYTHONPATH", "")
    cmd = [
        sys.executable,
        "-m",
        "streamlit",
        "run",
        str(dash),
        "--server.port",
        str(args.dashboard_port),
        "--server.address",
        args.dashboard_host,
    ]
    print(f"[*] Streamlit: http://{args.dashboard_host}:{args.dashboard_port}")
    return int(subprocess.call(cmd, cwd=str(ROOT), env=env))


def _cmd_start(args: argparse.Namespace) -> int:
    """
    Tek komut: arka planda Streamlit + önde ``watch`` (tail -f) ile timeline üretimi.
    Ctrl+C ile her ikisi sonlanır.
    """
    dash = ROOT / "src" / "dashboard.py"
    if not dash.is_file():
        print(f"Hata: panel dosyası yok: {dash}", file=sys.stderr)
        return 2
    global _streamlit_proc
    env = os.environ.copy()
    src = str(ROOT / "src")
    env["PYTHONPATH"] = src + os.pathsep + env.get("PYTHONPATH", "")
    cmd = [
        sys.executable,
        "-m",
        "streamlit",
        "run",
        str(dash),
        "--server.port",
        str(args.dashboard_port),
        "--server.address",
        args.dashboard_host,
    ]
    try:
        _streamlit_proc = subprocess.Popen(
            cmd,
            cwd=str(ROOT),
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except OSError as e:
        print(f"Uyarı: Dashboard başlatılamadı ({e}); yalnızca watch çalışacak.", file=sys.stderr)
        _streamlit_proc = None
    else:
        print(f"[*] Dashboard: http://{args.dashboard_host}:{args.dashboard_port}")

    try:
        return _cmd_watch(args)
    finally:
        _terminate_streamlit()


def _fire_initial_salute_from_main() -> None:
    """
    ``watch`` / ``start`` girişinde önce **Bozkurt selamı** (Twilio WhatsApp öncelikli).

    ``ASENA_SKIP_INITIAL_SALUTE=1`` ile kapatılır. Kanal: varsayılan ``whatsapp``;
    ``ASENA_INITIAL_SALUTE_CHANNEL=sms|both`` ile değiştirilebilir.
    """
    if os.environ.get("ASENA_SKIP_INITIAL_SALUTE", "").strip().lower() in ("1", "true", "yes", "on"):
        return
    ch = os.environ.get("ASENA_INITIAL_SALUTE_CHANNEL", "whatsapp").strip().lower()
    if ch not in ("whatsapp", "sms", "both"):
        ch = "whatsapp"
    try:
        from utils.notifier import AsenaMessenger

        r = AsenaMessenger().send_initial_salute(channel=ch)  # type: ignore[arg-type]
        if any(r.values()):
            print(
                "🐺 Bozkurt'tan selamlar — WhatsApp/Twilio ile töre selamı iletildi; "
                "log dinlemeye geçiliyor."
            )
    except Exception as e:
        print(f"[-] Töre selamı atlandı (Twilio yok veya hata): {e}")


def _cmd_summary(args: argparse.Namespace) -> int:
    """Executive Summary Markdown (LinkedIn gövde gösterisi)."""
    timeline = Path(args.timeline)
    out_md = Path(args.out)
    if not timeline.is_file():
        print(f"Hata: timeline yok: {timeline}", file=sys.stderr)
        return 2
    if not _require_consent(args):
        print("Aborted: yasal onay verilmedi.", file=sys.stderr)
        return 3
    try:
        export_executive_summary_md(timeline, out_md)
    except Exception as e:
        print(f"Hata: {e}", file=sys.stderr)
        return 4
    print(f"Olay özeti: {out_md.resolve()}")
    return 0


def _cmd_report(args: argparse.Namespace) -> int:
    """timeline.csv özetinden asena_report.pdf (LinkedIn / portföy)."""
    timeline = Path(args.timeline)
    out_pdf = Path(args.out)
    if not timeline.is_file():
        print(f"Hata: timeline bulunamadı: {timeline}", file=sys.stderr)
        print("Önce: python asena.py analyze ... veya watch çalıştırın.", file=sys.stderr)
        return 2
    if not _require_consent(args):
        print("Aborted: yasal onay verilmedi.", file=sys.stderr)
        return 3
    try:
        export_asena_report_pdf(timeline, out_pdf)
    except Exception as e:
        print(f"Hata: PDF üretilemedi: {e}", file=sys.stderr)
        return 4
    print(f"PDF rapor: {out_pdf.resolve()}")
    print("LinkedIn: PDF içindeki önerilen metni kopyalayıp paylaşabilirsiniz (KVKK: payload yok).")
    return 0


def _cmd_salute(args: argparse.Namespace) -> int:
    """Twilio üzerinden töre selamı (ilk operasyonel mesaj)."""
    if not _require_consent(args):
        print("Aborted: yasal onay verilmedi.", file=sys.stderr)
        return 3
    try:
        from utils.notifier import AsenaMessenger
    except ImportError as e:
        print(f"Hata: {e}", file=sys.stderr)
        return 4
    m = AsenaMessenger()
    result = m.send_initial_salute(channel=args.channel)
    print(f"🐺 Töre selamı — WhatsApp SID: {result.get('whatsapp')} | SMS SID: {result.get('sms')}")
    if not any(result.values()):
        print(
            "Uyarı: Mesaj gitmedi. TWILIO_SID (veya TWILIO_ACCOUNT_SID), TWILIO_TOKEN (veya "
            "TWILIO_AUTH_TOKEN), TWILIO_TO_NUMBER ve kanala göre TWILIO_FROM_WHATSAPP / "
            "TWILIO_FROM_SMS ayarlayın.",
            file=sys.stderr,
        )
        return 5
    return 0


def _add_watch_arguments(p: argparse.ArgumentParser) -> None:
    p.add_argument(
        "--log",
        default="docker/logs/apache2/access.log",
        help="Combined erişim logu (varsayılan: Docker volume)",
    )
    p.add_argument(
        "--rules",
        default=None,
        help="hunting_rules.yaml (varsayılan: src/rules/hunting_rules.yaml)",
    )
    p.add_argument(
        "--out",
        default="data/timeline.csv",
        help="Canlı tespitlerin ekleneceği timeline CSV",
    )
    p.add_argument(
        "--correlator-out",
        default="data/correlator_events.csv",
        metavar="FILE",
        help="AsenaCorrelator laboratuvar özet CSV (pandas)",
    )
    p.add_argument(
        "--no-correlator",
        action="store_true",
        help="AsenaCorrelator özet dosyasını yazma",
    )
    p.add_argument(
        "--read-existing",
        action="store_true",
        help="Önce dosyadaki mevcut satırları işle, sonra yeni satırları bekle",
    )
    p.add_argument(
        "--privacy-mode",
        choices=["subnet", "hash", "none"],
        default="subnet",
        help="PII: IP maskeleme modu",
    )
    p.add_argument("--salt", default=None, help="hash modu için tuz veya ASENA_SALT")
    p.add_argument(
        "--i-accept",
        action="store_true",
        help="Yasal uyarıyı okudum (CI: ASENA_I_ACCEPT=1)",
    )
    p.add_argument(
        "--allow-remote-ips",
        action="store_true",
        help="127.0.0.1 dışı istemci IP satırlarını da işle",
    )


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="asena",
        description=(
            "Savunma amaçlı HTTP log analizi: YAML kuralları, timeline.csv (KVKK uyumlu maskeleme)."
        ),
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    sub = p.add_subparsers(dest="command", required=True)
    a = sub.add_parser(
        "analyze",
        help="Log dosyasını analiz et, CSV üret",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=AsenaPrivacyShield().legal_disclaimer(),
    )
    a.add_argument("--log", default="logs/access.log", help="Combined format erişim logu")
    a.add_argument(
        "--rules",
        default=None,
        help="hunting_rules.yaml yolu (varsayılan: src/rules/hunting_rules.yaml)",
    )
    a.add_argument(
        "--out",
        default="data/timeline.csv",
        help="Çıktı CSV (varsayılan: data/timeline.csv)",
    )
    a.add_argument(
        "--json",
        default=None,
        metavar="FILE",
        help="İsteğe bağlı JSON raporu dosyası",
    )
    a.add_argument(
        "--window-minutes",
        type=int,
        default=5,
        help="Aynı IP için zincir penceresi (dakika)",
    )
    a.add_argument(
        "--context-seconds",
        type=int,
        default=120,
        help="Hikaye: saldırı zincirinden önce/sonra kaç saniye trafik dahil edilsin",
    )
    a.add_argument(
        "--privacy-mode",
        choices=["subnet", "hash", "none"],
        default="subnet",
        help="PII: IP maskeleme — subnet (varsayılan), hash (salt gerekir), none (yalnızca güvenilir ortam)",
    )
    a.add_argument(
        "--salt",
        default=None,
        help="SHA256+giz anahtarı (anonymize_user); yoksa ASENA_SALT veya varsayılan tuz",
    )
    a.add_argument(
        "--i-accept",
        action="store_true",
        help="Yasal uyarıyı okudum; onay prompt'unu atla (CI için ASENA_I_ACCEPT=1)",
    )
    a.add_argument(
        "--allow-remote-ips",
        action="store_true",
        help="Uyumluluk: 127.0.0.1 dışı istemci IP'li satırları da analiz et (yalnızca güvenilir ortam)",
    )
    a.add_argument(
        "--tore-rules",
        default=None,
        metavar="FILE",
        help="Töre korelasyon kuralları (sqli_rules.yaml; varsayılan: src/rules/sqli_rules.yaml)",
    )
    a.add_argument(
        "--no-tore",
        action="store_true",
        help="sqli_rules.yaml (Töre) değerlendirmesini atla",
    )
    a.set_defaults(func=_cmd_analyze)

    w = sub.add_parser(
        "watch",
        help="Erişim logunu anlık izle (tail -f), tespitleri timeline'a ekle",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=AsenaPrivacyShield().legal_disclaimer(),
    )
    _add_watch_arguments(w)
    w.set_defaults(func=_cmd_watch)

    sv = sub.add_parser(
        "serve",
        help="Streamlit panosu (canlı grafikler, timeline.csv okur)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=AsenaPrivacyShield().legal_disclaimer(),
    )
    sv.add_argument(
        "--dashboard-port",
        type=int,
        default=8501,
        metavar="PORT",
        help="Streamlit HTTP portu",
    )
    sv.add_argument(
        "--dashboard-host",
        default="127.0.0.1",
        metavar="ADDR",
        help="Dinlenecek adres",
    )
    sv.set_defaults(func=_cmd_serve)

    st = sub.add_parser(
        "start",
        help="Dashboard + canlı log izleme (tek komut: tail -f + Streamlit)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=AsenaPrivacyShield().legal_disclaimer(),
    )
    _add_watch_arguments(st)
    st.add_argument(
        "--dashboard-port",
        type=int,
        default=8501,
        metavar="PORT",
        help="Streamlit portu",
    )
    st.add_argument(
        "--dashboard-host",
        default="127.0.0.1",
        metavar="ADDR",
        help="Streamlit dinleme adresi",
    )
    st.set_defaults(func=_cmd_start)

    rep = sub.add_parser(
        "report",
        help="timeline.csv özetinden asena_report.pdf (LinkedIn / portföy paylaşımı)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=AsenaPrivacyShield().legal_disclaimer(),
    )
    rep.add_argument(
        "--timeline",
        default="data/timeline.csv",
        help="Girdi timeline CSV (maskeli)",
    )
    rep.add_argument(
        "--out",
        default="data/asena_report.pdf",
        help="Çıktı PDF dosyası",
    )
    rep.add_argument(
        "--i-accept",
        action="store_true",
        help="Yasal uyarıyı okudum (CI: ASENA_I_ACCEPT=1)",
    )
    rep.set_defaults(func=_cmd_report)

    sal = sub.add_parser(
        "salute",
        help="Twilio ile töre selamı (ilk canlı operasyonel mesaj — WhatsApp/SMS)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=AsenaPrivacyShield().legal_disclaimer(),
    )
    sal.add_argument(
        "--channel",
        choices=["whatsapp", "sms", "both"],
        default="whatsapp",
        help="Varsayılan: WhatsApp Sandbox/üretim numarası",
    )
    sal.add_argument(
        "--i-accept",
        action="store_true",
        help="Yasal uyarıyı okudum (CI: ASENA_I_ACCEPT=1)",
    )
    sal.set_defaults(func=_cmd_salute)

    summ = sub.add_parser(
        "summary",
        help="Olay özeti (Executive Summary) Markdown — LinkedIn / metrikler",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=AsenaPrivacyShield().legal_disclaimer(),
    )
    summ.add_argument(
        "--timeline",
        default="data/timeline.csv",
        help="Kaynak timeline CSV",
    )
    summ.add_argument(
        "--out",
        default="data/executive_summary.md",
        help="Çıktı Markdown dosyası",
    )
    summ.add_argument(
        "--i-accept",
        action="store_true",
        help="Yasal uyarıyı okudum (CI: ASENA_I_ACCEPT=1)",
    )
    summ.set_defaults(func=_cmd_summary)

    args = p.parse_args(argv)
    if getattr(args, "command", None) in ("watch", "start"):
        if not _require_consent(args):
            print("Aborted: yasal onay verilmedi.", file=sys.stderr)
            return 3
        _fire_initial_salute_from_main()
        setattr(args, "_asena_consent_done", True)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
