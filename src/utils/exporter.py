# =============================================================================
# ASENA-ANALYSIS — Hukuki şerh: Defansif analiz; yetkisiz kullanım yasaktır. LEGAL.md
# Çıktı yalnızca AsenaPrivacyShield sonrası satırlarla doldurulmalıdır.
# =============================================================================
"""timeline.csv üretici — Bozkurt hikayesi (önce / saldırı / sonra).

PDF: ``export_asena_report_pdf`` → ``asena_report.pdf`` (LinkedIn / portföy özeti).

Markdown: ``export_executive_summary_md`` → ``executive_summary.md`` (Executive Summary / metrikler).

LinkedIn metni: ``generate_linkedin_summary(df)`` → ``data/linkedin_post.txt`` (ganimet özeti).

Canlı izleme: ``start_periodic_linkedin_refresh(timeline_csv)`` — arka planda periyodik güncelleme.
"""

from __future__ import annotations

import csv
from datetime import datetime
from io import StringIO
from pathlib import Path
from typing import Any

from engine.correlator import StoryTimelineRow


_TIMELINE_FIELDNAMES = [
    "story_id",
    "sequence",
    "phase",
    "timestamp",
    "attack_started_at",
    "attack_ended_at",
    "source_ip",
    "payload",
    "http_status",
    "success",
    "method",
    "path",
    "rules_matched",
    "priority",
    "tore_status",
]


def export_timeline_csv(
    rows: list[StoryTimelineRow],
    out_path: Path,
    *,
    legal_header: str | None = None,
) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8", newline="") as f:
        if legal_header:
            f.write(legal_header)
        w = csv.DictWriter(f, fieldnames=_TIMELINE_FIELDNAMES, extrasaction="ignore")
        w.writeheader()
        for r in rows:
            w.writerow(
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
                    "rules_matched": r.rules_matched,
                    "priority": r.priority,
                    "tore_status": r.tore_status,
                }
            )


def _upgrade_timeline_csv_schema_if_needed(out_path: Path) -> None:
    """Eski timeline dosyasına ``priority`` / ``tore_status`` sütunlarını ekler."""
    if not out_path.is_file() or out_path.stat().st_size == 0:
        return
    raw = out_path.read_text(encoding="utf-8")
    lines = raw.splitlines()
    header_idx: int | None = None
    for i, line in enumerate(lines):
        if line.strip().startswith("story_id,"):
            header_idx = i
            break
    if header_idx is None:
        return
    header_line = lines[header_idx]
    if "priority" in header_line and "tore_status" in header_line:
        return
    preamble = lines[:header_idx]
    data_lines = lines[header_idx + 1 :]
    if not data_lines:
        return
    buf = StringIO("\n".join([header_line] + data_lines))
    reader = csv.DictReader(buf)
    old_rows = list(reader)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8", newline="") as f:
        for pl in preamble:
            f.write(pl + "\n")
        w = csv.DictWriter(f, fieldnames=_TIMELINE_FIELDNAMES, extrasaction="ignore")
        w.writeheader()
        for row in old_rows:
            row.setdefault("priority", "0")
            row.setdefault("tore_status", "")
            w.writerow({k: row.get(k, "") for k in _TIMELINE_FIELDNAMES})


def append_timeline_csv_rows(
    rows: list[StoryTimelineRow],
    out_path: Path,
    *,
    legal_header: str | None = None,
) -> None:
    """
    ``export_timeline_csv`` ile aynı şema; dosya yoksa veya boşsa başlık + isteğe bağlı hukuki üst bilgi yazar,
    ardından satırları ekler. Mevcut dolu dosyaya yalnızca veri satırları eklenir (tekrar başlık yazılmaz).
    """
    if not rows:
        return
    out_path.parent.mkdir(parents=True, exist_ok=True)
    new_file = not out_path.exists() or out_path.stat().st_size == 0
    if not new_file:
        _upgrade_timeline_csv_schema_if_needed(out_path)
    mode = "w" if new_file else "a"
    with out_path.open(mode, encoding="utf-8", newline="") as f:
        if new_file and legal_header:
            f.write(legal_header)
        w = csv.DictWriter(f, fieldnames=_TIMELINE_FIELDNAMES, extrasaction="ignore")
        if new_file:
            w.writeheader()
        for r in rows:
            w.writerow(
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
                    "rules_matched": r.rules_matched,
                    "priority": r.priority,
                    "tore_status": r.tore_status,
                }
            )


def resort_timeline_csv_by_priority(out_path: Path) -> None:
    """
    ``timeline.csv`` içindeki veri satırlarını ``priority`` (yüksek önce), sonra ``timestamp`` ile sıralar.
    Üst bilgi (# …) ve ayırıcı çizgi korunur.
    """
    if not out_path.exists() or out_path.stat().st_size == 0:
        return
    raw = out_path.read_text(encoding="utf-8")
    lines = raw.splitlines()
    header_idx: int | None = None
    for i, line in enumerate(lines):
        if line.strip().startswith("story_id,"):
            header_idx = i
            break
    if header_idx is None:
        return
    preamble = lines[:header_idx]
    header_line = lines[header_idx]
    data_lines = lines[header_idx + 1 :]
    if not data_lines:
        return
    buf = StringIO("\n".join([header_line] + data_lines))
    reader = csv.DictReader(buf)
    fieldnames = reader.fieldnames or list(_TIMELINE_FIELDNAMES)
    rows: list[dict[str, str]] = []
    for row in reader:
        if not any(row.values()):
            continue
        if "priority" not in row or row["priority"] is None or row["priority"] == "":
            row["priority"] = "0"
        if "tore_status" not in row or row["tore_status"] is None:
            row["tore_status"] = ""
        rows.append(row)

    def _sort_key(r: dict[str, str]) -> tuple[int, str]:
        try:
            p = -int(r.get("priority") or 0)
        except ValueError:
            p = 0
        return (p, r.get("timestamp") or "")

    rows.sort(key=_sort_key)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8", newline="") as f:
        for pl in preamble:
            f.write(pl + "\n")
        w = csv.DictWriter(f, fieldnames=_TIMELINE_FIELDNAMES, extrasaction="ignore")
        w.writeheader()
        for row in rows:
            out_row = {k: row.get(k, "") for k in _TIMELINE_FIELDNAMES}
            w.writerow(out_row)


def load_timeline_csv_for_report(path: Path) -> Any:
    """
    ``timeline.csv`` okur; hukuki üst bilgi satırlarını atlar (``dashboard.load_data`` ile uyumlu).
    ``pandas.DataFrame`` döndürür.
    """
    import pandas as pd

    if not path.is_file() or path.stat().st_size == 0:
        return pd.DataFrame()
    lines = path.read_text(encoding="utf-8").splitlines()
    start: int | None = None
    for i, line in enumerate(lines):
        if line.strip().startswith("story_id,"):
            start = i
            break
    if start is None:
        return pd.DataFrame()
    buf = StringIO("\n".join(lines[start:]))
    return pd.read_csv(buf)


def summarize_timeline_for_pdf(df: Any) -> dict[str, Any]:
    """PDF / LinkedIn metni için özet sayılar (maskeli timeline satırlarından)."""
    if df is None or len(df) == 0:
        return {
            "total_rows": 0,
            "attack_events": 0,
            "critical_events": 0,
            "unique_stories": 0,
        }
    total = int(len(df))
    phase = df["phase"].fillna("").astype(str).str.lower() if "phase" in df.columns else None
    attack_events = int((phase == "attack").sum()) if phase is not None else 0
    ts = df["tore_status"].fillna("").astype(str).str.strip() if "tore_status" in df.columns else None
    critical_events = int((ts == "CRITICAL").sum()) if ts is not None else 0
    unique_stories = int(df["story_id"].nunique()) if "story_id" in df.columns else 0
    return {
        "total_rows": total,
        "attack_events": attack_events,
        "critical_events": critical_events,
        "unique_stories": unique_stories,
    }


def export_asena_report_pdf(
    timeline_csv: Path,
    out_pdf: Path,
    *,
    legal_footer: str | None = None,
) -> None:
    """
    ``timeline.csv`` özetinden ``asena_report.pdf`` üretir (LinkedIn / portföy paylaşımı için).

    İçerik: özet istatistikler, KVKK notu, önerilen LinkedIn metni şablonu.
    Ham payload uzun tabloda yer almaz; yalnızca sayımlar.
    """
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import cm
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
    import reportlab

    from utils.privacy import AsenaPrivacyShield

    df = load_timeline_csv_for_report(timeline_csv)
    m = summarize_timeline_for_pdf(df)
    shield = AsenaPrivacyShield()
    footer = legal_footer or shield.legal_disclaimer()
    x = m["attack_events"]
    linkedin_suggested = (
        f"ASENA-ANALYSIS ile bugün {x} adet saldırı denemesini tespit ettim ve analiz ettim. "
        f"#CyberSecurity #DefensiveSecurity #ASENA"
    )
    linkedin_alt = (
        "Not: Pasif IDS/ analiz aracında sayı, tespit edilen saldırı-fazı satırlarıdır. "
        "Kurumsal 'engelleme' için WAF/IPS ile entegrasyon gerekir; paylaşımda ifadeyi ortamınıza göre düzenleyin."
    )

    vera = Path(reportlab.__file__).resolve().parent / "fonts" / "Vera.ttf"
    if not vera.is_file():
        raise FileNotFoundError(f"ReportLab Vera font bulunamadı: {vera}")
    pdfmetrics.registerFont(TTFont("Vera", str(vera)))

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "title",
        parent=styles["Heading1"],
        fontName="Vera",
        fontSize=16,
        spaceAfter=12,
    )
    body_style = ParagraphStyle(
        "body",
        parent=styles["Normal"],
        fontName="Vera",
        fontSize=10,
        leading=14,
    )
    small_style = ParagraphStyle(
        "small",
        parent=styles["Normal"],
        fontName="Vera",
        fontSize=8,
        textColor=colors.grey,
        leading=11,
    )

    out_pdf.parent.mkdir(parents=True, exist_ok=True)
    doc = SimpleDocTemplate(
        str(out_pdf),
        pagesize=A4,
        rightMargin=2 * cm,
        leftMargin=2 * cm,
        topMargin=2 * cm,
        bottomMargin=2 * cm,
    )
    story: list[Any] = []
    story.append(Paragraph("ASENA-ANALYSIS — Özet Rapor", title_style))
    story.append(
        Paragraph(
            f"Üretim zamanı: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}<br/>"
            f"Kaynak: {timeline_csv.name} (maskeli veri)",
            body_style,
        )
    )
    story.append(Spacer(1, 0.4 * cm))
    story.append(Paragraph("KVKK / GDPR", body_style))
    story.append(Paragraph(shield.legal_notice_external_channel_brief(), small_style))
    story.append(Spacer(1, 0.3 * cm))

    data = [
        ["Özet", "Adet"],
        ["Toplam timeline satırı", str(m["total_rows"])],
        ["Saldırı fazı (phase=attack)", str(m["attack_events"])],
        ["Kritik (tore_status=CRITICAL)", str(m["critical_events"])],
        ["Benzersiz olay (story_id)", str(m["unique_stories"])],
    ]
    t = Table(data, colWidths=[10 * cm, 4 * cm])
    t.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f4e79")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                ("FONTNAME", (0, 0), (-1, -1), "Vera"),
                ("FONTSIZE", (0, 0), (-1, -1), 10),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f0f0f0")]),
            ]
        )
    )
    story.append(t)
    story.append(Spacer(1, 0.6 * cm))
    story.append(Paragraph("LinkedIn için önerilen paylaşım metni (düzenleyebilirsiniz)", body_style))
    story.append(Spacer(1, 0.2 * cm))
    story.append(Paragraph(linkedin_suggested.replace("&", "&amp;"), body_style))
    story.append(Spacer(1, 0.3 * cm))
    story.append(Paragraph(linkedin_alt.replace("&", "&amp;"), small_style))
    story.append(Spacer(1, 0.5 * cm))
    story.append(Paragraph("Hukuki", small_style))
    story.append(Paragraph(footer.replace("&", "&amp;"), small_style))

    doc.build(story)


def _ai_anomaly_count_from_timeline(df: Any) -> int:
    """Isolation Forest: payload sütunundan anomali (skor -1) sayısı."""
    if df is None or len(df) < 3:
        return 0
    if "payload" not in df.columns:
        return 0
    try:
        from engine.ml_analyzer import isolation_forest_ai_scores

        payloads = df["payload"].fillna("").astype(str).tolist()
        return sum(1 for x in isolation_forest_ai_scores(payloads) if x == -1)
    except Exception:
        return 0


def export_executive_summary_md(
    timeline_csv: Path,
    out_md: Path,
) -> None:
    """
    LinkedIn / işveren paylaşımı için **Olay Özeti** (Executive Summary), Markdown.

    Metrikler: timeline (tespit / kritik), AI anomali sayısı, yerel ``asena_metrics.json`` (SMS/WA/Telegram).
    """
    from utils.metrics import load_metrics

    df = load_timeline_csv_for_report(timeline_csv)
    m = summarize_timeline_for_pdf(df)
    metrics = load_metrics()
    ai_n = _ai_anomaly_count_from_timeline(df)

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lines = [
        "# ASENA-ANALYSIS — Olay Özeti (Executive Summary)",
        "",
        f"**Tarih:** {now}",
        "",
        "## Operasyonel metrikler",
        "",
        "| Gösterge | Değer |",
        "|----------|------:|",
        f"| Timeline satırı (toplam) | {m['total_rows']} |",
        f"| Saldırı fazı (phase=attack) | {m['attack_events']} |",
        f"| Kritik korelasyon (tore_status=CRITICAL) | {m['critical_events']} |",
        f"| Benzersiz olay (story_id) | {m['unique_stories']} |",
        f"| AI anomali (Isolation Forest, skor -1) | {ai_n} |",
        "",
        "## Bildirim sayaçları (yerel, bu makinede)",
        "",
        "| Kanal | Gönderim |",
        "|-------|----------:|",
        f"| Twilio SMS (toplam) | {metrics.get('twilio_sms_total', 0)} |",
        f"| Twilio WhatsApp (toplam) | {metrics.get('twilio_whatsapp_total', 0)} |",
        f"| Telegram (KVKK özet uyarı) | {metrics.get('telegram_kvkk_alerts', 0)} |",
        f"| Telegram (HTTP özel bildirim) | {metrics.get('telegram_http_notifications', 0)} |",
        f"| Töre selamı (SMS) | {metrics.get('initial_salute_sms', 0)} |",
        f"| Töre selamı (WhatsApp) | {metrics.get('initial_salute_whatsapp', 0)} |",
        "",
        "## LinkedIn için kısa paragraf",
        "",
        f"ASENA-ANALYSIS ile bu oturumda **{m['attack_events']}** saldırı denemesi tespit edildi; "
        f"**{m['critical_events']}** kritik eşik kaydı oluştu; yapay zeka katmanı **{ai_n}** anomali işaretledi. "
        "Pasif analiz / lab ortamı; üretimde WAF ile birleştirin.",
        "",
        "---",
        "",
        "*KVKK: raporda ham PII yok; timeline maskeli.*",
        "",
    ]
    out_md.parent.mkdir(parents=True, exist_ok=True)
    out_md.write_text("\n".join(lines), encoding="utf-8")


def _linkedin_output_dir() -> Path:
    return Path(__file__).resolve().parent.parent.parent / "data"


def _df_resolve_column(df: Any, candidates: tuple[str, ...]) -> str | None:
    for c in candidates:
        if c in df.columns:
            return c
    return None


def generate_linkedin_summary(df: Any, *, out_path: Path | None = None) -> str:
    """
    LinkedIn / portföy için kısa **Operasyon Raporu** metni üretir ve ``data/linkedin_post.txt`` yazar.

    Sütun eşlemesi (ilk bulunan kullanılır):

    - Risk: ``Risk``, ``tore_status``, ``Risk_Seviyesi`` → CRITICAL sayımı
    - IP: ``IP (Maskeli)``, ``source_ip``, ``Maskelenmiş_IP``
    - AI: ``AI_Score`` veya ``ML_IF_Score``; yoksa ``payload`` üzerinden Isolation Forest (timeline ile uyumlu)

    Pasif IDS bağlamında “engelleme” yerine **tespit/kritik eşik** ifadesi kullanılır.
    """
    import pandas as pd

    out = out_path or (_linkedin_output_dir() / "linkedin_post.txt")

    if df is None or not isinstance(df, pd.DataFrame) or len(df) == 0:
        summary = (
            "🛡️ ASENA-ANALYSIS Operasyon Raporu\n"
            "--------------------------------\n"
            "🐺 Toplam İzlenen Olay: 0\n"
            "🚫 Kritik eşik (CRITICAL) kaydı: 0\n"
            "🔍 Analiz Edilen Tekil Kaynak: 0\n"
            "🤖 AI Anomali Tespit Oranı: %0.00\n\n"
            "#CyberSecurity #SOC #Bozkurt #Python #AI"
        )
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(summary, encoding="utf-8")
        return summary

    total = int(len(df))
    risk_col = _df_resolve_column(df, ("Risk", "tore_status", "Risk_Seviyesi"))
    if risk_col:
        critical = int((df[risk_col].astype(str).str.strip() == "CRITICAL").sum())
    else:
        critical = 0

    ip_col = _df_resolve_column(df, ("IP (Maskeli)", "source_ip", "Maskelenmiş_IP"))
    unique_targets = int(df[ip_col].nunique()) if ip_col else 0

    ai_col = _df_resolve_column(df, ("AI_Score", "ML_IF_Score"))
    if ai_col:
        ai_anomalies = int((df[ai_col] == -1).sum())
    else:
        ai_anomalies = _ai_anomaly_count_from_timeline(df)

    pct = (ai_anomalies / float(total)) * 100.0 if total > 0 else 0.0

    summary = (
        f"🛡️ ASENA-ANALYSIS Operasyon Raporu\n"
        f"--------------------------------\n"
        f"🐺 Toplam İzlenen Olay: {total}\n"
        f"🚫 Kritik eşik (CRITICAL) kayıtları: {critical}\n"
        f"🔍 Analiz Edilen Tekil Kaynak: {unique_targets}\n"
        f"🤖 AI Anomali Tespit Oranı: %{pct:.2f}\n\n"
        f"#CyberSecurity #SOC #Bozkurt #Python #AI"
    )
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(summary, encoding="utf-8")
    return summary


def start_periodic_linkedin_refresh(
    timeline_csv: Path,
    *,
    interval_sec: int = 300,
) -> tuple[Any, Any]:
    """
    Canlı izleme sırasında arka planda ``timeline_csv`` okuyup ``data/linkedin_post.txt`` dosyasını
    periyodik günceller (istatistikler maskeli timeline’dan; KVKK).

    Daemon thread; ana süreç (ör. ``watch``) Ctrl+C ile bitince sonlanır.

    - ``interval_sec``: minimum 60 saniye.
    - ``ASENA_LINKEDIN_REFRESH_SEC`` ortam değişkeni ile süre geçersiz kılınabilir (``asena.py``).
    """
    import threading

    interval_sec = max(60, int(interval_sec))
    stop = threading.Event()

    def _run() -> None:
        while not stop.is_set():
            try:
                df = load_timeline_csv_for_report(timeline_csv)
                generate_linkedin_summary(df)
            except Exception as e:
                print(f"[-] linkedin_post.txt güncellenemedi: {e}")
            if stop.wait(timeout=interval_sec):
                break

    t = threading.Thread(target=_run, name="asena-linkedin-refresh", daemon=True)
    t.start()
    return t, stop
