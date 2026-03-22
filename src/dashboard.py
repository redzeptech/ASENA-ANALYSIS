# =============================================================================
# ASENA-ANALYSIS — Hukuki şerh: Yalnızca izinli lab / defansif analiz. LEGAL.md
# =============================================================================
"""
Komuta merkezi (Streamlit): ``data/timeline.csv`` canlı görünüm.

Çalıştırma (repo kökünden):
  streamlit run src/dashboard.py

Gerekli: ``pip install streamlit plotly`` (ve isteğe bağlı ``streamlit-autorefresh``).
"""

from __future__ import annotations

from datetime import timedelta
from io import StringIO
from pathlib import Path

import numpy as np
import pandas as pd

try:
    import plotly.express as px
except ImportError as e:
    raise SystemExit("plotly gerekli: pip install plotly") from e

try:
    import streamlit as st
except ImportError as e:
    raise SystemExit("streamlit gerekli: pip install streamlit") from e


def _project_root() -> Path:
    return Path(__file__).resolve().parent.parent


def timeline_csv_path() -> Path:
    return _project_root() / "data" / "timeline.csv"


def load_data() -> pd.DataFrame:
    """Hukuki üst bilgi ve ayırıcı satırları atlayarak timeline CSV okur."""
    path = timeline_csv_path()
    if not path.is_file():
        return pd.DataFrame()
    with path.open(encoding="utf-8") as f:
        lines = f.readlines()
    start = None
    for i, line in enumerate(lines):
        if line.strip().startswith("story_id,"):
            start = i
            break
    if start is None:
        return pd.DataFrame()
    buf = StringIO("".join(lines[start:]))
    return pd.read_csv(buf)


def _risk_series(df: pd.DataFrame) -> pd.Series:
    if "tore_status" not in df.columns:
        return pd.Series(dtype=str)
    s = df["tore_status"].fillna("").astype(str).str.strip()
    return s.replace("", "Belirtilmedi")


def attach_ai_anomaly_scores(df: pd.DataFrame) -> pd.DataFrame:
    """
    ``AI_Score``: 0 = normal, -1 = şüpheli.

    - **Kural tabanlı:** ``tore_status``, ``priority``, ``phase``, ``rules_matched``.
    - **Isolation Forest** (``ml_analyzer``): payload uzunluğu + özel karakter yoğunluğu.

    İkisi birleştirilir (mantıksal VEYA).
    """
    out = df.copy()
    heur: list[int] = []
    for _, row in out.iterrows():
        ts = str(row.get("tore_status", "") or "").strip()
        try:
            pr = float(row.get("priority", 0) or 0)
        except (TypeError, ValueError):
            pr = 0.0
        phase = str(row.get("phase", "") or "").lower()
        rules = str(row.get("rules_matched", "") or "").lower()
        payload = str(row.get("payload", "") or "")

        anomaly = False
        if ts in ("CRITICAL", "High"):
            anomaly = True
        elif pr >= 100:
            anomaly = True
        elif pr >= 70 and phase == "attack":
            anomaly = True
        elif phase == "attack" and any(
            k in rules or k in payload.lower()
            for k in ("sqli", "union", "sleep", "benchmark", "drop")
        ):
            anomaly = True

        heur.append(-1 if anomaly else 0)

    payloads = out["payload"].fillna("").astype(str).tolist() if "payload" in out.columns else [""] * len(out)
    try:
        from engine.ml_analyzer import isolation_forest_ai_scores

        ml_if = isolation_forest_ai_scores(payloads)
    except Exception:
        ml_if = [0] * len(out)

    h = np.array(heur, dtype=int)
    m = np.array(ml_if, dtype=int)
    out["ML_IF_Score"] = m
    out["AI_Score"] = np.where((h == -1) | (m == -1), -1, 0)
    return out


def render_panel() -> None:
    df = load_data()

    if df.empty:
        st.warning("Henüz bir iz (timeline) bulunamadı. `asena.py analyze` veya `watch` çalıştırın.")
        return

    risk = _risk_series(df)
    df = df.copy()
    df["_risk"] = risk
    df = attach_ai_anomaly_scores(df)

    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Toplam satır", len(df))
    crit = int((df["_risk"] == "CRITICAL").sum()) if "_risk" in df.columns else 0
    m2.metric("Kritik (Töre)", crit)
    ip_col = "source_ip" if "source_ip" in df.columns else None
    m3.metric("Maskelenmiş IP (benzersiz)", df[ip_col].nunique() if ip_col else 0)
    ai_bad = int((df["AI_Score"] == -1).sum()) if "AI_Score" in df.columns else 0
    m4.metric("AI anomali (skor -1)", ai_bad)

    st.markdown("---")
    st.subheader("AI Anomali Skoru — 🤖 Yapay zeka (AI) sezgileri")
    anomalies = df[df["AI_Score"] == -1]
    if not anomalies.empty:
        st.error(f"Dikkat! AI tarafından {len(anomalies)} adet şüpheli anomali tespit edildi.")
        disp_cols = [c for c in ("timestamp", "source_ip", "payload") if c in anomalies.columns]
        if disp_cols:
            view = anomalies[disp_cols].copy()
            view = view.rename(
                columns={
                    "timestamp": "Zaman",
                    "source_ip": "IP (Maskeli)",
                    "payload": "Payload",
                }
            )
            st.dataframe(view, use_container_width=True)
        else:
            st.dataframe(anomalies, use_container_width=True)
    else:
        st.success("AI analizi: Trafik şu an normal görünüyor.")

    c1, c2 = st.columns(2)

    with c1:
        st.subheader("Risk dağılımı (tore_status)")
        pie_df = df["_risk"].value_counts().reset_index()
        pie_df.columns = ["risk", "count"]
        color_map = {
            "CRITICAL": "#c0392b",
            "High": "#e67e22",
            "Medium": "#f1c40f",
            "Low": "#27ae60",
            "Belirtilmedi": "#95a5a6",
        }
        fig_risk = px.pie(
            pie_df,
            values="count",
            names="risk",
            color="risk",
            color_discrete_map=color_map,
        )
        st.plotly_chart(fig_risk, use_container_width=True)

    with c2:
        st.subheader("Zaman serisi (timestamp)")
        if "timestamp" in df.columns:
            ts = (
                df.groupby("timestamp", as_index=False)
                .size()
                .rename(columns={"size": "adet"})
            )
            fig_ts = px.line(ts, x="timestamp", y="adet", markers=True)
            st.plotly_chart(fig_ts, use_container_width=True)
        else:
            st.info("timestamp sütunu yok.")

    st.subheader("Son tespitler (timeline)")
    show_cols = [
        c
        for c in (
            "timestamp",
            "phase",
            "source_ip",
            "http_status",
            "tore_status",
            "priority",
            "path",
            "rules_matched",
        )
        if c in df.columns
    ]
    st.dataframe(df[show_cols].tail(20), use_container_width=True)


def main() -> None:
    st.set_page_config(page_title="ASENA-ANALYSIS | Komuta Merkezi", layout="wide")

    st.title("ASENA-ANALYSIS: Siber iz sürme paneli")
    st.markdown("---")

    st.sidebar.header("Hukuki statü")
    st.sidebar.info(
        "KVKK/GDPR uyumlu: Aktif\n\n"
        "Maskeleme: Aktif (timeline)\n\n"
        "Ortam: Yerel laboratuvar / yetkili analiz"
    )
    st.sidebar.caption(f"Veri: `{timeline_csv_path()}`")
    st.sidebar.caption(
        "AI_Score: kural + Isolation Forest (uzunluk/özel karakter). ML_IF_Score: sadece IF."
    )

    use_autorefresh = False
    try:
        from streamlit_autorefresh import st_autorefresh

        st_autorefresh(interval=2000, key="asena_dashboard_refresh")
        use_autorefresh = True
    except ImportError:
        pass

    if not use_autorefresh:
        try:
            frag = getattr(st, "fragment", None)
            if callable(frag):

                @frag(run_every=timedelta(seconds=2))
                def _live() -> None:
                    render_panel()

                _live()
                return
        except Exception:
            pass

    render_panel()
    if not use_autorefresh:
        st.caption("Canlı yenileme: `pip install streamlit-autorefresh` veya Streamlit ≥1.33 (`fragment`).")
        if st.button("Yenile"):
            st.rerun()


if __name__ == "__main__":
    main()
