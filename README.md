# ASENA-ANALYSIS: Hibrit saldırı tespit ve analiz sistemi

**ASENA-ANALYSIS**, Apache **combined access log** dosyalarını gerçek zamanlı veya toplu olarak işleyen, **kural tabanlı (deterministik)** ve **yapay zeka destekli (Isolation Forest)** bileşenleri bir arada kullanan uçtan uca bir **siber güvenlik analiz** projesidir. Özellikle **SQL Injection (SQLi)** imzalarını (ör. `UNION`, `SELECT`, `SLEEP`) yakalar; olayları **timeline** formatında kayıt altına alır ve **KVKK / GDPR** uyumlu maskeleme ile raporlar.

> Bu yazılım **yetkisiz sistemlere karşı saldırı veya erişim** için değildir. Yalnızca **eğitim**, **izinli laboratuvar** (ör. DVWA) veya **yetkili** test ortamlarında kullanılmalıdır. Hukuki çerçeve: [LEGAL.md](LEGAL.md) (TCK 243–244 bilgi notu; hukuki tavsiye değildir).

---

## Mimari yapı

```
ASENA-ANALYSIS/
├── docker/                 # DVWA laboratuvar ortamı (Docker Compose)
├── src/
│   ├── engine/             # Çekirdek motor
│   │   ├── parser.py       # Log ayrıştırma, YAML + SQLi süzgeci, canlı izleme
│   │   ├── correlator.py   # Korelasyon, hibrit kural + AI kararı, timeline satırları
│   │   ├── ml_analyzer.py  # Isolation Forest ile anomali skorları (URL/payload özellikleri)
│   │   ├── privacy_shield.py
│   │   └── tore_evaluator.py
│   ├── utils/              # Bildirim, dışa aktarım, metrikler
│   │   ├── notifier.py     # Twilio (SMS/WhatsApp), KVKK uyumlu özet mesajlar
│   │   ├── exporter.py     # timeline.csv, PDF rapor, LinkedIn özeti
│   │   ├── metrics.py
│   │   └── privacy.py      # AsenaPrivacyShield re-export
│   ├── rules/              # hunting_rules.yaml, sqli_rules.yaml (Töre)
│   └── dashboard.py        # Streamlit komuta merkezi (canlı grafikler)
├── data/                   # timeline.csv, raporlar, linkedin_post.txt (üretilen çıktılar)
├── logs/                   # Örnek erişim logu (isteğe bağlı)
└── asena.py                # CLI giriş noktası (analyze / watch / start / report / …)
```

---

## Projenin amacı

Geleneksel **imza / kural tabanlı** tespitin ötesine geçerek, **makine öğrenmesi (ML)** ile **anomali tespiti** (Isolation Forest) eklenir; böylece **hibrit** bir savunma hattı oluşturulur. Tüm dışa aktarımlar **PII maskeleme** ve **veri minimizasyonu** ilkeleriyle sınırlandırılır. Referans senaryo: **DVWA (Damn Vulnerable Web Application)** üzerinde eğitim amaçlı çalıştırma.

---

## Temel özellikler

### Privacy Shield (gizlilik katmanı)

- **AsenaPrivacyShield**: IPv4 için alt ağ düzeyinde maskeleme (ör. `a.b.0.0`), isteğe bağlı hash modu.
- Timeline ve bildirimlerde **ham IP** ve **hassas içerik** üçüncü taraf kanallarına **KVKK uyumlu özet** dışında taşınmaz.

### Hibrit tespit motoru

| Katman | Açıklama |
|--------|----------|
| **Töre (kurallar)** | YAML ve regex tabanlı kurallar; SQLi süzgeci (`UNION`, `SELECT`, `SLEEP`, …). |
| **Sezgi (AI)** | **Isolation Forest**: URL/payload uzunluğu ve özel karakter yoğunluğu üzerinden anomali skoru (dashboard ve özet raporlarla uyumlu). |

### Gerçek zamanlı timeline

- **`data/timeline.csv`**: Saldırı anı, risk önceliği, maskelenmiş kaynak, korelasyon durumu (`tore_status`).
- Canlı mod: `watch` / `start` ile log dosyası **tail -f** benzeri izlenir.

### Komuta merkezi (dashboard)

- **Streamlit** tabanlı panel: `streamlit run src/dashboard.py` veya `python asena.py serve` / `start`.

### Anlık bildirimler

- **Telegram** ve isteğe bağlı **Twilio** (SMS / WhatsApp): kritik özetler **saldırı tipi + risk skoru** ile iletilir; operasyonel açılışta **“Bozkurt” selamı** (sabit şablon) yapılandırılabilir.
- Ayrıntılar: `src/utils/notifier.py`, ortam değişkenleri (Twilio SID/Token vb.).

---

## Hızlı başlangıç

```powershell
pip install -r requirements.txt
```

**Analiz (tek sefer):**

```powershell
python asena.py analyze --log logs/access.log --out data/timeline.csv --i-accept
```

**Canlı izleme + periyodik LinkedIn özeti + (yapılandırılmışsa) töre selamı:**

```powershell
python asena.py watch --log docker/logs/apache2/access.log --i-accept
```

**Dashboard + canlı izleme:**

```powershell
python asena.py start --i-accept
```

İlk çalıştırmada **yasal onay** istenir; otomasyon için `--i-accept` veya `ASENA_I_ACCEPT=1` kullanın.

**Yerellik:** Varsayılan olarak yalnızca **localhost** istemci IP’leri işlenir; istisna: `--allow-remote-ips` (yalnızca güvenilir ortam).

---

## DVWA (Docker lab)

```powershell
docker compose -f docker/docker-compose.yml up -d
```

- Arayüz örneği: `http://127.0.0.1:8081` (yapılandırmaya bağlı).
- Apache logları genelde volume ile `docker/logs/apache2/` altına eşlenir; canlı izleme için `--log docker/logs/apache2/access.log` kullanın.

---

## Hukuki uyum ve etik bildirimi

- Proje, **TCK 243–244** ve **KVKK** ilkeleri gözetilerek tasarlanmıştır; ayrıntı [LEGAL.md](LEGAL.md).
- Varsayılan kullanım **yerel / lab** odaklıdır; üretim ağlarında kullanım kurum politikalarına tabidir.
- **Eğitim ve defansif güvenlik araştırmaları** dışında kullanım önerilmez.

---

## Ek komutlar (özet)

| Komut | Görev |
|-------|--------|
| `analyze` | Log → `timeline.csv` (+ isteğe bağlı JSON) |
| `watch` | Canlı log izleme |
| `start` | Streamlit + `watch` |
| `serve` | Yalnızca Streamlit |
| `report` | `asena_report.pdf` |
| `summary` | Executive summary (Markdown) |
| `salute` | Twilio töre selamı (test) |

---

*ASENA-ANALYSIS — Bozkurt çevikliğiyle iz sürmek; savunmada kalmak.*
