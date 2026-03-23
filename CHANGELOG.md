# Changelog

ASENA-ANALYSIS için önemli değişiklikler bu dosyada listelenir.

Biçim [Keep a Changelog](https://keepachangelog.com/tr/1.0.0/) ilhamıyla tutulur; sürüm numaralandırması [Semantic Versioning](https://semver.org/lang/tr/) ile uyumludur.

---

## [1.0.0] — 2025-03-23 — *Bozkurt'un Doğuşu*

İlk stabil sürüm: proje çekirdek mimarisi tamamlandı.

### Privacy Shield

- Tüm PII verileri için maskeleme katmanı (KVKK / GDPR uyumlu çıktılar).

### Hybrid Engine

- Regex tabanlı kural motoru (SQLi imzaları, YAML av kuralları).
- **Isolation Forest** ML modülü ile anomali tespiti (URL/payload özellikleri).

### Notification

- WhatsApp / SMS bildirim desteği (**Twilio**); Telegram ile KVKK uyumlu özet mesajlar.

### Dashboard

- **Streamlit** ile anlık görselleştirme ve komuta merkezi paneli.
