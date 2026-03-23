# =============================================================================
# ASENA-ANALYSIS — Twilio SMS / WhatsApp + Telegram Bot (KVKK uyumlu özet)
# =============================================================================
"""
Haberci: Twilio SMS / WhatsApp ve **Telegram Bot** (``python-telegram-bot``).

- **Kritik uyarılar:** yalnızca **saldırı tipi** + **risk skoru** (KVKK).
- **Telegram:** risk skoru **90'dan büyük** (``> 90``) olduğunda gruba anlık mesaj;
  ham IP / URL / payload **gönderilmez**.
- **İlk selam:** ``send_initial_salute`` — kodda sabitlenmiş töre metni (PII yok);
  ``python asena.py watch`` / ``start`` girişinde otomatik; ayrıca ``python asena.py salute``.

**Twilio** — ortam değişkenleri (Console); kimlik için **iki isim** desteklenir:

- ``TWILIO_ACCOUNT_SID`` veya ``TWILIO_SID``
- ``TWILIO_AUTH_TOKEN`` veya ``TWILIO_TOKEN``
- ``TWILIO_FROM_SMS`` — gönderen SMS (E.164, örn. ``+15551234567``)
- ``TWILIO_FROM_WHATSAPP`` — gönderen WhatsApp (örn. ``whatsapp:+14155238886`` Sandbox)
- ``TWILIO_TO_NUMBER`` — alıcı (E.164, örn. ``+905551234567``)

İsteğe bağlı: ``TWILIO_SMS_ENABLED=1``, ``TWILIO_WHATSAPP_ENABLED=1`` (varsayılan: 1).

**Telegram** — `@BotFather` token + hedef sohbet/grup ID:

- ``ASENA_TELEGRAM_BOT_TOKEN`` veya ``TELEGRAM_BOT_TOKEN``
- ``ASENA_TELEGRAM_CHAT_ID`` veya ``TELEGRAM_CHAT_ID`` (grup için genelde negatif ``-100...``)

``pip install twilio python-telegram-bot`` gerekir (``requests`` zaten bağımlılıktadır).

İsteğe bağlı **HTTP** yolu: ``AsenaTelegramBot.send_tg_notification(alert_text)`` —
``sendMessage`` ile ``json`` gövdesi; token sohbet dışında tutulur, metin HTML kaçışlıdır.
"""

from __future__ import annotations

import asyncio
import html
import os
from typing import Any, Literal, Optional

import requests

from utils.metrics import bump as _bump_metric
from utils.privacy import AsenaPrivacyShield


def _kvkk_label(raw: str) -> str:
    s = " ".join((raw or "").split())[:120]
    return s if s else "Tanımsız"


def _risk_int(score: Any) -> int:
    try:
        v = int(score)
    except (TypeError, ValueError):
        return 0
    return max(0, min(v, 999))


def _truthy_env(name: str, default: bool = True) -> bool:
    v = os.environ.get(name, "").strip().lower()
    if not v:
        return default
    return v in ("1", "true", "yes", "on", "evet")


# Kritik Telegram bildirimi: yalnızca risk > 90 (korelasyon hibrit eşiği 90 ile uyumlu ayrım)
_TELEGRAM_EXCLUSIVE_MIN_RISK = 90


def _risk_exceeds_telegram_critical(score: Any) -> bool:
    return _risk_int(score) > _TELEGRAM_EXCLUSIVE_MIN_RISK


def _ptb_send_message_sync(token: str, chat_id: str, text: str) -> str:
    """python-telegram-bot ile tek mesaj (senkron bağlamdan ``asyncio.run``)."""
    try:
        from telegram import Bot
    except ImportError as e:
        raise ImportError("Telegram için: pip install python-telegram-bot") from e

    async def _run() -> str:
        bot = Bot(token=token)
        msg = await bot.send_message(chat_id=chat_id, text=text)
        return str(msg.message_id)

    return asyncio.run(_run())


class AsenaTelegramBot:
    """
    Telegram Bot API — ``python-telegram-bot``.

    Yalnızca **risk > 90** iken mesaj gönderir; içerik KVKK özetidir (tip + skor + kısa hukuk notu).
    """

    def __init__(
        self,
        shield: AsenaPrivacyShield | None = None,
        *,
        telegram_token: str | None = None,
        chat_id: str | None = None,
    ) -> None:
        self._shield = shield or AsenaPrivacyShield()
        self.token = (
            (telegram_token or "").strip()
            or os.environ.get("ASENA_TELEGRAM_BOT_TOKEN", "").strip()
            or os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
        )
        self.chat_id = (
            (chat_id or "").strip()
            or os.environ.get("ASENA_TELEGRAM_CHAT_ID", "").strip()
            or os.environ.get("TELEGRAM_CHAT_ID", "").strip()
        )

    @property
    def configured(self) -> bool:
        return bool(self.token and self.chat_id)

    def send_tg_notification(self, alert_text: str) -> Optional[bool]:
        """
        Telegram Bot API — ``requests`` ile doğrudan ``sendMessage``.

        Token ve sohbet ID **koda yazılmaz**; ``TELEGRAM_BOT_TOKEN`` /
        ``ASENA_TELEGRAM_BOT_TOKEN`` ve ``TELEGRAM_CHAT_ID`` / ``ASENA_TELEGRAM_CHAT_ID``
        ortam değişkenlerinden okunur.

        ``alert_text`` HTML olarak kaçışlanır (PII bilinçli kullanım; yine de ham log göndermeyin).
        Vurgu: düz metin başlık + ``parse_mode=HTML`` (Markdown yerine güvenli).
        """
        if not self.configured:
            return None
        raw = (alert_text or "").strip()
        if not raw:
            return None
        safe = html.escape(raw[:3800])
        text = f"🐺 <b>ASENA-ALARM</b> 🚨\n\n{safe}"
        url = f"https://api.telegram.org/bot{self.token}/sendMessage"
        try:
            r = requests.post(
                url,
                json={"chat_id": self.chat_id, "text": text, "parse_mode": "HTML"},
                timeout=15,
            )
            if r.status_code == 200:
                _bump_metric("telegram_http_notifications")
                self._shield.audit("Telegram HTTP: send_tg_notification gönderildi.")
                return True
            print(f"[-] Telegram HTTP yanıtı: {r.status_code} {r.text[:200]}")
            return False
        except Exception as e:
            print(f"[-] Telegram HTTP gönderilemedi: {e}")
            return False

    def send_kvkk_critical_alert(self, *, attack_type: str, risk_score: int) -> Optional[str]:
        """
        Risk **90'dan büyükse** gruba KVKK uyumlu kritik özet gönderir.
        ``<= 90`` ise sessizce ``None`` döner (Twilio yolu ayrıca devreye girebilir).
        """
        if not _risk_exceeds_telegram_critical(risk_score):
            return None
        if not self.configured:
            return None
        label = _kvkk_label(attack_type)
        score = _risk_int(risk_score)
        notice = self._shield.legal_notice_external_channel_brief()
        text = (
            "🐺 KRİTİK ALARM — ASENA (KVKK özet)\n"
            f"Saldırı tipi: {label}\n"
            f"Risk skoru: {score}\n"
            f"{notice}\n"
            "Detay: Dashboard (PII yok)."
        )
        try:
            mid = _ptb_send_message_sync(self.token, self.chat_id, text)
            _bump_metric("telegram_kvkk_alerts")
            self._shield.audit("Telegram Bot: KVKK-safe kritik özet gönderildi (risk>90).")
            return mid
        except Exception as e:
            print(f"[-] Telegram Bot mesajı gönderilemedi: {e}")
            return None


class AsenaNotifier:
    """
    Korelasyon kritik uyarıları: **Telegram** (``AsenaTelegramBot``, risk > 90).

    Twilio SMS/WhatsApp, ``AsenaCorrelator`` içinde ``CRITICAL`` / hibrit dalında
    ``AsenaMessenger`` ile ayrı tetiklenir.

    Ortam: ``ASENA_TELEGRAM_BOT_TOKEN`` / ``TELEGRAM_BOT_TOKEN``,
    ``ASENA_TELEGRAM_CHAT_ID`` / ``TELEGRAM_CHAT_ID``.
    """

    def __init__(
        self,
        telegram_token: str | None = None,
        chat_id: str | None = None,
        shield: AsenaPrivacyShield | None = None,
    ) -> None:
        self._bot = AsenaTelegramBot(shield=shield, telegram_token=telegram_token, chat_id=chat_id)

    @property
    def telegram_configured(self) -> bool:
        return self._bot.configured

    def send_kvkk_safe_alert(self, *, attack_type: str, risk_score: int) -> None:
        """Telegram — yalnızca risk > 90 (``AsenaTelegramBot``)."""
        self._bot.send_kvkk_critical_alert(attack_type=attack_type, risk_score=risk_score)

    def send_tg_notification(self, alert_text: str) -> Optional[bool]:
        """``AsenaTelegramBot.send_tg_notification`` — HTTP ``requests`` ile özel metin."""
        return self._bot.send_tg_notification(alert_text)

    def linkedin_alert(self, *, attack_type: str, risk_score: int) -> None:
        """LinkedIn API yok — yalnızca yerel log; içerik KVKK ile uyumlu özet alanları."""
        label = _kvkk_label(attack_type)
        score = _risk_int(risk_score)
        print(f"[LOG] LinkedIn özeti (yerel): tip={label!r} risk={score}")


class AsenaMessenger:
    """
    Twilio SMS / WhatsApp. Kimlik bilgileri ortam değişkenlerinden; koda gömülmez.

    ``AsenaPrivacyShield.legal_notice_external_channel_brief`` ile uyumlu kısa KVKK notu.
    Dışarıya **asla** ham IP, URL, kullanıcı adı veya parola gönderilmez.
    """

    def __init__(self, shield: AsenaPrivacyShield | None = None) -> None:
        self._shield = shield or AsenaPrivacyShield()
        self.account_sid = (
            os.environ.get("TWILIO_ACCOUNT_SID", "").strip() or os.environ.get("TWILIO_SID", "").strip()
        )
        self.auth_token = (
            os.environ.get("TWILIO_AUTH_TOKEN", "").strip() or os.environ.get("TWILIO_TOKEN", "").strip()
        )
        self.from_sms = os.environ.get("TWILIO_FROM_SMS", "").strip()
        self.from_whatsapp = os.environ.get("TWILIO_FROM_WHATSAPP", "whatsapp:+14155238886").strip()
        self.to_number = os.environ.get("TWILIO_TO_NUMBER", "").strip()
        self._client: Any = None

    def _get_client(self) -> Any:
        if not self.account_sid or not self.auth_token:
            return None
        if self._client is None:
            try:
                from twilio.rest import Client
            except ImportError as e:
                raise ImportError("Twilio için: pip install twilio") from e
            self._client = Client(self.account_sid, self.auth_token)
        return self._client

    @property
    def sms_configured(self) -> bool:
        return bool(self.account_sid and self.auth_token and self.from_sms and self.to_number)

    @property
    def whatsapp_configured(self) -> bool:
        return bool(self.account_sid and self.auth_token and self.from_whatsapp and self.to_number)

    def _kvkk_body(self, *, attack_type: str, risk_score: int) -> str:
        label = _kvkk_label(attack_type)
        score = _risk_int(risk_score)
        notice = self._shield.legal_notice_external_channel_brief()
        return (
            "ASENA KRİTİK\n"
            f"Saldırı tipi: {label}\n"
            f"Risk skoru: {score}\n"
            f"{notice}"
        )

    def _send_fixed_template_sms(self, body: str) -> Optional[str]:
        """Yalnızca kod içi sabit şablon (selam vb.); kullanıcı verisi taşımaz."""
        if not _truthy_env("TWILIO_SMS_ENABLED", True) or not self.sms_configured:
            return None
        client = self._get_client()
        if client is None:
            return None
        try:
            msg = client.messages.create(body=body, from_=self.from_sms, to=self.to_number)
            _bump_metric("twilio_sms_total")
            return str(msg.sid)
        except Exception as e:
            print(f"[-] Twilio SMS gönderilemedi: {e}")
            return None

    def _send_fixed_template_whatsapp(self, body: str) -> Optional[str]:
        """Yalnızca kod içi sabit şablon (selam vb.); kullanıcı verisi taşımaz."""
        if not _truthy_env("TWILIO_WHATSAPP_ENABLED", True) or not self.whatsapp_configured:
            return None
        client = self._get_client()
        if client is None:
            return None
        to_wa = self.to_number if self.to_number.startswith("whatsapp:") else f"whatsapp:{self.to_number}"
        try:
            msg = client.messages.create(from_=self.from_whatsapp, body=body, to=to_wa)
            _bump_metric("twilio_whatsapp_total")
            return str(msg.sid)
        except Exception as e:
            print(f"[-] Twilio WhatsApp gönderilemedi: {e}")
            return None

    def send_kvkk_safe_sms(self, *, attack_type: str, risk_score: int) -> Optional[str]:
        """Kritik özet SMS — yalnızca tip + skor + KVKK satırı."""
        body = self._kvkk_body(attack_type=attack_type, risk_score=risk_score)
        sid = self._send_fixed_template_sms(f"🐺 KRİTİK ALARM (ASENA)\n{body}")
        if sid:
            self._shield.audit("Twilio SMS: KVKK-safe kritik özet gönderildi.")
        return sid

    def send_kvkk_safe_whatsapp(self, *, attack_type: str, risk_score: int) -> Optional[str]:
        """WhatsApp Sandbox veya üretim — yalnızca özet metin."""
        body = self._kvkk_body(attack_type=attack_type, risk_score=risk_score)
        full = f"🚨 *KRİTİK ALARM — ASENA*\n\n{body}\n\n_Detay: Dashboard (PII yok)._"
        sid = self._send_fixed_template_whatsapp(full)
        if sid:
            self._shield.audit("Twilio WhatsApp: KVKK-safe kritik özet gönderildi.")
        return sid

    def send_initial_salute(
        self,
        *,
        channel: Literal["whatsapp", "sms", "both"] = "whatsapp",
    ) -> dict[str, Optional[str]]:
        """
        Sistem ilk açıldığında / operasyonel kanıt için gönderilecek **sabit** töre selamı.

        İçerik kodda tanımlıdır (PII yok). WhatsApp veya SMS veya ikisi.
        Dönüş: ``{"whatsapp": sid|None, "sms": sid|None}``.
        """
        message_body = (
            "🐺 *ASENA-ANALYSIS SİSTEMİ AKTİF*\n\n"
            "Bozkurt'tan selamlar! 🇹🇷\n"
            "Dijital pusulara karşı nöbet başladı.\n"
            "--------------------------\n"
            "📍 Durum: Laboratuvar Yayında\n"
            "🛡️ Koruma: KVKK/GDPR Maskeleme Aktif"
        )
        out: dict[str, Optional[str]] = {"whatsapp": None, "sms": None}
        if channel in ("whatsapp", "both"):
            out["whatsapp"] = self._send_fixed_template_whatsapp(message_body)
            if out["whatsapp"]:
                _bump_metric("initial_salute_whatsapp")
        if channel in ("sms", "both"):
            # SMS düz metin; * vurgusu bazı terminallerde görünmez
            out["sms"] = self._send_fixed_template_sms(message_body)
            if out["sms"]:
                _bump_metric("initial_salute_sms")
        if out["whatsapp"] or out["sms"]:
            self._shield.audit("Twilio: ASENA töre selamı (ilk operasyonel mesaj) gönderildi.")
        return out

    def send_sms(self, *, attack_type: str, risk_score: int) -> Optional[str]:
        """Korelasyon ``CRITICAL`` — KVKK: serbest metin / IP göndermez; ``send_kvkk_safe_sms`` ile aynı."""
        return self.send_kvkk_safe_sms(attack_type=attack_type, risk_score=risk_score)

    def send_whatsapp(self, *, attack_type: str, risk_score: int) -> Optional[str]:
        """Korelasyon ``CRITICAL`` — KVKK: serbest metin / IP göndermez; ``send_kvkk_safe_whatsapp`` ile aynı."""
        return self.send_kvkk_safe_whatsapp(attack_type=attack_type, risk_score=risk_score)
