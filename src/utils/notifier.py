# =============================================================================
# ASENA-ANALYSIS — Twilio SMS / WhatsApp (KVKK uyumlu özet)
# =============================================================================
"""
Haberci: Twilio SMS / WhatsApp.

- **Kritik uyarılar:** yalnızca **saldırı tipi** + **risk skoru** (KVKK).
- **İlk selam:** ``send_initial_salute`` — kodda sabitlenmiş töre metni (PII yok);
  ``python asena.py watch`` / ``start`` girişinde otomatik; ayrıca ``python asena.py salute``.

Ortam değişkenleri (Twilio Console); kimlik için **iki isim** desteklenir:

- ``TWILIO_ACCOUNT_SID`` veya ``TWILIO_SID``
- ``TWILIO_AUTH_TOKEN`` veya ``TWILIO_TOKEN``
- ``TWILIO_FROM_SMS`` — gönderen SMS (E.164, örn. ``+15551234567``)
- ``TWILIO_FROM_WHATSAPP`` — gönderen WhatsApp (örn. ``whatsapp:+14155238886`` Sandbox)
- ``TWILIO_TO_NUMBER`` — alıcı (E.164, örn. ``+905551234567``)

İsteğe bağlı: ``TWILIO_SMS_ENABLED=1``, ``TWILIO_WHATSAPP_ENABLED=1`` (varsayılan: 1).

``pip install twilio`` gerekir.
"""

from __future__ import annotations

import os
from typing import Any, Literal, Optional

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
