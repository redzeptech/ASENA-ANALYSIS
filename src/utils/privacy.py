# =============================================================================
# ASENA-ANALYSIS — Geriye dönük uyumluluk
# Gizlilik mantığı: engine.privacy_shield (tek kaynak)
# =============================================================================
"""Re-export: `from utils.privacy import …` kullanan kodlar için."""

from engine.privacy_shield import (
    AsenaPrivacyShield,
    PrivacyConfig,
    apply_privacy_to_story,
    mask_ip_with_shield,
    minimize_redact_request_text,
    redact_path,
    redact_query_string,
    resolve_salt,
)

__all__ = [
    "AsenaPrivacyShield",
    "PrivacyConfig",
    "apply_privacy_to_story",
    "mask_ip_with_shield",
    "minimize_redact_request_text",
    "redact_path",
    "redact_query_string",
    "resolve_salt",
]
