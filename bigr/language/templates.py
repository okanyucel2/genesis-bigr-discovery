"""Rule-based notification templates for the BİGR Product Language Engine.

These templates provide human-friendly Turkish notifications for each
alert type and severity combination. They are used as a fast, zero-cost
fallback when the AI router is unavailable or when alerts are simple
enough that AI generation is unnecessary.

Placeholders:
    {ip}          - Device IP address
    {device_name} - Friendly device name (or IP fallback)
    {port}        - Port number (from details dict)
"""

from __future__ import annotations

# type -> severity -> template fields
TEMPLATES: dict[str, dict[str, dict]] = {
    "new_device": {
        "info": {
            "title": "Yeni Misafir",
            "body": "Agina yeni bir cihaz katildi ({ip}). Taniyor musun?",
            "icon": "\U0001f44b",
            "action_label": "Incele",
            "action_type": "investigate",
        },
        "warning": {
            "title": "Tanimadigi Bir Cihaz",
            "body": "Aginda tanimadigi bir cihaz belirdi ({ip}). Kontrol etmeni oneririm.",
            "icon": "\u26a0\ufe0f",
            "action_label": "Kim Bu?",
            "action_type": "investigate",
        },
    },
    "port_change": {
        "info": {
            "title": "Port Degisikligi",
            "body": "{device_name} cihazinda bir port degisikligi fark ettim. Her sey kontrol altinda.",
            "icon": "\U0001f527",
        },
        "warning": {
            "title": "Riskli Port Acik",
            "body": "{device_name} cihazinda riskli bir kapi acik kalmis. Kapatmami ister misin?",
            "icon": "\U0001f6aa",
            "action_label": "Onar",
            "action_type": "fix_it",
        },
        "critical": {
            "title": "Tehlikeli Port!",
            "body": "{device_name} cihazinda cok tehlikeli bir port acik! Hemen mudahale ediyorum.",
            "icon": "\U0001f6a8",
            "action_label": "Hemen Kapat",
            "action_type": "fix_it",
        },
    },
    "rogue_device": {
        "warning": {
            "title": "Supheli Cihaz",
            "body": "Aginda supheli bir cihaz tespit ettim ({ip}). Bu cihaz bilinen listende yok.",
            "icon": "\U0001f575\ufe0f",
            "action_label": "Engelle",
            "action_type": "fix_it",
        },
        "critical": {
            "title": "Izinsiz Giris!",
            "body": "Agina izinsiz bir cihaz baglandi! ({ip}) Hemen engelliyorum.",
            "icon": "\U0001f6ab",
            "action_label": "Engelle",
            "action_type": "fix_it",
        },
    },
    "device_missing": {
        "info": {
            "title": "Cihaz Ayrildi",
            "body": "Bir cihaz agindan ayrildi ({ip}). Endiselenecek bir sey yok.",
            "icon": "\U0001f44b",
        },
        "warning": {
            "title": "Cihaz Kayip",
            "body": "Daha once gordugum bir cihaz artik aginda yok ({ip}). Kontrol etmeni oneririm.",
            "icon": "\u2753",
            "action_label": "Incele",
            "action_type": "investigate",
        },
    },
    "mass_change": {
        "warning": {
            "title": "Cok Sayida Degisiklik",
            "body": "Aginda cok sayida degisiklik tespit ettim. Goz atmanizi oneririm.",
            "icon": "\U0001f30a",
            "action_label": "Incele",
            "action_type": "investigate",
        },
        "critical": {
            "title": "Buyuk Degisiklik!",
            "body": "Aginda cok sayida degisiklik tespit ettim. Bir seyler olagandisi gorunuyor.",
            "icon": "\U0001f30a",
            "action_label": "Incele",
            "action_type": "investigate",
        },
    },
    "category_change": {
        "info": {
            "title": "Cihaz Guncellendi",
            "body": "{device_name} cihazinin turu degisti. Guncel bilgilerle takip ediyorum.",
            "icon": "\U0001f504",
        },
        "warning": {
            "title": "Cihaz Turu Degisti",
            "body": "{device_name} cihazi farkli davranmaya basladi. Kontrol etmeni oneririm.",
            "icon": "\u26a0\ufe0f",
            "action_label": "Incele",
            "action_type": "investigate",
        },
    },
    # Generic threat notification (not tied to a specific AlertType)
    "threat_detected": {
        "warning": {
            "title": "Tehdit Algilandi",
            "body": "Internetten gelen bir tehdit tespit ettim. Seni koruma altina aliyorum.",
            "icon": "\U0001f6e1\ufe0f",
        },
        "critical": {
            "title": "Ciddi Tehdit!",
            "body": "Ciddi bir siber tehdit tespit ettim! Koruma kalkanini guclendiriyorum.",
            "icon": "\U0001f534",
            "action_label": "Detaylar",
            "action_type": "investigate",
        },
    },
}

# Fallback template when no specific template exists for the alert type / severity
FALLBACK_TEMPLATE: dict[str, dict] = {
    "info": {
        "title": "Bilgi",
        "body": "Aginda kucuk bir degisiklik fark ettim. Her sey kontrol altinda.",
        "icon": "\u2139\ufe0f",
    },
    "warning": {
        "title": "Dikkat",
        "body": "Aginda dikkat edilmesi gereken bir durum var. Goz atmanizi oneririm.",
        "icon": "\u26a0\ufe0f",
        "action_label": "Incele",
        "action_type": "investigate",
    },
    "critical": {
        "title": "Acil Durum",
        "body": "Aginda acil mudahale gerektiren bir durum tespit ettim!",
        "icon": "\U0001f6a8",
        "action_label": "Mudahale Et",
        "action_type": "fix_it",
    },
}
