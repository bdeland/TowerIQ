"""
Settings Cards Stylesheets

This module contains the stylesheet definitions for the settings cards.
"""

# Settings card stylesheets
SETTINGS_CARD_LIGHT_QSS = """
SettingsCard {
    background-color: #ffffff;
    border: 1px solid #e0e0e0;
    border-radius: 8px;
    padding: 0px;
}

SettingsCard:hover {
    background-color: #f5f5f5;
    border: 1px solid #d0d0d0;
}
"""

SETTINGS_CARD_DARK_QSS = """
SettingsCard {
    background-color: #1f1f1f;
    border: 1px solid #404040;
    border-radius: 8px;
    padding: 0px;
}

SettingsCard:hover {
    background-color: #2d2d2d;
    border: 1px solid #505050;
}
"""

# Settings item card stylesheets (for individual settings with controls)
SETTINGS_ITEM_CARD_LIGHT_QSS = """
SettingsItemCard {
    background-color: #ffffff;
    border: 1px solid #e0e0e0;
    border-radius: 8px;
}

SettingsItemCard:hover {
    background-color: #f5f5f5;
}
SettingsItemCard BodyLabel {
    background-color: transparent;
    font-size: 14px;
    font-weight: 500;
}

SettingsItemCard CaptionLabel {
    background-color: transparent;
    font-size: 12px;
}
"""

SETTINGS_ITEM_CARD_DARK_QSS = """
SettingsItemCard {
    background-color: #2d2d2d;
    border: 1px solid #404040;
    border-radius: 8px;
}

SettingsItemCard:hover {
    background-color: #3a3a3a;
}

SettingsItemCard BodyLabel {
    background-color: transparent;
    font-size: 14px;
    font-weight: 500;
}

SettingsItemCard CaptionLabel {
    background-color: transparent;
    font-size: 12px;
}
"""