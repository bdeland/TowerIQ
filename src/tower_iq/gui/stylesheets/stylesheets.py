"""
TowerIQ Application Stylesheets

This module centralizes all Qt Style Sheet (QSS) definitions for the application.
It provides a function to generate a complete, theme-aware stylesheet.
"""

# --- QSS Templates ---
# Placeholders are now direct keys, e.g., {card_bg} instead of {theme.card_bg}

# Styles for the main category cards on the primary settings page
SETTINGS_CATEGORY_CARD_QSS = """
SettingsCategoryCard {{
    background-color: {card_bg};
    border: 1px solid {card_border};
    border-radius: 8px;
}}
SettingsCategoryCard:hover {{
    background-color: {card_hover_bg};
    border: 1px solid {card_hover_border};
}}
SettingsCategoryCard BodyLabel {{
    background-color: transparent;
    font-size: 24px;
    font-weight: 500;
}}
SettingsCategoryCard CaptionLabel {{
    background-color: transparent;
    opacity: 0.7;
}}
"""

# Styles for the individual setting items on category detail pages
SETTINGS_ITEM_CARD_QSS = """
SettingsItemCard {{
    background-color: {sub_card_bg};
    border: 1px solid {sub_card_border};
    border-radius: 8px;
}}
SettingsItemCard BodyLabel {{
    background-color: transparent;
    font-size: 14px;
    font-weight: 500;
}}
SettingsItemCard CaptionLabel {{
    background-color: transparent;
    font-size: 12px;
}}
"""

# Styles for the main content area of settings detail pages
SETTINGS_CATEGORY_PAGE_QSS = """
SettingsCategoryPage, QScrollArea, QScrollArea::viewport, #content_widget {{
    background-color: transparent;
    border: none;
}}
TitleLabel {{
    background-color: transparent;
    font-size: 28px;
    font-weight: 600;
    padding-top: 4px;
    padding-bottom: 4px;
}}
"""

# --- Theme Color Definitions ---
# This dictionary structure is correct.
THEME_COLORS = {
    'light': {
        'card_bg': '#ffffff',
        'card_border': '#e0e0e0',
        'card_hover_bg': '#f5f5f5',
        'card_hover_border': '#d0d0d0',
        'sub_card_bg': '#ffffff',
        'sub_card_border': '#e0e0e0',
    },
    'dark': {
        'card_bg': '#2d2d2d',
        'card_border': '#404040',
        'card_hover_bg': '#3a3a3a',
        'card_hover_border': '#505050',
        'sub_card_bg': '#2d2d2d',
        'sub_card_border': '#404040',
    }
}

def get_themed_stylesheet() -> str:
    """
    Generates the full application stylesheet based on the current theme.
    This is the function that will be imported by the MainWindow.
    """
    from qfluentwidgets import isDarkTheme
    theme_name = 'dark' if isDarkTheme() else 'light'
    theme_palette = THEME_COLORS[theme_name]
    
    # --- CORRECTED: Unpack the dictionary with ** ---
    return (
        SETTINGS_CATEGORY_CARD_QSS.format(**theme_palette) +
        SETTINGS_ITEM_CARD_QSS.format(**theme_palette) +
        SETTINGS_CATEGORY_PAGE_QSS.format(**theme_palette)
    )