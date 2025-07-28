"""
TowerIQ Application Stylesheets

This module centralizes all Qt Style Sheet (QSS) definitions for the application.
It provides a function to generate a complete, theme-aware stylesheet.
"""

# --- QSS Templates ---
# Placeholders are now direct keys, e.g., {card_bg} instead of {theme.card_bg}

# Styles for the Pivot component in settings page
PIVOT_QSS = """
#settings_pivot {{
    background-color: transparent;
    border: none;
    padding: 0px;
    margin: 0px;
}}

#settings_pivot PushButton {{
    background-color: {pivot_item_bg};
    border: 1px solid {pivot_item_border};
    border-radius: 8px;
    padding: 12px 20px;
    margin: 0px 4px;
    font-size: 14px;
    font-weight: 500;
    color: {pivot_item_text};
    text-align: center;
}}

#settings_pivot PushButton:hover {{
    background-color: {pivot_item_hover_bg};
    border: 1px solid {pivot_item_hover_border};
    color: {pivot_item_hover_text};
}}

#settings_pivot PushButton:checked {{
    background-color: {pivot_item_selected_bg};
    border: 1px solid {pivot_item_selected_border};
    color: {pivot_item_selected_text};
    font-weight: 600;
}}

#settings_pivot PushButton:checked:hover {{
    background-color: {pivot_item_selected_hover_bg};
    border: 1px solid {pivot_item_selected_hover_border};
    color: {pivot_item_selected_hover_text};
}}


"""

# Styles for the main category cards on the primary settings page
SETTINGS_CATEGORY_CARD_QSS = """
SettingsCategoryCard {{
    background-color: {card_bg};
    border: 1px solid {card_border};
    border-radius: 50px;
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

# Styles for the expandable card group (simplified)
EXPANDABLE_CARD_GROUP_QSS = """
#HeaderCard {{
    border-radius: 8px;
}}

#HeaderCard BodyLabel {{
    background-color: transparent;
    border: none;
}}

#HeaderCard CaptionLabel {{
    background-color: transparent;
    border: none;
}}
"""

# Styles for the main content area of settings detail pages
SETTINGS_CATEGORY_PAGE_QSS = """
SettingsCategoryPage, QScrollArea, QScrollArea::viewport, #content_widget {{
    background-color: transparent;
    border: none;
}}
"""

# Styles for the reusable PageHeader component
PAGE_HEADER_QSS = """
QWidget#page_header {{
    background-color: transparent;
}}
QWidget#page_header TitleLabel#title_label {{
    background-color: transparent;
}}
QWidget#page_header CaptionLabel#description_label {{
    background-color: transparent;
}}
"""

# Styles for the reusable ContentPage component
CONTENT_PAGE_QSS = """
QWidget#content_page {{
    background-color: transparent;
    border: none;
}}
QWidget#content_page QWidget#content_widget {{
    background-color: transparent;
    border: none;
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
        # Pivot colors
        'pivot_item_bg': '#f8f9fa',
        'pivot_item_border': '#303030',
        'pivot_item_text': '#495057',
        'pivot_item_hover_bg': '#11a8cd',
        'pivot_item_hover_border': '#dee2e6',
        'pivot_item_hover_text': '#212529',
        'pivot_item_selected_bg': '#007bff',
        'pivot_item_selected_border': '#0056b3',
        'pivot_item_selected_text': '#ffffff',
        'pivot_item_selected_hover_bg': '#0056b3',
        'pivot_item_selected_hover_border': '#004085',
        'pivot_item_selected_hover_text': '#ffffff',
    },
    'dark': {
        'card_bg': '#2d2d2d',
        'card_border': '#404040',
        'card_hover_bg': '#3a3a3a',
        'card_hover_border': '#505050',
        'sub_card_bg': '#2d2d2d',
        'sub_card_border': '#404040',
        # Pivot colors
        'pivot_item_bg': '#3a3a3a',
        'pivot_item_border': '#11a8cd',
        'pivot_item_text': '#e0e0e0',
        'pivot_item_hover_bg': '#4a4a4a',
        'pivot_item_hover_border': '#5a5a5a',
        'pivot_item_hover_text': '#ffffff',
        'pivot_item_selected_bg': '#0d6efd',
        'pivot_item_selected_border': '#0a58ca',
        'pivot_item_selected_text': '#ffffff',
        'pivot_item_selected_hover_bg': '#0a58ca',
        'pivot_item_selected_hover_border': '#084298',
        'pivot_item_selected_hover_text': '#ffffff',
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
        EXPANDABLE_CARD_GROUP_QSS.format(**theme_palette) +
        SETTINGS_CATEGORY_PAGE_QSS.format(**theme_palette) +
        PAGE_HEADER_QSS.format(**theme_palette) +
        CONTENT_PAGE_QSS.format(**theme_palette) +
        PIVOT_QSS.format(**theme_palette)
    )