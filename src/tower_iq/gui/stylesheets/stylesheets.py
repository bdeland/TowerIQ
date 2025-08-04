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

# Styles for the expandable card group (new compositional approach)
EXPANDABLE_CARD_GROUP_QSS = """
#HeaderCard {{
    /* Standard state: rounded corners */
    border-radius: 8px;
    background-color: {card_bg};
    border: 1px solid {card_border};
}}

#HeaderCard[expanded="true"][hasSubCards="true"] {{
    /* Expanded state: only top corners rounded */
    border-bottom-left-radius: 0px;
    border-bottom-right-radius: 0px;
}}

#HeaderCard BodyLabel {{
    background-color: transparent;
    font-size: 14px;
    font-weight: 500;
    border: none;
}}

#HeaderCard CaptionLabel {{
    background-color: transparent;
    font-size: 12px;
    border: none;
}}

/* Sub-card styling - target SubsettingItem class directly */
#SubCardContainer SubsettingItem {{
    /* Default styling for all sub-cards */
    background-color: {sub_card_bg};
    border: 1px solid {sub_card_border};
    border-top: none;
    border-radius: 0px;
}}

/* Ensure text elements within sub-cards are transparent and have no borders */
#SubCardContainer SubsettingItem > BodyLabel {{
    background-color: transparent !important;
    border: none !important;
    font-size: 14px;
    font-weight: 500;
}}

#SubCardContainer SubsettingItem > PushButton {{
    background-color: transparent !important;
    border: none !important;
    font-size: 14px;
    font-weight: 500;
}}

/* Property-based selectors for dynamic corner rounding */
#SubCardContainer SubsettingItem[position="single"] {{
    /* A single sub-card: only bottom corners rounded */
    border-top-left-radius: 0px;
    border-top-right-radius: 0px;
    border-bottom-left-radius: 8px;
    border-bottom-right-radius: 8px;
    background-color: {sub_card_bg};
    border: 1px solid {sub_card_border};
    border-top: none;
}}

#SubCardContainer SubsettingItem[position="first"] {{
    /* First of many sub-cards: square top, square bottom */
    border-top-left-radius: 0px;
    border-top-right-radius: 0px;
    border-bottom-left-radius: 0px;
    border-bottom-right-radius: 0px;
    background-color: {sub_card_bg};
    border: 1px solid {sub_card_border};
    border-top: none;
}}

#SubCardContainer SubsettingItem[position="middle"] {{
    /* Middle sub-cards: square top, square bottom */
    border-top-left-radius: 0px;
    border-top-right-radius: 0px;
    border-bottom-left-radius: 0px;
    border-bottom-right-radius: 0px;
    background-color: {sub_card_bg};
    border: 1px solid {sub_card_border};
    border-top: none;
}}

#SubCardContainer SubsettingItem[position="last"] {{
    /* Last sub-card: square top, rounded bottom */
    border-top-left-radius: 0px;
    border-top-right-radius: 0px;
    border-bottom-left-radius: 8px;
    border-bottom-right-radius: 8px;
    background-color: {sub_card_bg};
    border: 1px solid {sub_card_border};
    border-top: none;
}}

/* Spacer styling */
#CardSpacer {{
    background-color: transparent;
    border: none;
}}
"""

# Styles for subsetting items
SUBSETTING_ITEM_QSS = """
SubsettingItem {{
    background-color: transparent;
    border: none;
}}
SubsettingItem BodyLabel#subsetting_label {{
    background-color: transparent;
    font-size: 13px;
    font-weight: 400;
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

# Styles for the ModuleViewWidget component
MODULE_VIEW_QSS = """
QWidget#ModuleView {{
    background-color: {card_bg};
    border: 1px solid {card_border};
    border-radius: 15px;
    padding: 0px;
}}

QWidget#ModuleView TitleLabel#ModuleRarity {{
    background-color: transparent;
    font-size: 18px;
    font-weight: 600;
    padding: 5px 0px;
}}



QWidget#ModuleView TitleLabel#ModuleName {{
    background-color: transparent;
    font-size: 16px;
    font-weight: 500;
}}

QWidget#ModuleView TitleLabel#ModuleName[rarity="common"] {{
    color: #e4e4e5;
}}

QWidget#ModuleView TitleLabel#ModuleName[rarity="rare"] {{
    color: #47dbff;
}}

QWidget#ModuleView TitleLabel#ModuleName[rarity="rareplus"] {{
    color: #47dbff;
}}

QWidget#ModuleView TitleLabel#ModuleName[rarity="epic"] {{
    color: #ff4ccf;
}}

QWidget#ModuleView TitleLabel#ModuleName[rarity="epicplus"] {{
    color: #ff4ccf;
}}

QWidget#ModuleView TitleLabel#ModuleName[rarity="legendary"] {{
    color: #ff9c3d;
}}

QWidget#ModuleView TitleLabel#ModuleName[rarity="legendaryplus"] {{
    color: #ff9c3d;
}}

QWidget#ModuleView TitleLabel#ModuleName[rarity="mythic"] {{
    color: #ff4040;
}}

QWidget#ModuleView TitleLabel#ModuleName[rarity="mythicplus"] {{
    color: #ff4040;
}}

QWidget#ModuleView TitleLabel#ModuleName[rarity="ancestral"] {{
    color: #79f369;
}}

QWidget#ModuleView BodyLabel#ModuleRarity {{
    background-color: transparent;
    font-size: 18px;
    font-weight: 600;
    color: {secondary_text};
    margin-left: 0px;
}}

QWidget#ModuleView BodyLabel#ModuleMainStat {{
    background-color: transparent;
    font-size: 12px;
    color: {secondary_text};
}}

QWidget#ModuleView QWidget#ModuleIconContainer {{
    background-color: transparent;
    border: none;
}}

QWidget#ModuleView QLabel#ModuleIcon {{
    background-color: transparent;
    border: none;
}}

QWidget#ModuleView QLabel#ModuleFavorite {{
    background-color: transparent;
    border: none;
}}

QWidget#ModuleView BodyLabel#ModuleLevel {{
    background-color: transparent;
    font-size: 13px;
    font-weight: 500;
}}

QWidget#ModuleView ProgressBar#ModuleLevelBar {{
    background-color: transparent;
}}

QWidget#ModuleView BodyLabel#EffectsTitle {{
    background-color: transparent;
    font-size: 14px;
    font-weight: 600;
    padding: 8px 0px 4px 0px;
}}

QWidget#ModuleView BodyLabel#UniqueEffectTitle {{
    background-color: transparent;
    font-size: 14px;
    font-weight: 600;
    padding: 8px 0px 4px 0px;
}}

QWidget#ModuleView BodyLabel#UniqueEffectText {{
    background-color: {unique_effect_bg};
    border: 1px solid {unique_effect_border};
    border-radius: 8px;
    padding: 12px;
    font-size: 12px;
    font-weight: 400;
    color: {unique_effect_text};
}}

QWidget#SubstatRow {{
    background-color: {substat_row_bg};
    border: 1px solid {substat_row_border};
    border-radius: 8px;
    margin: 2px 0px;
}}

QWidget#SubstatRow BodyLabel#RarityPill {{
    background-color: {rarity_pill_bg};
    color: {rarity_pill_text};
    padding: 3px 8px;
    border-radius: 6px;
    font-size: 11px;
    font-weight: 600;
    min-width: 50px;
    max-width: 60px;
}}

QWidget#SubstatRow BodyLabel#RarityPill[rarity="common"] {{
    background-color: #a0a0a0;
    color: #ffffff;
}}

QWidget#SubstatRow BodyLabel#RarityPill[rarity="rare"] {{
    background-color: #47dbff;
    color: #000000;
}}

QWidget#SubstatRow BodyLabel#RarityPill[rarity="epic"] {{
    background-color: #ff4ccf;
    color: #ffffff;
}}

QWidget#SubstatRow BodyLabel#RarityPill[rarity="legendary"] {{
    background-color: #ff9c3d;
    color: #000000;
}}

QWidget#SubstatRow BodyLabel#RarityPill[rarity="mythic"] {{
    background-color: #ff4040;
    color: #ffffff;
}}

QWidget#SubstatRow BodyLabel#RarityPill[rarity="ancestral"] {{
    background-color: #79f369;
    color: #000000;
}}

QWidget#SubstatRow BodyLabel#SubstatText {{
    background-color: transparent;
    font-size: 12px;
    font-weight: 400;
}}

QWidget#LockedSubstatRow {{
    background-color: {locked_substat_bg};
    border: 1px solid {locked_substat_border};
    border-radius: 8px;
    margin: 2px 0px;
}}

QWidget#LockedSubstatRow BodyLabel#LockedText {{
    background-color: transparent;
    font-size: 12px;
    font-style: italic;
    color: {secondary_text};
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
        # Module view colors
        'secondary_text': '#666666',
        'substat_row_bg': '#f8f9fa',
        'substat_row_border': '#e9ecef',
        'rarity_pill_bg': '#6c757d',
        'rarity_pill_text': '#ffffff',
        'locked_substat_bg': '#f1f3f4',
        'locked_substat_border': '#dadce0',
        'unique_effect_bg': '#fff3cd',
        'unique_effect_border': '#ffeaa7',
        'unique_effect_text': '#856404',
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
        'divider_color': '#e0e0e0',
    },
    'dark': {
        'card_bg': '#2d2d2d',
        'card_border': '#404040',
        'card_hover_bg': '#3a3a3a',
        'card_hover_border': '#505050',
        'sub_card_bg': '#2d2d2d',
        'sub_card_border': '#404040',
        # Module view colors
        'secondary_text': '#a0a0a0',
        'substat_row_bg': '#3a3a3a',
        'substat_row_border': '#505050',
        'rarity_pill_bg': '#555555',
        'rarity_pill_text': '#ffffff',
        'locked_substat_bg': '#2a2a2a',
        'locked_substat_border': '#404040',
        'unique_effect_bg': '#3a2f1a',
        'unique_effect_border': '#5a4a2a',
        'unique_effect_text': '#ffd700',
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
        'divider_color': '#404040',
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
        SUBSETTING_ITEM_QSS.format(**theme_palette) +
        SETTINGS_CATEGORY_PAGE_QSS.format(**theme_palette) +
        PAGE_HEADER_QSS.format(**theme_palette) +
        CONTENT_PAGE_QSS.format(**theme_palette) +
        PIVOT_QSS.format(**theme_palette) +
        MODULE_VIEW_QSS.format(**theme_palette)
    )