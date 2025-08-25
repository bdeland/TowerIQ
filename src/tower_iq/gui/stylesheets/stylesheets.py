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
    qproperty-lightColor: {rc_common_primary};
    qproperty-darkColor: {rc_common_primary};
}}

QWidget#ModuleView TitleLabel#ModuleName[rarity="rare"] {{
    qproperty-lightColor: {rc_rare_primary};
    qproperty-darkColor: {rc_rare_primary};
}}

QWidget#ModuleView TitleLabel#ModuleName[rarity="rareplus"] {{
    qproperty-lightColor: {rc_rareplus_primary};
    qproperty-darkColor: {rc_rareplus_primary};
}}

QWidget#ModuleView TitleLabel#ModuleName[rarity="epic"] {{
    qproperty-lightColor: {rc_epic_primary};
    qproperty-darkColor: {rc_epic_primary};
}}

QWidget#ModuleView TitleLabel#ModuleName[rarity="epicplus"] {{
    qproperty-lightColor: {rc_epicplus_primary};
    qproperty-darkColor: {rc_epicplus_primary};
}}

QWidget#ModuleView TitleLabel#ModuleName[rarity="legendary"] {{
    qproperty-lightColor: {rc_legendary_primary};
    qproperty-darkColor: {rc_legendary_primary};
}}

QWidget#ModuleView TitleLabel#ModuleName[rarity="legendaryplus"] {{
    qproperty-lightColor: {rc_legendaryplus_primary};
    qproperty-darkColor: {rc_legendaryplus_primary};
}}

QWidget#ModuleView TitleLabel#ModuleName[rarity="mythic"] {{
    qproperty-lightColor: {rc_mythic_primary};
    qproperty-darkColor: {rc_mythic_primary};
}}

QWidget#ModuleView TitleLabel#ModuleName[rarity="mythicplus"] {{
    qproperty-lightColor: {rc_mythicplus_primary};
    qproperty-darkColor: {rc_mythicplus_primary};
}}

QWidget#ModuleView TitleLabel#ModuleName[rarity="ancestral"] {{
    qproperty-lightColor: {rc_ancestral_primary};
    qproperty-darkColor: {rc_ancestral_primary};
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

/* Main effect split styling */
/* Container for consistent spacing */
QWidget#MainEffectContainer {{
    background-color: transparent;
    border: none;
    padding: 0px;
    margin: 0px;
}}

/* Use descendant selector (no QWidget# prefix) to ensure QSS applies to BodyLabel subclass */
BodyLabel#MainEffectValue {{
    background-color: transparent;
    font-size: 18px;
    font-weight: 700;
    qproperty-lightColor: #4cedff;
    qproperty-darkColor: #4cedff;
}}
BodyLabel#MainEffectName {{
    background-color: transparent;
    font-size: 14px;
    font-weight: 500;
    qproperty-lightColor: #e0e0e0;
    qproperty-darkColor: #e0e0e0;
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
    qproperty-lightColor: {unique_effect_text};
    qproperty-darkColor: {unique_effect_text};
}}



/* RarityPillWidget styling - handled by custom paint event */

QWidget#SubstatRow BodyLabel#SubstatText {{
    background-color: transparent;
    font-size: 12px;
    font-weight: 400;
}}

/* New: Two-part substat styling */
QWidget#SubstatRow BodyLabel#SubstatValue {{
    background-color: transparent;
    font-size: 12px;
    font-weight: 800;
}}
QWidget#SubstatRow BodyLabel#SubstatName {{
    background-color: transparent;
    font-size: 12px;
    font-weight: 400;
    margin-left: 0px;
}}

/* Value colors per rarity - use qproperty to cooperate with qfluentwidgets color management */
QWidget#SubstatRow BodyLabel#SubstatValue[rarity="common"] {{ qproperty-lightColor: {rc_common_primary}; qproperty-darkColor: {rc_common_primary}; }}
QWidget#SubstatRow BodyLabel#SubstatValue[rarity="rare"] {{ qproperty-lightColor: {rc_rare_primary}; qproperty-darkColor: {rc_rare_primary}; }}
QWidget#SubstatRow BodyLabel#SubstatValue[rarity="rareplus"] {{ qproperty-lightColor: {rc_rareplus_primary}; qproperty-darkColor: {rc_rareplus_primary}; }}
QWidget#SubstatRow BodyLabel#SubstatValue[rarity="epic"] {{ qproperty-lightColor: {rc_epic_primary}; qproperty-darkColor: {rc_epic_primary}; }}
QWidget#SubstatRow BodyLabel#SubstatValue[rarity="epicplus"] {{ qproperty-lightColor: {rc_epicplus_primary}; qproperty-darkColor: {rc_epicplus_primary}; }}
QWidget#SubstatRow BodyLabel#SubstatValue[rarity="legendary"] {{ qproperty-lightColor: {rc_legendary_primary}; qproperty-darkColor: {rc_legendary_primary}; }}
QWidget#SubstatRow BodyLabel#SubstatValue[rarity="legendaryplus"] {{ qproperty-lightColor: {rc_legendaryplus_primary}; qproperty-darkColor: {rc_legendaryplus_primary}; }}
QWidget#SubstatRow BodyLabel#SubstatValue[rarity="mythic"] {{ qproperty-lightColor: {rc_mythic_primary}; qproperty-darkColor: {rc_mythic_primary}; }}
QWidget#SubstatRow BodyLabel#SubstatValue[rarity="mythicplus"] {{ qproperty-lightColor: {rc_mythicplus_primary}; qproperty-darkColor: {rc_mythicplus_primary}; }}
QWidget#SubstatRow BodyLabel#SubstatValue[rarity="ancestral"] {{ qproperty-lightColor: {rc_ancestral_primary}; qproperty-darkColor: {rc_ancestral_primary}; }}

/* Name colors per rarity (slightly softer than value) - via qproperty */
QWidget#SubstatRow BodyLabel#SubstatName[rarity="common"] {{ qproperty-lightColor: {rc_common_soft}; qproperty-darkColor: {rc_common_soft}; }}
QWidget#SubstatRow BodyLabel#SubstatName[rarity="rare"] {{ qproperty-lightColor: {rc_rare_soft}; qproperty-darkColor: {rc_rare_soft}; }}
QWidget#SubstatRow BodyLabel#SubstatName[rarity="rareplus"] {{ qproperty-lightColor: {rc_rareplus_soft}; qproperty-darkColor: {rc_rareplus_soft}; }}
QWidget#SubstatRow BodyLabel#SubstatName[rarity="epic"] {{ qproperty-lightColor: {rc_epic_soft}; qproperty-darkColor: {rc_epic_soft}; }}
QWidget#SubstatRow BodyLabel#SubstatName[rarity="epicplus"] {{ qproperty-lightColor: {rc_epicplus_soft}; qproperty-darkColor: {rc_epicplus_soft}; }}
QWidget#SubstatRow BodyLabel#SubstatName[rarity="legendary"] {{ qproperty-lightColor: {rc_legendary_soft}; qproperty-darkColor: {rc_legendary_soft}; }}
QWidget#SubstatRow BodyLabel#SubstatName[rarity="legendaryplus"] {{ qproperty-lightColor: {rc_legendaryplus_soft}; qproperty-darkColor: {rc_legendaryplus_soft}; }}
QWidget#SubstatRow BodyLabel#SubstatName[rarity="mythic"] {{ qproperty-lightColor: {rc_mythic_soft}; qproperty-darkColor: {rc_mythic_soft}; }}
QWidget#SubstatRow BodyLabel#SubstatName[rarity="mythicplus"] {{ qproperty-lightColor: {rc_mythicplus_soft}; qproperty-darkColor: {rc_mythicplus_soft}; }}
QWidget#SubstatRow BodyLabel#SubstatName[rarity="ancestral"] {{ qproperty-lightColor: {rc_ancestral_soft}; qproperty-darkColor: {rc_ancestral_soft}; }}



QWidget#LockedSubstatRow BodyLabel#LockedText {{
    background-color: transparent;
    font-size: 12px;
    font-style: italic;
    color: {secondary_text};
}}
"""

# Grafana-style main window and navigation styles
GRAFANA_MAIN_WINDOW_QSS = """
FluentWindow {{
    background-color: {main_bg};
}}

/* Sidebar styling */
FluentWindow NavigationInterface {{
    background-color: {sidebar_bg};
    border-right: 1px solid {card_border};
}}

/* Sidebar header */
FluentWindow NavigationInterface QWidget#navigationHeader {{
    background-color: {sidebar_bg};
    border-bottom: 1px solid {card_border};
    padding: 16px;
}}

/* Navigation items */
FluentWindow NavigationInterface NavigationItem {{
    background-color: transparent;
    border: none;
    padding: 12px 16px;
    margin: 1px 8px;
    border-radius: 4px;
    color: {text_color};
    font-size: 14px;
    font-weight: 500;
}}

FluentWindow NavigationInterface NavigationItem:hover {{
    background-color: rgba(255, 255, 255, 0.04);
}}

FluentWindow NavigationInterface NavigationItem:checked {{
    background-color: rgba(247, 149, 32, 0.1);
    border-left: 4px solid {active_indicator};
    color: {active_indicator};
    font-weight: 600;
}}

/* Navigation item icons */
FluentWindow NavigationInterface NavigationItem QLabel {{
    color: {text_color};
    font-size: 16px;
}}

FluentWindow NavigationInterface NavigationItem:checked QLabel {{
    color: {active_indicator};
}}

/* Nested navigation items */
FluentWindow NavigationInterface NavigationItem[level="1"] {{
    padding-left: 32px;
    font-size: 13px;
}}

/* Header styling */
QWidget#HeaderWidget {{
    background-color: {header_bg};
    border-bottom: 1px solid {card_border};
    padding: 0px;
}}

/* Main content area styling */
FluentWindow QStackedWidget {{
    background-color: {main_bg};
}}

FluentWindow QWidget#contentWidget {{
    background-color: {main_bg};
}}

QWidget#HeaderWidget QHBoxLayout {{
    background-color: transparent;
    padding: 8px 24px;
}}

/* Logo button styling */
QWidget#HeaderWidget QPushButton#logoButton {{
    background-color: transparent;
    border: none;
    padding: 8px;
    border-radius: 4px;
}}

QWidget#HeaderWidget QPushButton#logoButton:hover {{
    background-color: rgba(255, 255, 255, 0.04);
}}

/* Breadcrumb styling */
QWidget#HeaderWidget BreadcrumbBar {{
    background-color: transparent;
    border: none;
    color: {text_color};
    font-size: 14px;
}}

/* Search bar styling */
QWidget#HeaderWidget SearchLineEdit {{
    background-color: {sub_card_bg};
    border: 1px solid {card_border};
    border-radius: 4px;
    padding: 8px 12px;
    color: {text_color};
    font-size: 14px;
}}

QWidget#HeaderWidget SearchLineEdit:focus {{
    border: 1px solid {accent_color};
}}
"""

# Styles for the modules page
MODULES_PAGE_QSS = """
#FiltersSection, #TableSection {{
    background-color: transparent;
    border: none;
    padding: 0px;
}}

#ModuleSearch {{
    background-color: {sub_card_bg};
    border: 1px solid {sub_card_border};
    border-radius: 6px;
    padding: 8px 12px;
    font-size: 14px;
}}

#ModuleSearch:focus {{
    border: 2px solid {accent_color};
}}

#LevelSlider {{
    background-color: transparent;
    qproperty-barColor: {accent_color};
}}

#LevelSlider::groove:horizontal {{
    background-color: {sub_card_bg};
    border: 1px solid {sub_card_border};
    border-radius: 4px;
    height: 6px;
}}

#LevelSlider::handle:horizontal {{
    background-color: {accent_color};
    border: 1px solid {accent_color};
    border-radius: 8px;
    width: 16px;
    height: 16px;
    margin: -5px 0px;
}}

#ModulesTable {{
    background-color: {sub_card_bg};
    border: 1px solid {sub_card_border};
    border-radius: 6px;
    gridline-color: {card_border};
}}

#ModulesTable::item {{
    padding: 4px;
    border: none;
}}

#ModulesTable::item:selected {{
    background-color: {accent_color};
    color: white;
}}

#ModulesTable QHeaderView::section {{
    background-color: {card_bg};
    border: 1px solid {card_border};
    padding: 8px;
    font-weight: 600;
    color: {text_color};
}}

#ModuleViewWidget {{
    background-color: {card_bg};
    border: 1px solid {card_border};
    border-radius: 8px;
    padding: 15px;
}}

#GenerateModulesButton {{
    /* Keep default button styling to avoid clashes with theme */
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
        #'substat_row_bg': '#292929',
        #'substat_row_border': 'transparent',
        'rarity_pill_bg': '#6c757d',
        'rarity_pill_text': '#ffffff',
        'rarity_pill_border': '#495057',
        #'locked_substat_bg': '#f1f3f4',
        #'locked_substat_border': '#dadce0',
        'unique_effect_bg': '#fff3cd',
        'unique_effect_border': '#ffeaa7',
        'unique_effect_text': '#ffae00',
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
        'text_color': '#212529',
        'accent_color': '#007bff',
    },
    'dark': {
        # Grafana-inspired dark theme colors
        'card_bg': '#202226',  # Grafana sidebar/card background
        'card_border': '#343434',  # Grafana border color
        'card_hover_bg': '#2a2a2a',
        'card_hover_border': '#404040',
        'sub_card_bg': '#202226',
        'sub_card_border': '#343434',
        # Module view colors
        'secondary_text': '#8e8e8e',
        'rarity_pill_bg': '#555555',
        'rarity_pill_text': '#ffffff',
        'rarity_pill_border': '#404040',
        'unique_effect_bg': '#3a2f1a',
        'unique_effect_border': '#5a4a2a',
        'unique_effect_text': '#ffae00',
        # Pivot colors
        'pivot_item_bg': '#2a2a2a',
        'pivot_item_border': '#343434',
        'pivot_item_text': '#e0e0e0',
        'pivot_item_hover_bg': '#3a3a3a',
        'pivot_item_hover_border': '#404040',
        'pivot_item_hover_text': '#ffffff',
        'pivot_item_selected_bg': '#f79520',  # Grafana orange
        'pivot_item_selected_border': '#f79520',
        'pivot_item_selected_text': '#ffffff',
        'pivot_item_selected_hover_bg': '#e88a1d',
        'pivot_item_selected_hover_border': '#e88a1d',
        'pivot_item_selected_hover_text': '#ffffff',
        'divider_color': '#343434',
        'text_color': '#e0e0e0',
        'accent_color': '#f79520',  # Grafana orange
        # Grafana-specific colors
        'main_bg': '#111217',  # Grafana main background
        'sidebar_bg': '#202226',  # Grafana sidebar background
        'header_bg': '#202226',  # Grafana header background
        'active_indicator': '#f79520',  # Grafana orange for active items
    }
}

# --- Centralized Rarity Color Palette ---
# Use these to avoid repeating hex codes across multiple rarity-based rules.
# 'primary' is the strong/primary color for the rarity, 'soft' is a softer companion.
RARITY_COLORS = {
    'common':       {'primary': '#ffffff', 'soft': '#e3e3e4'},
    'rare':         {'primary': '#47d8fd', 'soft': '#47dbff'},
    'rareplus':     {'primary': '#47d8fd', 'soft': '#47dbff'},
    'epic':         {'primary': '#fd4bce', 'soft': '#ff7cdc'},
    'epicplus':     {'primary': '#fd4bce', 'soft': '#ff7cdc'},
    'legendary':    {'primary': '#ff9c3d', 'soft': '#f8b26f'},
    'legendaryplus':{'primary': '#ff9c3d', 'soft': '#f8b26f'},
    'mythic':       {'primary': '#ff4040', 'soft': '#f35d6e'},
    'mythicplus':   {'primary': '#ff4040', 'soft': '#f35d6e'},
    'ancestral':    {'primary': '#83e879', 'soft': '#c0f1c1'},
}

def _flatten_rarity_colors() -> dict:
    flat: dict[str, str] = {}
    for rarity_key, tones in RARITY_COLORS.items():
        flat[f'rc_{rarity_key}_primary'] = tones['primary']
        flat[f'rc_{rarity_key}_soft'] = tones['soft']
    return flat

def get_themed_stylesheet() -> str:
    """
    Generates the full application stylesheet based on the current theme.
    This is the function that will be imported by the MainWindow.
    """
    from qfluentwidgets import isDarkTheme
    theme_name = 'dark' if isDarkTheme() else 'light'
    theme_palette = THEME_COLORS[theme_name]
    rarity_palette = _flatten_rarity_colors()
    merged = {**theme_palette, **rarity_palette}
    
    # --- CORRECTED: Unpack the dictionary with ** ---
    return (
        GRAFANA_MAIN_WINDOW_QSS.format(**merged) +
        SETTINGS_CATEGORY_CARD_QSS.format(**merged) +
        SETTINGS_ITEM_CARD_QSS.format(**merged) +
        EXPANDABLE_CARD_GROUP_QSS.format(**merged) +
        SUBSETTING_ITEM_QSS.format(**merged) +
        SETTINGS_CATEGORY_PAGE_QSS.format(**merged) +
        PAGE_HEADER_QSS.format(**merged) +
        CONTENT_PAGE_QSS.format(**merged) +
        PIVOT_QSS.format(**merged) +
        MODULE_VIEW_QSS.format(**merged) +
        MODULES_PAGE_QSS.format(**merged)
    )