"""
TowerIQ GUI Stylesheets

This package contains all the stylesheet definitions for the TowerIQ GUI components.
Each stylesheet is organized by component and theme (light/dark).
"""

from .stylesheets import (
    get_themed_stylesheet,
    THEME_COLORS,
    SETTINGS_CATEGORY_CARD_QSS,
    SETTINGS_ITEM_CARD_QSS,
    SETTINGS_CATEGORY_PAGE_QSS,
    CONTENT_PAGE_QSS,
    PAGE_HEADER_QSS,
    PIVOT_QSS
)

# Extract theme colors for convenience
LIGHT_THEME_COLORS = THEME_COLORS['light']
DARK_THEME_COLORS = THEME_COLORS['dark']

__all__ = [
    # Main function
    'get_themed_stylesheet',
    
    # Theme colors
    'THEME_COLORS',
    'LIGHT_THEME_COLORS',
    'DARK_THEME_COLORS',
    
    # Individual stylesheets
    'SETTINGS_CATEGORY_CARD_QSS',
    'SETTINGS_ITEM_CARD_QSS',
    'SETTINGS_CATEGORY_PAGE_QSS',
    'CONTENT_PAGE_QSS',
    'PAGE_HEADER_QSS',
    'PIVOT_QSS'
] 