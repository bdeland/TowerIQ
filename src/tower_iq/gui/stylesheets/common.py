"""
Common Stylesheets and Color Constants

This module contains common stylesheet definitions and color constants used across the application.
"""

# Color constants for consistent theming
LIGHT_THEME_COLORS = {
    'background': '#ffffff',
    'background_secondary': '#f8f8f8',
    'background_tertiary': '#f5f5f5',
    'text_primary': '#000000',
    'text_secondary': '#666666',
    'border': '#e0e0e0',
    'border_hover': '#d0d0d0',
    'accent': '#0078d4'
}

DARK_THEME_COLORS = {
    'background': '#1f1f1f',
    'background_secondary': '#272727',
    'background_tertiary': '#2d2d2d',
    'text_primary': '#ffffff',
    'text_secondary': '#cccccc',
    'border': '#404040',
    'border_hover': '#505050',
    'accent': '#0078d4'
}

# Common widget stylesheets
COMMON_LABEL_LIGHT_QSS = """
QLabel {
    color: #000000;
}
"""

COMMON_LABEL_DARK_QSS = """
QLabel {
    color: #ffffff;
}
"""

COMMON_WIDGET_LIGHT_QSS = """
QWidget {
    background-color: #ffffff;
    color: #000000;
}
"""

COMMON_WIDGET_DARK_QSS = """
QWidget {
    background-color: #272727;
    color: #ffffff;
}
""" 