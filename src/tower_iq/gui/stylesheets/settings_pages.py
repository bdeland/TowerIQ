"""
Settings Pages Stylesheets

This module contains the stylesheet definitions for the settings pages and their components.
"""

# Settings page main stylesheets
SETTINGS_PAGE_LIGHT_QSS = """
QWidget {
    background-color: #ffffff;
    color: #000000;
}

QWidget#header_widget {
    background-color: #f8f8f8;
    color: #000000;
}

QWidget#content_widget {
    background-color: #f8f8f8;
    color: #000000;
}

QLabel {
    color: #000000;
}

QLabel#title_label {
    color: #000000;
    font-size: 24px;
    font-weight: bold;
}
"""

SETTINGS_PAGE_DARK_QSS = """
QWidget {
    background-color: #272727;
    color: #ffffff;
}

QWidget#header_widget {
    background-color: #156f39;
    color: #ffffff;
}

QWidget#content_widget {
    background-color: #2d2d2d;
    color: #ffffff;
}

QLabel {
    color: #ffffff;
}

QLabel#title_label {
    color: #ffffff;
    font-size: 24px;
    font-weight: bold;
}
"""

# Settings content widget stylesheets
SETTINGS_CONTENT_WIDGET_LIGHT_QSS = """
QWidget {
    background-color: #f8f8f8;
    color: #000000;
    border-radius: 8px;
    padding: 16px;
}

QLabel {
    color: #000000;
}
"""

SETTINGS_CONTENT_WIDGET_DARK_QSS = """
QWidget {
    background-color: #2d2d2d;
    color: #ffffff;
    border-radius: 8px;
    padding: 16px;
}

QLabel {
    color: #ffffff;
}
""" 