"""
TowerIQ v1.0 - GUI Package

This package contains the PyQt6-based graphical user interface components for TowerIQ.
"""

__version__ = "1.0.0"
__author__ = "TowerIQ Development Team"

from .main_window import MainWindow
from .pages.home_page import HomePage
from .pages.dashboards_page import DashboardsPage
from .pages.connection_page import ConnectionPage
from .pages.settings_page import SettingsPage

# Settings pages
from .pages.appearance_settings_page import AppearanceSettingsPage
from .pages.logging_settings_page import LoggingSettingsPage
from .pages.connection_settings_page import ConnectionSettingsPage
from .pages.database_settings_page import DatabaseSettingsPage
from .pages.frida_settings_page import FridaSettingsPage
from .pages.advanced_settings_page import AdvancedSettingsPage

# Utils
from .utils.database_path_card import DatabasePathCard
from .utils.database_info_card import DatabaseInfoCard
from .utils.health_check_card import HealthCheckCard
from .utils.settings_item_card import SettingsItemCard
from .utils.settings_category_card import SettingsCategoryCard
from .utils.expandable_settings_card import ExpandableCardGroup, SubsettingItem
from .utils.page_header import PageHeader
from .utils.header_widget import HeaderWidget
from .utils.logging_settings_widget import LoggingSettingsWidget

# Stylesheets
from .stylesheets import get_themed_stylesheet, THEME_COLORS, LIGHT_THEME_COLORS, DARK_THEME_COLORS

__all__ = [
    'MainWindow',
    'HomePage',
    'DashboardsPage', 
    'ConnectionPage',
    'SettingsPage',
    'AppearanceSettingsPage',
    'LoggingSettingsPage',
    'ConnectionSettingsPage',
    'DatabaseSettingsPage',
    'FridaSettingsPage',
    'AdvancedSettingsPage',
    'DatabasePathCard',
    'DatabaseInfoCard',
    'HealthCheckCard',
    'SettingsItemCard',
    'SettingsCategoryCard',
    'ExpandableCardGroup',
    'SubsettingItem',
    'PageHeader',
    'HeaderWidget',
    'LoggingSettingsWidget',
    'get_themed_stylesheet',
    'THEME_COLORS',
    'LIGHT_THEME_COLORS',
    'DARK_THEME_COLORS',
]