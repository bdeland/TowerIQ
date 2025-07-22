# TowerIQ Product Overview

TowerIQ is an advanced mobile game analysis platform that monitors and analyzes "The Tower" mobile game using Frida instrumentation. It provides real-time data collection, visualization, and analysis through a PyQt6 desktop application.

## Core Purpose
- Real-time monitoring of mobile game metrics (coins, gems, cells, game speed)
- Data visualization and analysis through interactive dashboards
- Automated device connection and Frida hook injection
- Historical data tracking and analysis

## Target Game
- Package: `com.TechTreeGames.TheTower`
- Supported versions defined in `config/hook_contract.yaml`
- Uses Frida JavaScript hooks for runtime instrumentation

## Key Features
- Embedded SQLite database with encryption
- Multi-stage connection wizard for device setup
- Real-time graph plotting with PyQtGraph
- Automated frida-server management
- Cross-platform desktop application (Windows focus)