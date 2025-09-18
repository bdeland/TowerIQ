"""
TowerIQ Database Schema and Metadata Configuration

This file defines the complete database schema, metadata, and structure for TowerIQ.
It serves as the single source of truth for database configuration.
"""

from typing import Dict, List, Any

# Database version
SCHEMA_VERSION = "1.0"

# ============================================================================
# COLUMN METADATA DEFINITIONS
# ============================================================================

# Data type constants
DATA_TYPES = {
    "INTEGER": "integer",
    "TEXT": "string", 
    "BLOB": "binary",
    "REAL": "float",
    "BOOLEAN": "boolean",
    "TIMESTAMP": "timestamp",
    "CURRENCY": "currency",
    "DURATION": "duration",
    "PERCENTAGE": "percentage",
    "COUNT": "count",
    "ENUM": "enum"
}

# Unit constants
UNITS = {
    # Time units
    "MILLISECONDS": "ms",
    "SECONDS": "s", 
    "MINUTES": "m",
    "HOURS": "h",
    "DAYS": "d",
    
    # Currency units
    "COINS": "coins",
    "GEMS": "gems", 
    "CELLS": "cells",
    "CASH": "cash",
    "STONES": "stones",
    
    # Count units
    "COUNT": "count",
    "WAVES": "waves",
    "TAPS": "taps",
    "CLAIMS": "claims",
    
    # Rate units
    "COINS_PER_HOUR": "coins/h",
    "WAVES_PER_MINUTE": "waves/min",
    
    # Percentage
    "PERCENT": "%",
    
    # Raw values
    "RAW": "raw",
    "SCALED": "scaled"
}

# Column metadata for all database tables
COLUMN_METADATA: Dict[str, Dict[str, Dict[str, Any]]] = {
    "runs": {
        "run_id": {
            "data_type": DATA_TYPES["BLOB"],
            "unit": UNITS["RAW"],
            "description": "Unique identifier for each run",
            "is_primary_key": True,
            "is_nullable": False,
            "formatting": {
                "display_as": "uuid",
                "max_length": 16
            }
        },
        "start_time": {
            "data_type": DATA_TYPES["TIMESTAMP"],
            "unit": UNITS["MILLISECONDS"],
            "description": "Run start timestamp",
            "is_primary_key": False,
            "is_nullable": False,
            "formatting": {
                "display_as": "datetime",
                "timezone": "UTC"
            }
        },
        "end_time": {
            "data_type": DATA_TYPES["TIMESTAMP"],
            "unit": UNITS["MILLISECONDS"],
            "description": "Run end timestamp",
            "is_primary_key": False,
            "is_nullable": True,
            "formatting": {
                "display_as": "datetime",
                "timezone": "UTC"
            }
        },
        "duration_realtime": {
            "data_type": DATA_TYPES["DURATION"],
            "unit": UNITS["MILLISECONDS"],
            "description": "Real-world duration of the run",
            "is_primary_key": False,
            "is_nullable": True,
            "formatting": {
                "display_as": "duration",
                "precision": 0
            }
        },
        "duration_gametime": {
            "data_type": DATA_TYPES["DURATION"],
            "unit": UNITS["MILLISECONDS"],
            "description": "In-game duration of the run",
            "is_primary_key": False,
            "is_nullable": True,
            "formatting": {
                "display_as": "duration",
                "precision": 0
            }
        },
        "final_wave": {
            "data_type": DATA_TYPES["COUNT"],
            "unit": UNITS["WAVES"],
            "description": "Last wave reached in the run",
            "is_primary_key": False,
            "is_nullable": True,
            "formatting": {
                "display_as": "number",
                "precision": 0
            }
        },
        "round_coins": {
            "data_type": DATA_TYPES["INTEGER"],
            "unit": UNITS["COINS"],
            "description": "Total coins earned in the run",
            "is_primary_key": False,
            "is_nullable": True,
            "formatting": {
                "display_as": "currency",
                "precision": 0,
                "use_commas": True,
                "suffix": " coins"
            }
        },
        "CPH": {
            "data_type": DATA_TYPES["INTEGER"],
            "unit": UNITS["COINS_PER_HOUR"],
            "description": "Coins per hour rate",
            "is_primary_key": False,
            "is_nullable": True,
            "formatting": {
                "display_as": "currency",
                "precision": 0,
                "use_commas": True,
                "suffix": " coins/h"
            }
        },
        "round_cells": {
            "data_type": DATA_TYPES["INTEGER"],
            "unit": UNITS["CELLS"],
            "description": "Total cells accumulated in the run",
            "is_primary_key": False,
            "is_nullable": True,
            "formatting": {
                "display_as": "currency",
                "precision": 0,
                "use_commas": True,
                "suffix": " cells"
            }
        },
        "round_gems": {
            "data_type": DATA_TYPES["INTEGER"],
            "unit": UNITS["GEMS"],
            "description": "Total gems accumulated in the run",
            "is_primary_key": False,
            "is_nullable": True,
            "formatting": {
                "display_as": "currency",
                "precision": 0,
                "use_commas": True,
                "suffix": " gems"
            }
        },
        "round_cash": {
            "data_type": DATA_TYPES["INTEGER"],
            "unit": UNITS["CASH"],
            "description": "Total cash accumulated in the run",
            "is_primary_key": False,
            "is_nullable": True,
            "formatting": {
                "display_as": "currency",
                "precision": 0,
                "use_commas": True,
                "suffix": " cash"
            }
        },
        "tier": {
            "data_type": DATA_TYPES["INTEGER"],
            "unit": UNITS["RAW"],
            "description": "Game tier/level",
            "is_primary_key": False,
            "is_nullable": True,
            "formatting": {
                "display_as": "number",
                "precision": 0
            }
        },
        "game_version_id": {
            "data_type": DATA_TYPES["INTEGER"],
            "unit": UNITS["RAW"],
            "description": "Foreign key to game_versions table",
            "is_primary_key": False,
            "is_nullable": False,
            "is_foreign_key": True,
            "references": "game_versions(id)",
            "formatting": {
                "display_as": "number",
                "precision": 0
            }
        }
    },
    
    "metrics": {
        "id": {
            "data_type": DATA_TYPES["INTEGER"],
            "unit": UNITS["RAW"],
            "description": "Auto-incrementing primary key",
            "is_primary_key": True,
            "is_nullable": False,
            "formatting": {
                "display_as": "number",
                "precision": 0
            }
        },
        "run_id": {
            "data_type": DATA_TYPES["BLOB"],
            "unit": UNITS["RAW"],
            "description": "Foreign key to runs table",
            "is_primary_key": False,
            "is_nullable": False,
            "is_foreign_key": True,
            "references": "runs(run_id)",
            "formatting": {
                "display_as": "uuid",
                "max_length": 16
            }
        },
        "real_timestamp": {
            "data_type": DATA_TYPES["TIMESTAMP"],
            "unit": UNITS["MILLISECONDS"],
            "description": "Real-world timestamp when metric was recorded",
            "is_primary_key": False,
            "is_nullable": False,
            "formatting": {
                "display_as": "datetime",
                "timezone": "UTC"
            }
        },
        "game_duration": {
            "data_type": DATA_TYPES["DURATION"],
            "unit": UNITS["MILLISECONDS"],
            "description": "In-game duration when metric was recorded",
            "is_primary_key": False,
            "is_nullable": True,
            "formatting": {
                "display_as": "duration",
                "precision": 0
            }
        },
        "current_wave": {
            "data_type": DATA_TYPES["COUNT"],
            "unit": UNITS["WAVES"],
            "description": "Wave number when metric was recorded",
            "is_primary_key": False,
            "is_nullable": True,
            "formatting": {
                "display_as": "number",
                "precision": 0
            }
        },
        "metric_name_id": {
            "data_type": DATA_TYPES["INTEGER"],
            "unit": UNITS["RAW"],
            "description": "Foreign key to metric_names table",
            "is_primary_key": False,
            "is_nullable": False,
            "is_foreign_key": True,
            "references": "metric_names(id)",
            "formatting": {
                "display_as": "number",
                "precision": 0
            }
        },
        "metric_value": {
            "data_type": DATA_TYPES["INTEGER"],
            "unit": UNITS["RAW"],
            "description": "Metric value as integer",
            "is_primary_key": False,
            "is_nullable": False,
            "formatting": {
                "display_as": "number",
                "precision": 0,
                "use_commas": True
            }
        }
    },
    
    "events": {
        "id": {
            "data_type": DATA_TYPES["INTEGER"],
            "unit": UNITS["RAW"],
            "description": "Auto-incrementing primary key",
            "is_primary_key": True,
            "is_nullable": False,
            "formatting": {
                "display_as": "number",
                "precision": 0
            }
        },
        "run_id": {
            "data_type": DATA_TYPES["BLOB"],
            "unit": UNITS["RAW"],
            "description": "Foreign key to runs table",
            "is_primary_key": False,
            "is_nullable": False,
            "is_foreign_key": True,
            "references": "runs(run_id)",
            "formatting": {
                "display_as": "uuid",
                "max_length": 16
            }
        },
        "timestamp": {
            "data_type": DATA_TYPES["TIMESTAMP"],
            "unit": UNITS["MILLISECONDS"],
            "description": "Timestamp when event occurred",
            "is_primary_key": False,
            "is_nullable": False,
            "formatting": {
                "display_as": "datetime",
                "timezone": "UTC"
            }
        },
        "event_name_id": {
            "data_type": DATA_TYPES["INTEGER"],
            "unit": UNITS["RAW"],
            "description": "Foreign key to event_names table",
            "is_primary_key": False,
            "is_nullable": False,
            "is_foreign_key": True,
            "references": "event_names(id)",
            "formatting": {
                "display_as": "number",
                "precision": 0
            }
        },
        "data": {
            "data_type": DATA_TYPES["TEXT"],
            "unit": UNITS["RAW"],
            "description": "JSON data associated with the event",
            "is_primary_key": False,
            "is_nullable": True,
            "formatting": {
                "display_as": "json",
                "max_length": None
            }
        }
    }
}

# ============================================================================
# METADATA DEFINITIONS
# ============================================================================

METRIC_METADATA: Dict[str, Dict[str, Any]] = {
    "round_coins": {
        "display_name": "Round Coins", 
        "description": "Total coins accumulated during the run.", 
        "unit": UNITS["COINS"],
        "data_type": DATA_TYPES["INTEGER"],
        "formatting": {
            "display_as": "currency",
            "precision": 0,
            "use_commas": True,
            "suffix": " coins"
        }
    },
    "wave_coins": {
        "display_name": "Wave Coins", 
        "description": "Coins generated specifically by the completed wave.", 
        "unit": UNITS["COINS"],
        "data_type": DATA_TYPES["INTEGER"],
        "formatting": {
            "display_as": "currency",
            "precision": 0,
            "use_commas": True,
            "suffix": " coins"
        }
    },
    "coins": {
        "display_name": "Global Coins", 
        "description": "The player's total coin balance, including global multipliers.", 
        "unit": UNITS["COINS"],
        "data_type": DATA_TYPES["INTEGER"],
        "formatting": {
            "display_as": "currency",
            "precision": 0,
            "use_commas": True,
            "suffix": " coins"
        }
    },
    "gems": {
        "display_name": "Total Gems", 
        "description": "The player's total gem balance.", 
        "unit": UNITS["GEMS"],
        "data_type": DATA_TYPES["INTEGER"],
        "formatting": {
            "display_as": "currency",
            "precision": 0,
            "use_commas": True,
            "suffix": " gems"
        }
    },
    "round_cells": {
        "display_name": "Round Cells", 
        "description": "Total cells accumulated during the run.", 
        "unit": UNITS["CELLS"],
        "data_type": DATA_TYPES["INTEGER"],
        "formatting": {
            "display_as": "currency",
            "precision": 0,
            "use_commas": True,
            "suffix": " cells"
        }
    },
    "wave_cells": {
        "display_name": "Wave Cells", 
        "description": "Cells generated specifically by the completed wave.", 
        "unit": UNITS["CELLS"],
        "data_type": DATA_TYPES["INTEGER"],
        "formatting": {
            "display_as": "currency",
            "precision": 0,
            "use_commas": True,
            "suffix": " cells"
        }
    },
    "cells": {
        "display_name": "Global Cells", 
        "description": "The player's total cell balance, including global multipliers.", 
        "unit": UNITS["CELLS"],
        "data_type": DATA_TYPES["INTEGER"],
        "formatting": {
            "display_as": "currency",
            "precision": 0,
            "use_commas": True,
            "suffix": " cells"
        }
    },
    "round_cash": {
        "display_name": "Round Cash", 
        "description": "Total cash accumulated during the run.", 
        "unit": UNITS["CASH"],
        "data_type": DATA_TYPES["INTEGER"],
        "formatting": {
            "display_as": "currency",
            "precision": 0,
            "use_commas": True,
            "suffix": " cash"
        }
    },
    "cash": {
        "display_name": "Global Cash", 
        "description": "The player's total cash balance, including global multipliers.", 
        "unit": UNITS["CASH"],
        "data_type": DATA_TYPES["INTEGER"],
        "formatting": {
            "display_as": "currency",
            "precision": 0,
            "use_commas": True,
            "suffix": " cash"
        }
    },
    "stones": {
        "display_name": "Stones", 
        "description": "Total stones accumulated.", 
        "unit": UNITS["STONES"],
        "data_type": DATA_TYPES["INTEGER"],
        "formatting": {
            "display_as": "currency",
            "precision": 0,
            "use_commas": True,
            "suffix": " stones"
        }
    },
    "round_gems_from_blocks_count": {
        "display_name": "Gem Blocks Tapped (Count)", 
        "description": "Number of times a gem block was tapped.", 
        "unit": UNITS["TAPS"],
        "data_type": DATA_TYPES["COUNT"],
        "formatting": {
            "display_as": "number",
            "precision": 0,
            "use_commas": True,
            "suffix": " taps"
        }
    },
    "round_gems_from_blocks_value": {
        "display_name": "Gems from Blocks", 
        "description": "Total gem value from tapped blocks.", 
        "unit": UNITS["GEMS"],
        "data_type": DATA_TYPES["INTEGER"],
        "formatting": {
            "display_as": "currency",
            "precision": 0,
            "use_commas": True,
            "suffix": " gems"
        }
    },
    "round_gems_from_ads_count": {
        "display_name": "Ad Gems Claimed (Count)", 
        "description": "Number of times gems were claimed from ads.", 
        "unit": UNITS["CLAIMS"],
        "data_type": DATA_TYPES["COUNT"],
        "formatting": {
            "display_as": "number",
            "precision": 0,
            "use_commas": True,
            "suffix": " claims"
        }
    },
    "round_gems_from_ads_value": {
        "display_name": "Gems from Ads", 
        "description": "Total gem value from watching ads.", 
        "unit": UNITS["GEMS"],
        "data_type": DATA_TYPES["INTEGER"],
        "formatting": {
            "display_as": "currency",
            "precision": 0,
            "use_commas": True,
            "suffix": " gems"
        }
    },
    "round_gems_from_guardian": {
        "display_name": "Gems from Guardian", 
        "description": "Total gem value awarded by the Guardian.", 
        "unit": UNITS["GEMS"],
        "data_type": DATA_TYPES["INTEGER"],
        "formatting": {
            "display_as": "currency",
            "precision": 0,
            "use_commas": True,
            "suffix": " gems"
        }
    },
}

EVENT_METADATA: Dict[str, Dict[str, str]] = {
    "startNewRound": {
        "description": "Fired when a new game run begins. Data contains the selected tier."
    },
    "gameOver": {
        "description": "Fired when the run ends. Data contains final summary stats."
    },
    "gemBlockTapped": {
        "description": "User tapped a gem block on the game grid."
    },
    "adGemClaimed": {
        "description": "User claimed gems after watching a rewarded advertisement."
    },
    "gameSpeedChanged": {
        "description": "The game speed multiplier was changed."
    },
    "gamePaused": {
        "description": "The game was paused by the user."
    },
    "gameResumed": {
        "description": "The game was resumed by the user after a pause."
    }
}

# Database metrics metadata (for system monitoring)
DB_METRIC_METADATA: Dict[str, Dict[str, str]] = {
    "total_pages": {
        "description": "Total number of database pages"
    },
    "page_size": {
        "description": "Size of each database page in bytes"
    },
    "database_size": {
        "description": "Total database size in bytes"
    },
    "free_pages": {
        "description": "Number of free pages in database"
    },
    "record_count": {
        "description": "Number of records in table"
    },
    "table_size_bytes": {
        "description": "Table size in bytes"
    },
    "index_count": {
        "description": "Number of user indexes in database"
    }
}

# ============================================================================
# SCHEMA DEFINITIONS
# ============================================================================

# Table creation SQL statements
TABLE_DEFINITIONS: Dict[str, str] = {
    "game_versions": """
        CREATE TABLE IF NOT EXISTS game_versions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            version_text TEXT UNIQUE NOT NULL
        )
    """,
    
    "metric_names": """
        CREATE TABLE IF NOT EXISTS metric_names (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            display_name TEXT,
            description TEXT,
            unit TEXT
        )
    """,
    
    "event_names": """
        CREATE TABLE IF NOT EXISTS event_names (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            description TEXT
        )
    """,
    
    "runs": """
        CREATE TABLE IF NOT EXISTS runs (
            run_id BLOB PRIMARY KEY,
            start_time INTEGER NOT NULL,
            end_time INTEGER,
            duration_realtime INTEGER,
            duration_gametime INTEGER,
            final_wave INTEGER,
            round_coins INTEGER,
            CPH INTEGER,
            round_cells INTEGER,
            round_gems INTEGER,
            round_cash INTEGER,
            tier INTEGER,
            game_version_id INTEGER NOT NULL REFERENCES game_versions(id)
        )
    """,
    
    "metrics": """
        CREATE TABLE IF NOT EXISTS metrics (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id BLOB NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
            real_timestamp INTEGER NOT NULL,
            game_duration INTEGER,
            current_wave INTEGER,
            metric_name_id INTEGER NOT NULL REFERENCES metric_names(id),
            metric_value INTEGER NOT NULL
        )
    """,
    
    "events": """
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id BLOB NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
            timestamp INTEGER NOT NULL,
            event_name_id INTEGER NOT NULL REFERENCES event_names(id),
            data TEXT
        )
    """,
    
    "logs": """
        CREATE TABLE IF NOT EXISTS logs (
            timestamp INTEGER,
            level TEXT,
            source TEXT,
            event TEXT,
            data TEXT
        )
    """,
    
    "settings": """
        CREATE TABLE IF NOT EXISTS settings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key TEXT UNIQUE NOT NULL,
            value TEXT NOT NULL,
            value_type TEXT,
            description TEXT,
            category TEXT,
            is_sensitive INTEGER DEFAULT 0,
            created_at TEXT DEFAULT (datetime('now', 'localtime')),
            updated_at TEXT DEFAULT (datetime('now', 'localtime')),
            created_by TEXT DEFAULT 'system',
            version INTEGER DEFAULT 1
        )
    """,
    
    "dashboards": """
        CREATE TABLE IF NOT EXISTS dashboards (
            id TEXT PRIMARY KEY,
            uid TEXT UNIQUE NOT NULL,
            title TEXT NOT NULL,
            description TEXT,
            config TEXT NOT NULL,
            tags TEXT,
            created_at TEXT DEFAULT (datetime('now', 'localtime')),
            updated_at TEXT DEFAULT (datetime('now', 'localtime')),
            created_by TEXT DEFAULT 'system',
            is_default BOOLEAN DEFAULT 0,
            schema_version INTEGER DEFAULT 1
        )
    """,
    
    "db_metric_names": """
        CREATE TABLE IF NOT EXISTS db_metric_names (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            description TEXT
        )
    """,
    
    "db_monitored_objects": """
        CREATE TABLE IF NOT EXISTS db_monitored_objects (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            type TEXT NOT NULL, -- 'TABLE' or 'INDEX'
            UNIQUE(name, type)
        )
    """,
    
    "db_metrics": """
        CREATE TABLE IF NOT EXISTS db_metrics (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp INTEGER NOT NULL,
            metric_id INTEGER NOT NULL REFERENCES db_metric_names(id),
            object_id INTEGER REFERENCES db_monitored_objects(id),
            value INTEGER NOT NULL
        )
    """
}

# Index creation SQL statements
INDEX_DEFINITIONS: Dict[str, str] = {
    "idx_runs_start_time": "CREATE INDEX IF NOT EXISTS idx_runs_start_time ON runs(start_time)",
    "idx_metrics_run_id_name_time": "CREATE INDEX IF NOT EXISTS idx_metrics_run_id_name_time ON metrics(run_id, metric_name_id, real_timestamp)",
    "idx_events_run_id_time": "CREATE INDEX IF NOT EXISTS idx_events_run_id_time ON events(run_id, timestamp)",
    "idx_settings_key": "CREATE INDEX IF NOT EXISTS idx_settings_key ON settings(key)",
    "idx_settings_category": "CREATE INDEX IF NOT EXISTS idx_settings_category ON settings(category)",
    "idx_dashboards_uid": "CREATE INDEX IF NOT EXISTS idx_dashboards_uid ON dashboards(uid)",
    "idx_dashboards_title": "CREATE INDEX IF NOT EXISTS idx_dashboards_title ON dashboards(title)",
    "idx_db_metrics_time_metric": "CREATE INDEX IF NOT EXISTS idx_db_metrics_time_metric ON db_metrics(timestamp, metric_id)"
}

# ============================================================================
# SCHEMA GENERATION FUNCTIONS
# ============================================================================

def get_full_schema_script() -> str:
    """
    Generate the complete schema creation script.
    
    Returns:
        str: Complete SQL script for creating all tables and indexes
    """
    script_parts = []
    
    # Add all table definitions
    for table_name, table_sql in TABLE_DEFINITIONS.items():
        script_parts.append(table_sql.strip())
    
    # Add all index definitions
    for index_name, index_sql in INDEX_DEFINITIONS.items():
        script_parts.append(index_sql.strip())
    
    return ";\n\n".join(script_parts) + ";"

def get_table_creation_order() -> List[str]:
    """
    Get the recommended order for creating tables (respecting foreign key dependencies).
    
    Returns:
        List[str]: Table names in dependency order
    """
    return [
        "game_versions",
        "metric_names", 
        "event_names",
        "runs",
        "metrics",
        "events",
        "logs",
        "settings",
        "dashboards",
        "db_metric_names",
        "db_monitored_objects",
        "db_metrics"
    ]

def get_tables_to_wipe() -> List[str]:
    """
    Get the list of tables that should be wiped during seeding (excluding system tables).
    
    Returns:
        List[str]: Table names to wipe
    """
    return [
        "events",
        "metrics", 
        "runs",
        "game_versions",
        "metric_names",
        "event_names",
        "db_metrics",
        "db_metric_names", 
        "db_monitored_objects"
    ]

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def validate_schema_consistency() -> Dict[str, Any]:
    """
    Validate that the schema configuration is internally consistent.
    
    Returns:
        Dict[str, Any]: Validation results
    """
    results = {
        "valid": True,
        "errors": [],
        "warnings": []
    }
    
    # Check that all metadata references exist
    table_names = set(TABLE_DEFINITIONS.keys())
    wipe_tables = set(get_tables_to_wipe())
    
    # Warn about tables in wipe list that don't exist in schema
    missing_tables = wipe_tables - table_names
    if missing_tables:
        results["warnings"].append(f"Tables in wipe list but not in schema: {missing_tables}")
    
    # Check for required metadata
    if not METRIC_METADATA:
        results["errors"].append("METRIC_METADATA is empty")
        results["valid"] = False
    
    if not EVENT_METADATA:
        results["errors"].append("EVENT_METADATA is empty") 
        results["valid"] = False
    
    return results

# ============================================================================
# CONFIGURATION SUMMARY
# ============================================================================

def get_schema_info() -> Dict[str, Any]:
    """
    Get summary information about the schema configuration.
    
    Returns:
        Dict[str, Any]: Schema information
    """
    return {
        "schema_version": SCHEMA_VERSION,
        "table_count": len(TABLE_DEFINITIONS),
        "index_count": len(INDEX_DEFINITIONS),
        "metric_metadata_count": len(METRIC_METADATA),
        "event_metadata_count": len(EVENT_METADATA),
        "db_metric_metadata_count": len(DB_METRIC_METADATA),
        "tables": list(TABLE_DEFINITIONS.keys()),
        "indexes": list(INDEX_DEFINITIONS.keys())
    }

# ============================================================================
# DATA CONVERSION AND FORMATTING UTILITIES
# ============================================================================

def get_column_metadata(table_name: str, column_name: str) -> Dict[str, Any]:
    """
    Get metadata for a specific column.
    
    Args:
        table_name: Name of the table
        column_name: Name of the column
        
    Returns:
        Dict containing column metadata or empty dict if not found
    """
    return COLUMN_METADATA.get(table_name, {}).get(column_name, {})

def get_metric_metadata(metric_name: str) -> Dict[str, Any]:
    """
    Get metadata for a specific metric.
    
    Args:
        metric_name: Name of the metric
        
    Returns:
        Dict containing metric metadata or empty dict if not found
    """
    return METRIC_METADATA.get(metric_name, {})

def convert_stored_to_display_value(value: Any, table_name: str, column_name: str) -> Any:
    """
    Convert a stored database value to its display value using column metadata.
    
    Args:
        value: The stored value from the database
        table_name: Name of the table
        column_name: Name of the column
        
    Returns:
        Converted value ready for display
    """
    if value is None:
        return None
        
    metadata = get_column_metadata(table_name, column_name)
    if not metadata:
        return value
        
    # Apply scaling factor if present
    scaling_factor = metadata.get('scaling_factor')
    if scaling_factor and isinstance(value, (int, float)):
        return value / scaling_factor
        
    return value

def convert_display_to_stored_value(value: Any, table_name: str, column_name: str) -> Any:
    """
    Convert a display value to its stored database value using column metadata.
    
    Args:
        value: The display value
        table_name: Name of the table
        column_name: Name of the column
        
    Returns:
        Converted value ready for database storage
    """
    if value is None:
        return None
        
    metadata = get_column_metadata(table_name, column_name)
    if not metadata:
        return value
        
    # Apply scaling factor if present
    scaling_factor = metadata.get('scaling_factor')
    if scaling_factor and isinstance(value, (int, float)):
        return int(value * scaling_factor)
        
    return value

def format_value_for_display(value: Any, table_name: str, column_name: str, 
                           format_type: str = "default") -> str:
    """
    Format a value for display using column metadata and formatting rules.
    
    Args:
        value: The value to format
        table_name: Name of the table
        column_name: Name of the column
        format_type: Type of formatting ("default", "chart", "tooltip")
        
    Returns:
        Formatted string for display
    """
    if value is None:
        return "N/A"
        
    # Convert stored value to display value first
    display_value = convert_stored_to_display_value(value, table_name, column_name)
    
    metadata = get_column_metadata(table_name, column_name)
    if not metadata:
        return str(display_value)
        
    formatting = metadata.get('formatting', {})
    display_as = formatting.get('display_as', 'number')
    
    if display_as == 'currency':
        return _format_currency(display_value, formatting, format_type)
    elif display_as == 'duration':
        return _format_duration(display_value, formatting)
    elif display_as == 'datetime':
        return _format_datetime(display_value, formatting)
    elif display_as == 'number':
        return _format_number(display_value, formatting, format_type)
    elif display_as == 'uuid':
        return _format_uuid(display_value, formatting)
    elif display_as == 'json':
        return _format_json(display_value, formatting)
    else:
        return str(display_value)

def _format_currency(value: float, formatting: Dict[str, Any], format_type: str) -> str:
    """Format a currency value using the existing formatting utilities."""
    precision = formatting.get('precision', 3)
    use_commas = formatting.get('use_commas', True)
    suffix = formatting.get('suffix', '')
    
    # Use the existing format_currency function from utils.py
    try:
        from src.tower_iq.core.utils import format_currency
    except ImportError:
        # Fallback if import fails
        def format_currency(value, symbol="", pad_to_cents=False):
            return f"{value:.2f}"
    
    # Convert to the format expected by the existing function
    if format_type == "chart":
        decimals = 1
    elif format_type == "tooltip":
        decimals = 2
    else:
        decimals = precision
        
    formatted = format_currency(value, symbol="", pad_to_cents=False)
    
    if suffix:
        formatted += f" {suffix}"
        
    return formatted

def _format_duration(value: float, formatting: Dict[str, Any]) -> str:
    """Format a duration value."""
    try:
        from src.tower_iq.core.utils import format_duration
        return format_duration(value)
    except ImportError:
        # Fallback if import fails
        seconds = int(value)
        days, rem = divmod(seconds, 86400)
        hours, rem = divmod(rem, 3600)
        minutes, secs = divmod(rem, 60)
        if days > 0:
            return f"{days:02}:{hours:02}:{minutes:02}:{secs:02}"
        else:
            return f"{hours:02}:{minutes:02}:{secs:02}"

def _format_datetime(value: int, formatting: Dict[str, Any]) -> str:
    """Format a datetime value."""
    from datetime import datetime
    try:
        import pytz
    except ImportError:
        pytz = None
    
    # Convert milliseconds to seconds if needed
    if value > 1e12:  # Likely milliseconds
        value = value / 1000
        
    dt = datetime.fromtimestamp(value)
    timezone = formatting.get('timezone', 'UTC')
    
    if timezone != 'UTC' and pytz:
        tz = pytz.timezone(timezone)
        dt = dt.replace(tzinfo=pytz.UTC).astimezone(tz)
    
    return dt.strftime('%Y-%m-%d %H:%M:%S')

def _format_number(value: float, formatting: Dict[str, Any], format_type: str) -> str:
    """Format a number value."""
    precision = formatting.get('precision', 0)
    use_commas = formatting.get('use_commas', False)
    suffix = formatting.get('suffix', '')
    
    if format_type == "chart":
        precision = min(precision, 1)
    
    if precision > 0:
        formatted = f"{value:.{precision}f}"
    else:
        formatted = f"{int(value)}"
        
    if use_commas and abs(value) >= 1000:
        # Add comma separators
        parts = formatted.split('.')
        parts[0] = f"{int(parts[0]):,}"
        formatted = '.'.join(parts)
        
    if suffix:
        formatted += f" {suffix}"
        
    return formatted

def _format_uuid(value: bytes, formatting: Dict[str, Any]) -> str:
    """Format a UUID value."""
    import uuid
    try:
        return str(uuid.UUID(bytes=value))
    except (ValueError, TypeError):
        return str(value)

def _format_json(value: str, formatting: Dict[str, Any]) -> str:
    """Format a JSON value."""
    import json
    try:
        parsed = json.loads(value)
        return json.dumps(parsed, indent=2)
    except (json.JSONDecodeError, TypeError):
        return str(value)

def get_scaling_factor(table_name: str, column_name: str) -> int:
    """
    Get the scaling factor for a column.
    
    Args:
        table_name: Name of the table
        column_name: Name of the column
        
    Returns:
        Scaling factor (default: 1)
    """
    metadata = get_column_metadata(table_name, column_name)
    return metadata.get('scaling_factor', 1)

def get_unit(table_name: str, column_name: str) -> str:
    """
    Get the unit for a column.
    
    Args:
        table_name: Name of the table
        column_name: Name of the column
        
    Returns:
        Unit string
    """
    metadata = get_column_metadata(table_name, column_name)
    return metadata.get('unit', 'raw')

def get_data_type(table_name: str, column_name: str) -> str:
    """
    Get the data type for a column.
    
    Args:
        table_name: Name of the table
        column_name: Name of the column
        
    Returns:
        Data type string
    """
    metadata = get_column_metadata(table_name, column_name)
    return metadata.get('data_type', 'integer')

def validate_column_metadata() -> Dict[str, Any]:
    """
    Validate that all column metadata is consistent and complete.
    
    Returns:
        Dict containing validation results
    """
    results = {
        "valid": True,
        "errors": [],
        "warnings": []
    }
    
    # Check that all tables in COLUMN_METADATA exist in TABLE_DEFINITIONS
    for table_name in COLUMN_METADATA.keys():
        if table_name not in TABLE_DEFINITIONS:
            results["errors"].append(f"Table '{table_name}' in COLUMN_METADATA but not in TABLE_DEFINITIONS")
            results["valid"] = False
    
    # Check that all columns have required metadata
    required_fields = ['data_type', 'unit', 'description']
    for table_name, columns in COLUMN_METADATA.items():
        for column_name, metadata in columns.items():
            for field in required_fields:
                if field not in metadata:
                    results["warnings"].append(f"Column '{table_name}.{column_name}' missing required field '{field}'")
    
    return results
