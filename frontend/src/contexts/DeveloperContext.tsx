import { createContext, useContext, useState, useEffect, ReactNode } from 'react';
import { API_CONFIG } from '../config/environment';

interface DebugBorderSettings {
  gridContainer: {
    enabled: boolean;
    color: string;
  };
  panels: {
    enabled: boolean;
    color: string;
  };
  gridCells: {
    enabled: boolean;
    color: string;
  };
}

interface DeveloperContextType {
  isDevMode: boolean;
  debugBorders: boolean; // Legacy - kept for backward compatibility
  debugBorderSettings: DebugBorderSettings;
  breadcrumbCopy: boolean;
  minPanelLoadingMs: number;
  toggleDevMode: () => void;
  setDevMode: (enabled: boolean) => void;
  setDebugBorders: (enabled: boolean) => void; // Legacy - kept for backward compatibility
  setDebugBorderSettings: (settings: Partial<DebugBorderSettings>) => void;
  setBreadcrumbCopy: (enabled: boolean) => void;
  setMinPanelLoadingMs: (milliseconds: number) => void;
}

interface DeveloperProviderProps {
  children: ReactNode;
}

const DEFAULT_DEBUG_BORDERS = true;
const DEFAULT_BREADCRUMB_COPY = true;
const DEFAULT_MIN_LOADING_MS = 100;

// Default colors from the specified palette
const DEFAULT_DEBUG_BORDER_SETTINGS: DebugBorderSettings = {
  gridContainer: {
    enabled: true,
    color: '#003f5c', // Dark blue
  },
  panels: {
    enabled: true,
    color: '#f95d6a', // Pink/red
  },
  gridCells: {
    enabled: true,
    color: '#ffa600', // Orange
  },
};

const SETTINGS_KEYS = {
  devMode: 'developer.mode.enabled',
  debugBorders: 'developer.features.debugBorders',
  breadcrumbCopy: 'developer.features.breadcrumbCopy',
  minLoading: 'developer.features.minPanelLoadingMs',
  // New individual border settings
  gridContainerEnabled: 'developer.borders.gridContainer.enabled',
  gridContainerColor: 'developer.borders.gridContainer.color',
  panelsEnabled: 'developer.borders.panels.enabled',
  panelsColor: 'developer.borders.panels.color',
  gridCellsEnabled: 'developer.borders.gridCells.enabled',
  gridCellsColor: 'developer.borders.gridCells.color',
} as const;

const DeveloperContext = createContext<DeveloperContextType | undefined>(undefined);

const toBoolean = (value: unknown, fallback: boolean): boolean => {
  if (typeof value === 'boolean') {
    return value;
  }

  if (typeof value === 'string') {
    const normalized = value.toLowerCase();
    if (normalized === 'true') return true;
    if (normalized === 'false') return false;
  }

  if (typeof value === 'number') {
    return value === 1;
  }

  return fallback;
};

const toNumber = (value: unknown, fallback: number): number => {
  if (typeof value === 'number' && Number.isFinite(value)) {
    return value;
  }

  if (typeof value === 'string') {
    const parsed = Number(value);
    if (Number.isFinite(parsed)) {
      return parsed;
    }
  }

  return fallback;
};

const toString = (value: unknown, fallback: string): string => {
  if (typeof value === 'string') {
    return value;
  }
  return fallback;
};

async function loadSetting<T>(key: string): Promise<T | undefined> {
  const response = await fetch(`${API_CONFIG.BASE_URL}/settings/get/${key}`);
  if (!response.ok) {
    throw new Error(`Failed to load setting: ${key} (${response.status})`);
  }
  const data = await response.json();
  return data.value as T;
}

const persistSetting = (key: string, value: boolean | number | string, revert: () => void) => {
  fetch(`${API_CONFIG.BASE_URL}/settings/set`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ key, value }),
  }).then(response => {
    if (!response.ok) {
      throw new Error(`Failed to save setting: ${key} (${response.status})`);
    }
  }).catch(error => {
    console.error(`Failed to persist setting '${key}':`, error);
    revert();
  });
};

export function DeveloperProvider({ children }: DeveloperProviderProps) {
  const [isDevMode, setIsDevMode] = useState(false);
  const [debugBorders, setDebugBordersState] = useState(DEFAULT_DEBUG_BORDERS);
  const [debugBorderSettings, setDebugBorderSettingsState] = useState(DEFAULT_DEBUG_BORDER_SETTINGS);
  const [breadcrumbCopy, setBreadcrumbCopyState] = useState(DEFAULT_BREADCRUMB_COPY);
  const [minPanelLoadingMs, setMinPanelLoadingMsState] = useState(DEFAULT_MIN_LOADING_MS);

  useEffect(() => {
    let isCancelled = false;

    const loadBooleanSetting = async (
      key: string,
      setter: (value: boolean) => void,
      fallback: boolean
    ) => {
      try {
        const value = await loadSetting<unknown>(key);
        if (!isCancelled) {
          setter(toBoolean(value, fallback));
        }
      } catch (error) {
        console.warn(`Failed to load boolean setting '${key}':`, error);
        if (!isCancelled) {
          setter(fallback);
        }
      }
    };

    const loadNumberSetting = async (
      key: string,
      setter: (value: number) => void,
      fallback: number
    ) => {
      try {
        const value = await loadSetting<unknown>(key);
        if (!isCancelled) {
          setter(Math.max(0, toNumber(value, fallback)));
        }
      } catch (error) {
        console.warn(`Failed to load numeric setting '${key}':`, error);
        if (!isCancelled) {
          setter(fallback);
        }
      }
    };

    const loadStringSetting = async (
      key: string,
      setter: (value: string) => void,
      fallback: string
    ) => {
      try {
        const value = await loadSetting<unknown>(key);
        if (!isCancelled) {
          setter(toString(value, fallback));
        }
      } catch (error) {
        console.warn(`Failed to load string setting '${key}':`, error);
        if (!isCancelled) {
          setter(fallback);
        }
      }
    };

    loadBooleanSetting(SETTINGS_KEYS.devMode, setIsDevMode, false);
    loadBooleanSetting(SETTINGS_KEYS.debugBorders, setDebugBordersState, DEFAULT_DEBUG_BORDERS);
    loadBooleanSetting(SETTINGS_KEYS.breadcrumbCopy, setBreadcrumbCopyState, DEFAULT_BREADCRUMB_COPY);
    loadNumberSetting(SETTINGS_KEYS.minLoading, setMinPanelLoadingMsState, DEFAULT_MIN_LOADING_MS);

    // Load individual debug border settings
    const loadDebugBorderSettings = async () => {
      const newSettings = { ...DEFAULT_DEBUG_BORDER_SETTINGS };
      
      try {
        const [
          gridContainerEnabled,
          gridContainerColor,
          panelsEnabled,
          panelsColor,
          gridCellsEnabled,
          gridCellsColor
        ] = await Promise.all([
          loadSetting<unknown>(SETTINGS_KEYS.gridContainerEnabled),
          loadSetting<unknown>(SETTINGS_KEYS.gridContainerColor),
          loadSetting<unknown>(SETTINGS_KEYS.panelsEnabled),
          loadSetting<unknown>(SETTINGS_KEYS.panelsColor),
          loadSetting<unknown>(SETTINGS_KEYS.gridCellsEnabled),
          loadSetting<unknown>(SETTINGS_KEYS.gridCellsColor)
        ]);

        newSettings.gridContainer.enabled = toBoolean(gridContainerEnabled, DEFAULT_DEBUG_BORDER_SETTINGS.gridContainer.enabled);
        newSettings.gridContainer.color = toString(gridContainerColor, DEFAULT_DEBUG_BORDER_SETTINGS.gridContainer.color);
        newSettings.panels.enabled = toBoolean(panelsEnabled, DEFAULT_DEBUG_BORDER_SETTINGS.panels.enabled);
        newSettings.panels.color = toString(panelsColor, DEFAULT_DEBUG_BORDER_SETTINGS.panels.color);
        newSettings.gridCells.enabled = toBoolean(gridCellsEnabled, DEFAULT_DEBUG_BORDER_SETTINGS.gridCells.enabled);
        newSettings.gridCells.color = toString(gridCellsColor, DEFAULT_DEBUG_BORDER_SETTINGS.gridCells.color);

        if (!isCancelled) {
          setDebugBorderSettingsState(newSettings);
        }
      } catch (error) {
        console.warn('Failed to load debug border settings:', error);
        if (!isCancelled) {
          setDebugBorderSettingsState(DEFAULT_DEBUG_BORDER_SETTINGS);
        }
      }
    };

    loadDebugBorderSettings();

    return () => {
      isCancelled = true;
    };
  }, []);

  const toggleDevMode = () => {
    const previousValue = isDevMode;
    const newValue = !previousValue;
    setIsDevMode(newValue);
    persistSetting(SETTINGS_KEYS.devMode, newValue, () => setIsDevMode(previousValue));
  };

  const setDevMode = (enabled: boolean) => {
    const previousValue = isDevMode;
    setIsDevMode(enabled);
    persistSetting(SETTINGS_KEYS.devMode, enabled, () => setIsDevMode(previousValue));
  };

  const setDebugBorders = (enabled: boolean) => {
    const previousValue = debugBorders;
    setDebugBordersState(enabled);
    persistSetting(SETTINGS_KEYS.debugBorders, enabled, () => setDebugBordersState(previousValue));
  };

  const setBreadcrumbCopy = (enabled: boolean) => {
    const previousValue = breadcrumbCopy;
    setBreadcrumbCopyState(enabled);
    persistSetting(SETTINGS_KEYS.breadcrumbCopy, enabled, () => setBreadcrumbCopyState(previousValue));
  };

  const setMinPanelLoadingMs = (milliseconds: number) => {
    const previousValue = minPanelLoadingMs;
    const normalizedValue = Number.isFinite(milliseconds)
      ? Math.max(0, Math.floor(milliseconds))
      : previousValue;

    setMinPanelLoadingMsState(normalizedValue);
    persistSetting(SETTINGS_KEYS.minLoading, normalizedValue, () => setMinPanelLoadingMsState(previousValue));
  };

  const setDebugBorderSettings = (newSettings: Partial<DebugBorderSettings>) => {
    const previousSettings = debugBorderSettings;
    const updatedSettings = {
      ...debugBorderSettings,
      ...newSettings,
      // Handle nested updates properly
      gridContainer: { ...debugBorderSettings.gridContainer, ...newSettings.gridContainer },
      panels: { ...debugBorderSettings.panels, ...newSettings.panels },
      gridCells: { ...debugBorderSettings.gridCells, ...newSettings.gridCells },
    };

    setDebugBorderSettingsState(updatedSettings);

    // Persist each setting individually
    const persistPromises: Promise<void>[] = [];
    
    if (newSettings.gridContainer?.enabled !== undefined) {
      persistPromises.push(
        new Promise<void>((resolve, reject) => {
          persistSetting(SETTINGS_KEYS.gridContainerEnabled, updatedSettings.gridContainer.enabled, () => {
            setDebugBorderSettingsState(previousSettings);
            reject();
          });
          resolve();
        })
      );
    }
    
    if (newSettings.gridContainer?.color !== undefined) {
      persistPromises.push(
        new Promise<void>((resolve, reject) => {
          persistSetting(SETTINGS_KEYS.gridContainerColor, updatedSettings.gridContainer.color, () => {
            setDebugBorderSettingsState(previousSettings);
            reject();
          });
          resolve();
        })
      );
    }
    
    if (newSettings.panels?.enabled !== undefined) {
      persistPromises.push(
        new Promise<void>((resolve, reject) => {
          persistSetting(SETTINGS_KEYS.panelsEnabled, updatedSettings.panels.enabled, () => {
            setDebugBorderSettingsState(previousSettings);
            reject();
          });
          resolve();
        })
      );
    }
    
    if (newSettings.panels?.color !== undefined) {
      persistPromises.push(
        new Promise<void>((resolve, reject) => {
          persistSetting(SETTINGS_KEYS.panelsColor, updatedSettings.panels.color, () => {
            setDebugBorderSettingsState(previousSettings);
            reject();
          });
          resolve();
        })
      );
    }
    
    if (newSettings.gridCells?.enabled !== undefined) {
      persistPromises.push(
        new Promise<void>((resolve, reject) => {
          persistSetting(SETTINGS_KEYS.gridCellsEnabled, updatedSettings.gridCells.enabled, () => {
            setDebugBorderSettingsState(previousSettings);
            reject();
          });
          resolve();
        })
      );
    }
    
    if (newSettings.gridCells?.color !== undefined) {
      persistPromises.push(
        new Promise<void>((resolve, reject) => {
          persistSetting(SETTINGS_KEYS.gridCellsColor, updatedSettings.gridCells.color, () => {
            setDebugBorderSettingsState(previousSettings);
            reject();
          });
          resolve();
        })
      );
    }

    // Wait for all persistence operations to complete
    Promise.all(persistPromises).catch(error => {
      console.error('Failed to persist debug border settings:', error);
    });
  };

  return (
    <DeveloperContext.Provider
      value={{
        isDevMode,
        debugBorders,
        debugBorderSettings,
        breadcrumbCopy,
        minPanelLoadingMs,
        toggleDevMode,
        setDevMode,
        setDebugBorders,
        setDebugBorderSettings,
        setBreadcrumbCopy,
        setMinPanelLoadingMs,
      }}
    >
      {children}
    </DeveloperContext.Provider>
  );
}

export function useDeveloper() {
  const context = useContext(DeveloperContext);
  if (context === undefined) {
    throw new Error('useDeveloper must be used within a DeveloperProvider');
  }
  return context;
}

