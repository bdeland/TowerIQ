import { createContext, useContext, useState, useEffect, ReactNode } from 'react';
import { API_CONFIG } from '../config/environment';

interface DeveloperContextType {
  isDevMode: boolean;
  debugBorders: boolean;
  breadcrumbCopy: boolean;
  minPanelLoadingMs: number;
  toggleDevMode: () => void;
  setDevMode: (enabled: boolean) => void;
  setDebugBorders: (enabled: boolean) => void;
  setBreadcrumbCopy: (enabled: boolean) => void;
  setMinPanelLoadingMs: (milliseconds: number) => void;
}

interface DeveloperProviderProps {
  children: ReactNode;
}

const DEFAULT_DEBUG_BORDERS = true;
const DEFAULT_BREADCRUMB_COPY = true;
const DEFAULT_MIN_LOADING_MS = 100;

const SETTINGS_KEYS = {
  devMode: 'developer.mode.enabled',
  debugBorders: 'developer.features.debugBorders',
  breadcrumbCopy: 'developer.features.breadcrumbCopy',
  minLoading: 'developer.features.minPanelLoadingMs',
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

async function loadSetting<T>(key: string): Promise<T | undefined> {
  const response = await fetch(`${API_CONFIG.BASE_URL}/settings/get/${key}`);
  if (!response.ok) {
    throw new Error(`Failed to load setting: ${key} (${response.status})`);
  }
  const data = await response.json();
  return data.value as T;
}

const persistSetting = (key: string, value: boolean | number, revert: () => void) => {
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

    loadBooleanSetting(SETTINGS_KEYS.devMode, setIsDevMode, false);
    loadBooleanSetting(SETTINGS_KEYS.debugBorders, setDebugBordersState, DEFAULT_DEBUG_BORDERS);
    loadBooleanSetting(SETTINGS_KEYS.breadcrumbCopy, setBreadcrumbCopyState, DEFAULT_BREADCRUMB_COPY);
    loadNumberSetting(SETTINGS_KEYS.minLoading, setMinPanelLoadingMsState, DEFAULT_MIN_LOADING_MS);

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

  return (
    <DeveloperContext.Provider
      value={{
        isDevMode,
        debugBorders,
        breadcrumbCopy,
        minPanelLoadingMs,
        toggleDevMode,
        setDevMode,
        setDebugBorders,
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

