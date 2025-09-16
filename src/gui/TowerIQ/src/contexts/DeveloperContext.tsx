import { createContext, useContext, useState, useEffect, ReactNode } from 'react';
import { API_CONFIG } from '../config/environment';

interface DeveloperContextType {
  isDevMode: boolean;
  toggleDevMode: () => void;
  setDevMode: (enabled: boolean) => void;
}

const DeveloperContext = createContext<DeveloperContextType | undefined>(undefined);

interface DeveloperProviderProps {
  children: ReactNode;
}

export function DeveloperProvider({ children }: DeveloperProviderProps) {
  const [isDevMode, setIsDevMode] = useState(false);

  // Load dev mode setting on mount
  useEffect(() => {
    const loadDevModeSetting = async () => {
      try {
        const response = await fetch(`${API_CONFIG.BASE_URL}/settings/get/developer.mode.enabled`);
        if (response.ok) {
          const data = await response.json();
          setIsDevMode(data.value === true || data.value === 'true');
        }
      } catch (error) {
        console.warn('Failed to load development mode setting:', error);
        // Default to false if loading fails
        setIsDevMode(false);
      }
    };

    loadDevModeSetting();
  }, []);

  const toggleDevMode = async () => {
    const newValue = !isDevMode;
    setIsDevMode(newValue);
    
    // Persist the setting
    try {
      await fetch(`${API_CONFIG.BASE_URL}/settings/set`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          key: 'developer.mode.enabled',
          value: newValue
        }),
      });
    } catch (error) {
      console.error('Failed to save development mode setting:', error);
      // Revert the state if save fails
      setIsDevMode(!newValue);
    }
  };

  const setDevMode = async (enabled: boolean) => {
    setIsDevMode(enabled);
    
    // Persist the setting
    try {
      await fetch(`${API_CONFIG.BASE_URL}/settings/set`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          key: 'developer.mode.enabled',
          value: enabled
        }),
      });
    } catch (error) {
      console.error('Failed to save development mode setting:', error);
      // Revert the state if save fails
      setIsDevMode(!enabled);
    }
  };

  return (
    <DeveloperContext.Provider value={{ isDevMode, toggleDevMode, setDevMode }}>
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