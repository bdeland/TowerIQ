import { useState, useEffect, useCallback } from 'react';
import { API_CONFIG } from '../config/environment';

// Global state for drawer width - shared across all instances
let globalDrawerWidth = 500; // Default width
let isLoading = false;
let hasLoaded = false;
const listeners = new Set<(width: number) => void>();

// Subscribe to width changes
const subscribe = (listener: (width: number) => void) => {
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
};

// Notify all listeners of width changes
const notifyListeners = (width: number) => {
  globalDrawerWidth = width;
  listeners.forEach(listener => listener(width));
};

// Load width from database
const loadDrawerWidth = async (): Promise<number> => {
  if (hasLoaded) return globalDrawerWidth;
  if (isLoading) return globalDrawerWidth;
  
  isLoading = true;
  try {
    const response = await fetch(`${API_CONFIG.BASE_URL}/settings/get/ui.debug_drawer.width`);
    if (response.ok) {
      const data = await response.json();
      if (data.value && typeof data.value === 'number') {
        const width = Math.max(300, Math.min(1200, data.value));
        notifyListeners(width);
        hasLoaded = true;
        return width;
      }
    }
  } catch (error) {
    if (import.meta.env.DEV) {
      console.log('Failed to load drawer width setting:', error);
    }
  } finally {
    isLoading = false;
    hasLoaded = true;
  }
  
  return globalDrawerWidth;
};

// Save width to database
const saveDrawerWidth = async (width: number): Promise<void> => {
  try {
    await fetch(`${API_CONFIG.BASE_URL}/settings/set`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ 
        key: 'ui.debug_drawer.width', 
        value: width 
      }),
    });
    notifyListeners(width);
  } catch (error) {
    if (import.meta.env.DEV) {
      console.log('Failed to save drawer width setting:', error);
    }
  }
};

/**
 * Hook for managing debug drawer width globally
 * Provides consistent width across all drawer instances
 */
export const useDebugDrawerWidth = () => {
  const [drawerWidth, setDrawerWidth] = useState(globalDrawerWidth);

  // Subscribe to global width changes
  useEffect(() => {
    const unsubscribe = subscribe(setDrawerWidth);
    
    // Load initial width if not already loaded
    if (!hasLoaded) {
      loadDrawerWidth().then(width => {
        if (width !== drawerWidth) {
          setDrawerWidth(width);
        }
      });
    }
    
    return unsubscribe;
  }, [drawerWidth]);

  // Update drawer width (local and global)
  const updateDrawerWidth = useCallback((width: number) => {
    setDrawerWidth(width);
    notifyListeners(width);
  }, []);

  // Save drawer width to database
  const persistDrawerWidth = useCallback(async (width: number) => {
    await saveDrawerWidth(width);
  }, []);

  return {
    drawerWidth,
    updateDrawerWidth,
    persistDrawerWidth,
    DEFAULT_WIDTH: 500,
    SNAP_THRESHOLD: 30
  };
};
