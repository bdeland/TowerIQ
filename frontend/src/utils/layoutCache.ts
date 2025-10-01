// Layout cache utility to persist grid layouts and prevent unnecessary recalculations
interface LayoutItem {
  i: string;
  x: number;
  y: number;
  w: number;
  h: number;
}

interface LayoutCache {
  [dashboardId: string]: {
    [breakpoint: string]: LayoutItem[];
  };
}

class LayoutCacheManager {
  private cache: LayoutCache = {};
  private readonly CACHE_KEY = 'toweriq-dashboard-layouts';

  constructor() {
    this.loadFromStorage();
  }

  private loadFromStorage(): void {
    try {
      const stored = localStorage.getItem(this.CACHE_KEY);
      if (stored) {
        this.cache = JSON.parse(stored);
      }
    } catch (error) {
      console.warn('Failed to load layout cache from localStorage:', error);
      this.cache = {};
    }
  }

  private saveToStorage(): void {
    try {
      localStorage.setItem(this.CACHE_KEY, JSON.stringify(this.cache));
    } catch (error) {
      console.warn('Failed to save layout cache to localStorage:', error);
    }
  }

  getLayout(dashboardId: string, breakpoint: string = 'lg'): LayoutItem[] | null {
    return this.cache[dashboardId]?.[breakpoint] || null;
  }

  setLayout(dashboardId: string, breakpoint: string, layout: LayoutItem[]): void {
    if (!this.cache[dashboardId]) {
      this.cache[dashboardId] = {};
    }
    this.cache[dashboardId][breakpoint] = layout;
    this.saveToStorage();
  }

  clearLayout(dashboardId: string): void {
    delete this.cache[dashboardId];
    this.saveToStorage();
  }

  clearAllLayouts(): void {
    this.cache = {};
    this.saveToStorage();
  }

  // Check if a layout exists for a dashboard
  hasLayout(dashboardId: string, breakpoint: string = 'lg'): boolean {
    return this.cache[dashboardId]?.[breakpoint] !== undefined;
  }

  // Get all layouts for a dashboard
  getAllLayouts(dashboardId: string): { [breakpoint: string]: LayoutItem[] } | null {
    return this.cache[dashboardId] || null;
  }
}

// Export singleton instance
export const layoutCache = new LayoutCacheManager();

// Helper function to convert panel grid positions to layout items
export function panelsToLayout(panels: any[]): LayoutItem[] {
  return panels.map(panel => ({
    i: panel.id,
    x: panel.gridPos.x,
    y: panel.gridPos.y,
    w: panel.gridPos.w,
    h: panel.gridPos.h
  }));
}

// Helper function to check if two layouts are equivalent
export function layoutsEqual(layout1: LayoutItem[], layout2: LayoutItem[]): boolean {
  if (layout1.length !== layout2.length) return false;
  
  return layout1.every(item1 => {
    const item2 = layout2.find(item => item.i === item1.i);
    return item2 && 
           item1.x === item2.x && 
           item1.y === item2.y && 
           item1.w === item2.w && 
           item1.h === item2.h;
  });
}
