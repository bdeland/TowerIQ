import React, { createContext, useContext, useState, useEffect, ReactNode } from 'react';
import { API_CONFIG } from '../config/environment';

interface VariableState {
  selectedValues: Record<string, any>;
  options: Record<string, Array<{ label: string; value: any }>>;
  isLoading: boolean;
}

interface DashboardVariableContextType extends VariableState {
  updateVariable: (name: string, value: any) => void;
}

const DashboardVariableContext = createContext<DashboardVariableContextType | undefined>(undefined);

export const DashboardVariableProvider = ({ children }: { children: ReactNode }) => {
  const [state, setState] = useState<VariableState>({
    selectedValues: { tier: ['all'], num_runs: 10 },
    options: {
      tier: [{ label: 'All', value: 'all' }],
      num_runs: [
        { label: 'All', value: 'all' }, 
        { label: '1', value: 1 }, 
        { label: '5', value: 5 },
        { label: '10', value: 10 }, 
        { label: '15', value: 15 }, 
        { label: '25', value: 25 }, 
        { label: '50', value: 50 }
      ],
    },
    isLoading: true,
  });

  useEffect(() => {
    const fetchTierOptions = async () => {
      const tierQuery = "SELECT DISTINCT tier FROM runs WHERE tier IS NOT NULL ORDER BY tier ASC";
      try {
        const response = await fetch(`${API_CONFIG.BASE_URL}/query`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ query: tierQuery }),
        });
        
        if (!response.ok) {
          throw new Error(`Query failed: ${response.statusText}`);
        }
        
        const result = await response.json();
        const tierOptions = result.data.map((row: { tier: number }) => ({
          label: `${row.tier}`,
          value: row.tier,
        }));
        const finalOptions = [{ label: 'All', value: 'all' }, ...tierOptions];
        
        setState(prev => ({ 
          ...prev, 
          options: { ...prev.options, tier: finalOptions }, 
          isLoading: false 
        }));
      } catch (error) {
        console.error("Failed to fetch tier options:", error);
        setState(prev => ({ ...prev, isLoading: false }));
      }
    };
    
    fetchTierOptions();
  }, []);

  const updateVariable = (name: string, value: any) => {
    setState(prev => {
      let newValue = value;
      
      // Special handling for multiselect with "all" option
      if (Array.isArray(value)) {
        const options = prev.options[name] || [];
        const allOption = options.find(opt => opt.value === 'all');
        const nonAllOptions = options.filter(opt => opt.value !== 'all');
        
        if (allOption) {
          // If "All" was just selected, select all options
          if (value.includes('all') && !prev.selectedValues[name]?.includes('all')) {
            newValue = ['all', ...nonAllOptions.map(opt => opt.value)];
          }
          // If "All" was deselected, deselect everything
          else if (!value.includes('all') && prev.selectedValues[name]?.includes('all')) {
            newValue = [];
          }
          // If all individual options are selected, also select "All"
          else if (!value.includes('all') && nonAllOptions.length > 0 && 
                   nonAllOptions.every(opt => value.includes(opt.value))) {
            newValue = ['all', ...value];
          }
          // If not all individual options are selected, make sure "All" is not selected
          else if (value.includes('all') && nonAllOptions.length > 0 && 
                   !nonAllOptions.every(opt => value.includes(opt.value))) {
            newValue = value.filter(v => v !== 'all');
          }
        }
      }
      
      return { 
        ...prev, 
        selectedValues: { ...prev.selectedValues, [name]: newValue } 
      };
    });
  };

  return (
    <DashboardVariableContext.Provider value={{ ...state, updateVariable }}>
      {children}
    </DashboardVariableContext.Provider>
  );
};

export const useDashboardVariable = () => {
  const context = useContext(DashboardVariableContext);
  if (!context) {
    throw new Error('useDashboardVariable must be used within a DashboardVariableProvider');
  }
  return context;
};
