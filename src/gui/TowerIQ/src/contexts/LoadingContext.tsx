import React, { createContext, useContext, useState, useEffect } from 'react';

interface LoadingState {
  [key: string]: boolean;
}

interface LoadingContextType {
  setComponentLoaded: (componentName: string) => void;
  isAllLoaded: boolean;
}

const LoadingContext = createContext<LoadingContextType | undefined>(undefined);

interface LoadingProviderProps {
  children: React.ReactNode;
  requiredComponents: string[];
}

export const LoadingProvider: React.FC<LoadingProviderProps> = ({ 
  children, 
  requiredComponents 
}) => {
  const [loadingState, setLoadingState] = useState<LoadingState>({});
  const [isAllLoaded, setIsAllLoaded] = useState(false);

  const setComponentLoaded = (componentName: string) => {
    setLoadingState(prev => ({
      ...prev,
      [componentName]: true
    }));
  };

  useEffect(() => {
    // Check if all required components are loaded
    const allLoaded = requiredComponents.every(component => loadingState[component]);
    
    if (allLoaded && !isAllLoaded) {
      setIsAllLoaded(true);
      
      // Hide splash screen after a small delay to ensure smooth transition
      setTimeout(() => {
        if ((window as any).hideSplashScreen) {
          (window as any).hideSplashScreen();
        }
      }, 100);
    }
  }, [loadingState, requiredComponents, isAllLoaded]);

  return (
    <LoadingContext.Provider value={{ setComponentLoaded, isAllLoaded }}>
      {children}
    </LoadingContext.Provider>
  );
};

export const useLoading = () => {
  const context = useContext(LoadingContext);
  if (context === undefined) {
    throw new Error('useLoading must be used within a LoadingProvider');
  }
  return context;
};
