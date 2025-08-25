import React, { createContext, useContext, useState, useCallback, useMemo, ReactNode } from 'react';

interface DashboardEditContextType {
  isDashboardPage: boolean;
  isEditMode: boolean;
  saving: boolean;
  setIsDashboardPage: (value: boolean) => void;
  setIsEditMode: (value: boolean) => void;
  setSaving: (value: boolean) => void;
  onEditToggle?: () => void;
  onAddVisualization?: () => void;
  onAddRow?: () => void;
  onPastePanel?: () => void;
  onSave?: () => void;
  onSaveAsCopy?: () => void;
  setEditHandlers: (handlers: {
    onEditToggle: () => void;
    onAddVisualization: () => void;
    onAddRow: () => void;
    onPastePanel: () => void;
    onSave: () => void;
    onSaveAsCopy: () => void;
  }) => void;
}

const DashboardEditContext = createContext<DashboardEditContextType | undefined>(undefined);

export const useDashboardEdit = () => {
  const context = useContext(DashboardEditContext);
  if (context === undefined) {
    // Provide safe defaults when context is not available
    console.warn('useDashboardEdit called outside of DashboardEditProvider');
    return {
      isDashboardPage: false,
      isEditMode: false,
      saving: false,
      setIsDashboardPage: () => {},
      setIsEditMode: () => {},
      setSaving: () => {},
      onEditToggle: undefined,
      onAddVisualization: undefined,
      onAddRow: undefined,
      onPastePanel: undefined,
      onSave: undefined,
      onSaveAsCopy: undefined,
      setEditHandlers: () => {},
    };
  }
  return context;
};

interface DashboardEditProviderProps {
  children: ReactNode;
}

export const DashboardEditProvider: React.FC<DashboardEditProviderProps> = ({ children }) => {
  const [isDashboardPage, setIsDashboardPage] = useState(false);
  const [isEditMode, setIsEditMode] = useState(false);
  const [saving, setSaving] = useState(false);
  const [editHandlers, setEditHandlers] = useState<{
    onEditToggle?: () => void;
    onAddVisualization?: () => void;
    onAddRow?: () => void;
    onPastePanel?: () => void;
    onSave?: () => void;
    onSaveAsCopy?: () => void;
  }>({});

  const handleSetEditHandlers = useCallback((handlers: {
    onEditToggle: () => void;
    onAddVisualization: () => void;
    onAddRow: () => void;
    onPastePanel: () => void;
    onSave: () => void;
    onSaveAsCopy: () => void;
  }) => {
    setEditHandlers(handlers);
  }, []);

  const value: DashboardEditContextType = useMemo(() => ({
    isDashboardPage,
    isEditMode,
    saving,
    setIsDashboardPage,
    setIsEditMode,
    setSaving,
    onEditToggle: editHandlers.onEditToggle,
    onAddVisualization: editHandlers.onAddVisualization,
    onAddRow: editHandlers.onAddRow,
    onPastePanel: editHandlers.onPastePanel,
    onSave: editHandlers.onSave,
    onSaveAsCopy: editHandlers.onSaveAsCopy,
    setEditHandlers: handleSetEditHandlers,
  }), [
    isDashboardPage,
    isEditMode,
    saving,
    editHandlers.onEditToggle,
    editHandlers.onAddVisualization,
    editHandlers.onAddRow,
    editHandlers.onPastePanel,
    editHandlers.onSave,
    editHandlers.onSaveAsCopy,
    handleSetEditHandlers
  ]);

  return (
    <DashboardEditContext.Provider value={value}>
      {children}
    </DashboardEditContext.Provider>
  );
};
