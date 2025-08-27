import React, { createContext, useContext, useState, useCallback, useMemo, ReactNode } from 'react';

interface DashboardEditContextType {
  isDashboardPage: boolean;
  isEditMode: boolean;
  isPanelEditPage: boolean;
  saving: boolean;
  hasUnsavedChanges: boolean;
  setIsDashboardPage: (value: boolean) => void;
  setIsEditMode: (value: boolean) => void;
  setIsPanelEditPage: (value: boolean) => void;
  setSaving: (value: boolean) => void;
  setHasUnsavedChanges: (value: boolean) => void;
  onEditToggle?: () => void;
  onAddVisualization?: () => void;
  onAddRow?: () => void;
  onPastePanel?: () => void;
  onSave?: () => void;
  onSaveAsCopy?: () => void;
  // Panel edit handlers
  onBackToDashboard?: () => void;
  onDiscardChanges?: () => void;
  onSavePanelChanges?: () => void;
  setEditHandlers: (handlers: {
    onEditToggle: () => void;
    onAddVisualization: () => void;
    onAddRow: () => void;
    onPastePanel: () => void;
    onSave: () => void;
    onSaveAsCopy: () => void;
  }) => void;
  setPanelEditHandlers: (handlers: {
    onBackToDashboard: () => void;
    onDiscardChanges: () => void;
    onSavePanelChanges: () => void;
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
      isPanelEditPage: false,
      saving: false,
      hasUnsavedChanges: false,
      setIsDashboardPage: () => {},
      setIsEditMode: () => {},
      setIsPanelEditPage: () => {},
      setSaving: () => {},
      setHasUnsavedChanges: () => {},
      onEditToggle: undefined,
      onAddVisualization: undefined,
      onAddRow: undefined,
      onPastePanel: undefined,
      onSave: undefined,
      onSaveAsCopy: undefined,
      onBackToDashboard: undefined,
      onDiscardChanges: undefined,
      onSavePanelChanges: undefined,
      setEditHandlers: () => {},
      setPanelEditHandlers: () => {},
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
  const [isPanelEditPage, setIsPanelEditPage] = useState(false);
  const [saving, setSaving] = useState(false);
  const [hasUnsavedChanges, setHasUnsavedChanges] = useState(false);
  const [editHandlers, setEditHandlers] = useState<{
    onEditToggle?: () => void;
    onAddVisualization?: () => void;
    onAddRow?: () => void;
    onPastePanel?: () => void;
    onSave?: () => void;
    onSaveAsCopy?: () => void;
  }>({});
  const [panelEditHandlers, setPanelEditHandlers] = useState<{
    onBackToDashboard?: () => void;
    onDiscardChanges?: () => void;
    onSavePanelChanges?: () => void;
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

  const handleSetPanelEditHandlers = useCallback((handlers: {
    onBackToDashboard: () => void;
    onDiscardChanges: () => void;
    onSavePanelChanges: () => void;
  }) => {
    setPanelEditHandlers(handlers);
  }, []);

  const value: DashboardEditContextType = useMemo(() => ({
    isDashboardPage,
    isEditMode,
    isPanelEditPage,
    saving,
    hasUnsavedChanges,
    setIsDashboardPage,
    setIsEditMode,
    setIsPanelEditPage,
    setSaving,
    setHasUnsavedChanges,
    onEditToggle: editHandlers.onEditToggle,
    onAddVisualization: editHandlers.onAddVisualization,
    onAddRow: editHandlers.onAddRow,
    onPastePanel: editHandlers.onPastePanel,
    onSave: editHandlers.onSave,
    onSaveAsCopy: editHandlers.onSaveAsCopy,
    onBackToDashboard: panelEditHandlers.onBackToDashboard,
    onDiscardChanges: panelEditHandlers.onDiscardChanges,
    onSavePanelChanges: panelEditHandlers.onSavePanelChanges,
    setEditHandlers: handleSetEditHandlers,
    setPanelEditHandlers: handleSetPanelEditHandlers,
  }), [
    isDashboardPage,
    isEditMode,
    isPanelEditPage,
    saving,
    hasUnsavedChanges,
    editHandlers.onEditToggle,
    editHandlers.onAddVisualization,
    editHandlers.onAddRow,
    editHandlers.onPastePanel,
    editHandlers.onSave,
    editHandlers.onSaveAsCopy,
    panelEditHandlers.onBackToDashboard,
    panelEditHandlers.onDiscardChanges,
    panelEditHandlers.onSavePanelChanges,
    handleSetEditHandlers,
    handleSetPanelEditHandlers
  ]);

  return (
    <DashboardEditContext.Provider value={value}>
      {children}
    </DashboardEditContext.Provider>
  );
};
