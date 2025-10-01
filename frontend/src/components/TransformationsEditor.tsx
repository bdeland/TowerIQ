import React, { useState, useCallback } from 'react';
import {
  Box,
  Button,
  Card,
  CardContent,
  CardActions,
  Typography,
  MenuItem,
  Select,
  FormControl,
  InputLabel,
  IconButton,
  Tooltip,
  Alert,
  Accordion,
  AccordionSummary,
  AccordionDetails
} from '@mui/material';
import {
  DndContext,
  closestCenter,
  KeyboardSensor,
  PointerSensor,
  useSensor,
  useSensors,
  DragEndEvent,
} from '@dnd-kit/core';
import {
  arrayMove,
  SortableContext,
  sortableKeyboardCoordinates,
  verticalListSortingStrategy,
} from '@dnd-kit/sortable';
import {
  useSortable,
} from '@dnd-kit/sortable';
import { CSS } from '@dnd-kit/utilities';
import {
  Add as AddIcon,
  Delete as DeleteIcon,
  ExpandMore as ExpandMoreIcon,
  ExpandLess as ExpandLessIcon,
  ContentCopy as ContentCopyIcon,
  VisibilityOff as VisibilityOffIcon,
  Visibility as VisibilityIcon,
  DragIndicator as DragIndicatorIcon,
  Edit as EditIcon
} from '@mui/icons-material';
import { DashboardPanel } from '../contexts/DashboardContext';
import { TransformationConfig, getAvailableTransformations, getDefaultTransformationOptions } from '../services/transformationService';
import TransformationRow from './TransformationRow';

interface TransformationsEditorProps {
  panel: DashboardPanel;
  onPanelUpdate: (updatedPanel: DashboardPanel) => void;
  panelData?: any[]; // Raw data from the panel's query
}

// Sortable Accordion Component
interface SortableAccordionProps {
  transformation: TransformationConfig;
  index: number;
  availableTransformations: any[];
  expandedTransformations: Set<number>;
  onToggleExpanded: (index: number) => void;
  onDelete: (index: number) => void;
  onDuplicate: (transformation: TransformationConfig) => void;
  onUpdate: (index: number, updatedTransformation: TransformationConfig) => void;
  availableFields: any[];
}

function SortableAccordion({
  transformation,
  index,
  availableTransformations,
  expandedTransformations,
  onToggleExpanded,
  onDelete,
  onDuplicate,
  onUpdate,
  availableFields
}: SortableAccordionProps) {
  const {
    attributes,
    listeners,
    setNodeRef,
    transform,
    transition,
    isDragging,
  } = useSortable({ id: `transformation-${index}` });

  const style = {
    transform: isDragging 
      ? `translate3d(0, ${transform?.y || 0}px, 0)` 
      : CSS.Transform.toString(transform),
    transition: isDragging ? 'none' : 'transform 100ms ease',
    opacity: isDragging ? 0.5 : 1,
  };

  return (
    <div ref={setNodeRef} style={style}>
      <Accordion 
        expanded={expandedTransformations.has(index)}
        onChange={() => onToggleExpanded(index)}
        sx={{ 
          mb: 0, 
          borderRadius: '12px',
          border: '1px solid',
          borderColor: 'divider',
          boxShadow: 'none',
          position: 'relative',
          zIndex: 1,
          '& .MuiAccordion-root': {
            boxShadow: 'none'
          },
          '& .MuiAccordionSummary-root': { 
            height: '30px !important',
            minHeight: '30px !important',
            padding: '0 !important'
          },
          '& .MuiAccordionSummary-content': {
            margin: '0 !important',
            padding: '0 !important'
          },
          '&:hover': {
            backgroundColor: 'transparent'
          }
        }}>
        <AccordionSummary 
          expandIcon={<ExpandMoreIcon sx={{ fontSize: '16px' }} />}
          sx={{ 
            flexDirection: 'row-reverse',
            py: 0,
            px: 6,
            borderRadius: '4px',
            '& .MuiAccordionSummary-expandIconWrapper': {
              transform: 'rotate(0deg)',
              marginLeft: 1,
              marginRight: 'auto'
            },
            '& .MuiAccordionSummary-expandIconWrapper.Mui-expanded': {
              transform: 'rotate(180deg)'
            },
            '&.Mui-expanded': {
              borderBottom: '1px solid',
              borderColor: 'divider'
            }
          }}
        >
          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', width: '100%', ml: 0.5, py: 0.25 }}>
            <Typography
              sx={{
                color: 'primary.main',
                fontSize: '0.75rem',
                fontWeight: 'bold',
              }}
            >
              {transformation.name || `${index + 1} - ${availableTransformations.find(t => t.id === transformation.id)?.name || transformation.id}`}
            </Typography>
            
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 0 }}>
              <Tooltip title="Duplicate transformation">
                <IconButton
                  onClick={(e) => {
                    e.stopPropagation();
                    onDuplicate(transformation);
                  }}
                >
                  <ContentCopyIcon sx={{ fontSize: '14px' }} />
                </IconButton>
              </Tooltip>
              
              <Tooltip title="Hide transformation">
                <IconButton
                  onClick={(e) => {
                    e.stopPropagation();
                    // TODO: Implement hide transformation
                  }}
                >
                  <VisibilityIcon sx={{ fontSize: '14px' }} />
                </IconButton>
              </Tooltip>
              
              <Tooltip title="Delete transformation">
                <IconButton
                  color="error"
                  onClick={(e) => {
                    e.stopPropagation();
                    onDelete(index);
                  }}
                >
                  <DeleteIcon sx={{ fontSize: '14px' }} />
                </IconButton>
              </Tooltip>
              
              <Tooltip title="Drag and drop to reorder transformations">
                <IconButton
                  {...attributes}
                  {...listeners}
                  sx={{ cursor: 'grab', '&:active': { cursor: 'grabbing' } }}
                  onClick={(e) => e.stopPropagation()}
                >
                  <DragIndicatorIcon sx={{ fontSize: '14px' }} />
                </IconButton>
              </Tooltip>
            </Box>
          </Box>
        </AccordionSummary>
        
        <AccordionDetails sx={{ 
          py: 1, 
          px: 1,
          borderRadius: '0 0 4px 4px',
          overflow: 'hidden'
        }}>
          <TransformationRow
            config={transformation}
            index={index}
            onUpdate={onUpdate}
            onDelete={onDelete}
            availableFields={availableFields}
          />
        </AccordionDetails>
      </Accordion>
    </div>
  );
}

export default function TransformationsEditor({ panel, onPanelUpdate, panelData }: TransformationsEditorProps) {
  const [availableTransformations] = useState(() => getAvailableTransformations());
  const [expandedTransformations, setExpandedTransformations] = useState<Set<number>>(new Set());
  const [isDragging, setIsDragging] = useState(false);

  const transformations = panel.transformations || [];
  
  // Drag and drop sensors
  const sensors = useSensors(
    useSensor(PointerSensor, {
      activationConstraint: {
        distance: 8,
      },
    }),
    useSensor(KeyboardSensor, {
      coordinateGetter: sortableKeyboardCoordinates,
    })
  );
  
  // Ensure all transformations have proper names (for backward compatibility)
  React.useEffect(() => {
    if (transformations.length > 0 && !isDragging) {
      // Check if transformations are already properly numbered
      const needsRenumbering = transformations.some((t, index) => {
        const expectedName = `${index + 1} - ${availableTransformations.find(at => at.id === t.id)?.name || t.id}`;
        return !t.name || t.name !== expectedName;
      });
      
      // Only renumber if there are missing names or incorrect numbering
      if (needsRenumbering) {
        const renumberedTransformations = transformations.map((transformation, index) => {
          const transformationName = availableTransformations.find(t => t.id === transformation.id)?.name || transformation.id;
          return {
            ...transformation,
            name: `${index + 1} - ${transformationName}`
          };
        });
        
        const updatedPanel = {
          ...panel,
          transformations: renumberedTransformations
        };
        onPanelUpdate(updatedPanel);
      }
    }
  }, [transformations.length, availableTransformations, panel, onPanelUpdate, isDragging]); // Only depend on length, not the full transformations array
  
  // Extract available fields from panel data
  const availableFields = React.useMemo(() => {
    if (!panelData || panelData.length === 0) return [];
    
    const firstRow = panelData[0];
    return Object.keys(firstRow).map(key => {
      const value = firstRow[key];
      const isNumeric = typeof value === 'number';
      const isString = typeof value === 'string';
      const isDate = !isNumeric && !isString && value instanceof Date;
      
      return {
        name: key,
        type: isNumeric ? 'number' : isString ? 'string' : isDate ? 'date' : 'other'
      };
    });
  }, [panelData]);

  const handleAddTransformation = useCallback((transformationId: string) => {
    const defaultOptions = getDefaultTransformationOptions(transformationId);
    const transformationName = availableTransformations.find(t => t.id === transformationId)?.name || transformationId;
    const newNumber = transformations.length + 1;
    
    const newTransformation: TransformationConfig = {
      id: transformationId,
      name: `${newNumber} - ${transformationName}`,
      options: defaultOptions
    };

    const updatedTransformations = [...transformations, newTransformation];
    const updatedPanel = {
      ...panel,
      transformations: updatedTransformations
    };

    onPanelUpdate(updatedPanel);
    
    // Expand the newly added transformation
    setExpandedTransformations(prev => new Set([...prev, transformations.length]));
  }, [panel, transformations, onPanelUpdate, availableTransformations]);

  const handleUpdateTransformation = useCallback((index: number, updatedTransformation: TransformationConfig) => {
    const updatedTransformations = [...transformations];
    updatedTransformations[index] = updatedTransformation;

    const updatedPanel = {
      ...panel,
      transformations: updatedTransformations
    };

    onPanelUpdate(updatedPanel);
  }, [panel, transformations, onPanelUpdate]);



  const handleDeleteTransformation = useCallback((index: number) => {
    const updatedTransformations = transformations.filter((_, i) => i !== index);
    const renumberedTransformations = updatedTransformations.map((transformation, index) => {
      const transformationName = availableTransformations.find(t => t.id === transformation.id)?.name || transformation.id;
      return {
        ...transformation,
        name: `${index + 1} - ${transformationName}`
      };
    });
    
    const updatedPanel = {
      ...panel,
      transformations: renumberedTransformations
    };

    onPanelUpdate(updatedPanel);
    
    // Remove from expanded set
    setExpandedTransformations(prev => {
      const newSet = new Set(prev);
      newSet.delete(index);
      // Adjust indices for remaining transformations
      const adjustedSet = new Set<number>();
      newSet.forEach(i => {
        if (i < index) {
          adjustedSet.add(i);
        } else if (i > index) {
          adjustedSet.add(i - 1);
        }
      });
      return adjustedSet;
    });
  }, [panel, transformations, onPanelUpdate, availableTransformations]);

  const handleToggleExpanded = useCallback((index: number) => {
    setExpandedTransformations(prev => {
      const newSet = new Set(prev);
      if (newSet.has(index)) {
        newSet.delete(index);
      } else {
        newSet.add(index);
      }
      return newSet;
    });
  }, []);

  // Handle drag start
  const handleDragStart = useCallback(() => {
    setIsDragging(true);
  }, []);

  // Handle drag end for reordering
  const handleDragEnd = useCallback((event: DragEndEvent) => {
    setIsDragging(false);
    const { active, over } = event;

    if (active.id !== over?.id) {
      const oldIndex = transformations.findIndex((_, index) => `transformation-${index}` === active.id);
      const newIndex = transformations.findIndex((_, index) => `transformation-${index}` === over?.id);

      if (oldIndex !== -1 && newIndex !== -1) {
        const updatedTransformations = arrayMove(transformations, oldIndex, newIndex);
        const renumberedTransformations = updatedTransformations.map((transformation, index) => {
          const transformationName = availableTransformations.find(t => t.id === transformation.id)?.name || transformation.id;
          return {
            ...transformation,
            name: `${index + 1} - ${transformationName}`
          };
        });
        
        const updatedPanel = {
          ...panel,
          transformations: renumberedTransformations
        };

        onPanelUpdate(updatedPanel);
      }
    }
  }, [transformations, availableTransformations, panel, onPanelUpdate]);

  // Handle duplicate transformation
  const handleDuplicateTransformation = useCallback((transformation: TransformationConfig) => {
    const duplicatedTransformation = { ...transformation };
    const updatedTransformations = [...transformations, duplicatedTransformation];
    const renumberedTransformations = updatedTransformations.map((t, index) => {
      const transformationName = availableTransformations.find(at => at.id === t.id)?.name || t.id;
      return {
        ...t,
        name: `${index + 1} - ${transformationName}`
      };
    });
    
    const updatedPanel = {
      ...panel,
      transformations: renumberedTransformations
    };
    
    onPanelUpdate(updatedPanel);
    
    // Expand the newly added transformation
    setExpandedTransformations(prev => new Set([...prev, transformations.length]));
  }, [transformations, availableTransformations, panel, onPanelUpdate]);

  return (
    <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
      <Box sx={{ display: 'flex', justifyContent: 'flex-end' }}>
        <FormControl size="small" sx={{ minWidth: 200 }}>
          <InputLabel>Add transformation</InputLabel>
          <Select
            value=""
            label="Add transformation"
            onChange={(e) => {
              if (e.target.value) {
                handleAddTransformation(e.target.value as string);
              }
            }}
          >
            {availableTransformations.map((transformation) => (
              <MenuItem key={transformation.id} value={transformation.id}>
                {transformation.name}
              </MenuItem>
            ))}
          </Select>
        </FormControl>
      </Box>

      {transformations.length === 0 ? (
        <Box sx={{ 
          display: 'flex', 
          alignItems: 'center', 
          justifyContent: 'center', 
          py: 4,
          border: '1px solid',
          borderColor: 'divider',
          borderRadius: 2,
          backgroundColor: 'background.default'
        }}>
          <Typography variant="body2" color="text.secondary">
            No transformations defined. Click "Add transformation" to get started.
          </Typography>
        </Box>
             ) : (
                   <DndContext
            sensors={sensors}
            collisionDetection={closestCenter}
            onDragStart={handleDragStart}
            onDragEnd={handleDragEnd}
          >
           <SortableContext
             items={transformations.map((_, index) => `transformation-${index}`)}
             strategy={verticalListSortingStrategy}
           >
             <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
               {transformations.map((transformation, index) => (
                 <SortableAccordion
                   key={`transformation-${index}`}
                   transformation={transformation}
                   index={index}
                   availableTransformations={availableTransformations}
                   expandedTransformations={expandedTransformations}
                   onToggleExpanded={handleToggleExpanded}
                   onDelete={handleDeleteTransformation}
                   onDuplicate={handleDuplicateTransformation}
                   onUpdate={handleUpdateTransformation}
                   availableFields={availableFields}
                 />
               ))}
             </Box>
           </SortableContext>
         </DndContext>
       )}
    </Box>
  );
}
