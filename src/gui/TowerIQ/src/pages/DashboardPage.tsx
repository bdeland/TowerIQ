import { Box, Typography, Button } from '@mui/material';
import { Dashboard as DashboardIcon, Add as AddIcon } from '@mui/icons-material';
import { Responsive, WidthProvider, Layout } from 'react-grid-layout';
import 'react-grid-layout/css/styles.css';
import { useState } from 'react';

const ResponsiveGridLayout = WidthProvider(Responsive);

interface PanelItem {
  i: string;
  x: number;
  y: number;
  w: number;
  h: number;
  content: string;
}

export function DashboardPage() {
  const [panels, setPanels] = useState<PanelItem[]>([
    {
      i: 'panel-1',
      x: 0,
      y: 0,
      w: 4,
      h: 2,
      content: 'Quick Stats'
    },
    {
      i: 'panel-2',
      x: 4,
      y: 0,
      w: 4,
      h: 2,
      content: 'Recent Activity'
    },
    {
      i: 'panel-3',
      x: 8,
      y: 0,
      w: 4,
      h: 2,
      content: 'System Status'
    }
  ]);

  const [panelCounter, setPanelCounter] = useState(4);

  const addPanel = () => {
    const newPanel: PanelItem = {
      i: `panel-${panelCounter}`,
      x: (panels.length * 4) % 12,
      y: Math.floor(panels.length / 3) * 2,
      w: 4,
      h: 2,
      content: `Panel ${panelCounter}`
    };
    
    console.log('Adding new panel:', newPanel);
    setPanels([...panels, newPanel]);
    setPanelCounter(panelCounter + 1);
  };

  const onLayoutChange = (layout: Layout[]) => {
    console.log('Layout changed:', layout);
    // Update panel positions when layout changes
    const updatedPanels = panels.map(panel => {
      const layoutItem = layout.find(item => item.i === panel.i);
      if (layoutItem) {
        return {
          ...panel,
          x: layoutItem.x,
          y: layoutItem.y,
          w: layoutItem.w,
          h: layoutItem.h
        };
      }
      return panel;
    });
    setPanels(updatedPanels);
  };

  console.log('Current panels:', panels);

  return (
    <Box sx={{ padding: 3 }}>
      <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 3 }}>
        <Box sx={{ display: 'flex', alignItems: 'center' }}>
          <DashboardIcon sx={{ mr: 2, fontSize: 40, color: 'primary.main' }} />
          <Typography variant="h4" component="h1">
            Dashboard
          </Typography>
        </Box>
        <Button
          variant="contained"
          startIcon={<AddIcon />}
          onClick={addPanel}
          sx={{ minWidth: 120 }}
        >
          Add Panel
        </Button>
      </Box>
      
      <Typography variant="body1" color="text.secondary" paragraph>
        Monitor your system performance and key metrics. Drag and resize panels to customize your layout.
      </Typography>
      
      <Box sx={{ mt: 2 }}>
        <ResponsiveGridLayout
          className="layout"
          layouts={{ lg: panels }}
          breakpoints={{ lg: 1200, md: 996, sm: 768, xs: 480, xxs: 0 }}
          cols={{ lg: 12, md: 10, sm: 6, xs: 4, xxs: 2 }}
          rowHeight={100}
          margin={[8, 8]}
          onLayoutChange={onLayoutChange}
          isDraggable={true}
          isResizable={true}
        >
          {panels.map((panel) => (
            <Box
              key={panel.i}
              sx={{
                backgroundColor: 'background.paper',
                border: '1px solid',
                borderColor: 'divider',
                borderRadius: 1,
                p: 2,
                height: '100%',
                display: 'flex',
                flexDirection: 'column',
                justifyContent: 'center',
                alignItems: 'center',
                textAlign: 'center',
                boxShadow: 1,
                '&:hover': {
                  boxShadow: 2,
                  borderColor: 'primary.main'
                }
              }}
            >
              <Typography variant="h6" gutterBottom>
                {panel.content}
              </Typography>
              <Typography variant="body2" color="text.secondary">
                Drag to move • Resize corners to adjust
              </Typography>
            </Box>
          ))}
        </ResponsiveGridLayout>
      </Box>
    </Box>
  );
}
