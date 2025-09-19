import React from 'react';
import { SvgIcon, SvgIconProps } from '@mui/material';

interface TowerIQLogoProps extends SvgIconProps {
  // Add any additional props specific to TowerIQ logo if needed
}

export const TowerIQLogo: React.FC<TowerIQLogoProps> = (props) => (
  <SvgIcon {...props} viewBox="0 0 1010 876.02502">
    <g transform="translate(-182.68069,-377.47661)">
      <g
        transform="matrix(1.7309062,0,0,1.7309062,-128.52245,-270.90014)"
        style={{ fill: '#e18b3d', fillOpacity: 1 }}
      >
        <path
          style={{ 
            fill: '#39b5e0', 
            fillOpacity: 1, 
            stroke: 'none', 
            strokeWidth: '11.5546', 
            strokeLinecap: 'round', 
            strokeLinejoin: 'round', 
            strokeMiterlimit: 8, 
            strokeDasharray: 'none', 
            strokeOpacity: 1 
          }}
          d="m 327.54672,627.39191 144,249.41529 54.25843,-93.97843 -89.74157,-155.43686 89.74157,-155.43696 h 179.48304 l 54.25853,-93.97834 h -576 l 54.25843,93.97834 h 179.48304 z"
        />
        <path
          style={{ 
            fill: '#39b5e0', 
            stroke: 'none', 
            strokeWidth: '0.577732px', 
            strokeLinecap: 'butt', 
            strokeLinejoin: 'miter', 
            strokeOpacity: 1, 
            fillOpacity: 1 
          }}
          d="M 674.67741,525.57531 559.80826,724.53455 M 674.67741,525.57531 H 559.80826 l -57.4346,99.47966 57.4346,99.47958"
        />
      </g>
    </g>
  </SvgIcon>
);

export default TowerIQLogo;
