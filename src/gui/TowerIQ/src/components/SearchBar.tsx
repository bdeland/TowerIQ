import { useState } from 'react';
import { 
  Box, 
  InputBase, 
  alpha 
} from '@mui/material';
import { Search as SearchIcon } from '@mui/icons-material';

export function SearchBar() {
  const [searchQuery, setSearchQuery] = useState('');

  return (
    <Box
                    sx={{
         position: 'relative',
         borderRadius: 0.5, // You can change this value: 0 = no radius, 1 = small, 2 = medium, 3 = large, etc.
         backgroundColor: '#111217', // Use theme background color
         '&:hover': {
           backgroundColor: alpha('#fff', 0.25),
         },
        margin: 0, // Remove all margins
        padding: 0, // Remove all padding
        marginLeft: 0,
        marginRight: 0,
        marginTop: 0,
        marginBottom: 0,
        paddingLeft: 0,
        paddingRight: 0,
        paddingTop: 0,
        paddingBottom: 0,
        overflow: 'hidden',
        // Extend to full available width
        minWidth: '40px', // Minimum width (just icon)
        width: '100%', // Take full available width
        // Force override any Material-UI defaults
        '& *': {
          margin: 0,
          padding: 0,
        },
      }}
    >
      <Box sx={{ 
        p: 0, // Remove all padding
        display: 'flex', 
        alignItems: 'center', 
        width: '100%',
        height: '28px',
        overflow: 'hidden'
      }}>
                 {/* Always show the search icon */}
         <Box
           sx={{
             display: 'flex',
             alignItems: 'center',
             justifyContent: 'center',
             width: '32px',
             height: '32px',
             color: 'text.primary', // Use theme text color
             flexShrink: 0, // Prevent icon from shrinking
           }}
         >
           <SearchIcon sx={{ fontSize: 20, color: 'text.primary' }} />
         </Box>
        
                 {/* Input field - hidden on small screens */}
         <InputBase
           sx={{ 
             ml: 1, 
             flex: 1, 
             color: 'text.primary', // Use theme text color
             // Hide input on very small screens
             display: {
               xs: 'none', // Hide on mobile
               sm: 'block', // Show on small screens and up
             },
             '& .MuiInputBase-input': {
               color: 'text.primary', // Ensure input text uses theme color
             },
             '& .MuiInputBase-input::placeholder': {
               color: 'text.secondary', // Use secondary text color for placeholder
               opacity: 1, // Ensure placeholder is visible
             },
           }}
          placeholder="Search..."
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          inputProps={{ 'aria-label': 'search' }}
        />
      </Box>
    </Box>
  );
}
