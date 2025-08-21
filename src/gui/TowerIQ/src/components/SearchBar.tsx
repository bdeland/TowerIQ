import { useState } from 'react';
import { 
  Box, 
  InputBase, 
  IconButton, 
  alpha 
} from '@mui/material';
import { Search as SearchIcon } from '@mui/icons-material';

export function SearchBar() {
  const [searchQuery, setSearchQuery] = useState('');

  return (
    <Box
      sx={{
        position: 'relative',
        borderRadius: 1,
        backgroundColor: alpha('#fff', 0.15),
        '&:hover': {
          backgroundColor: alpha('#fff', 0.25),
        },
        marginRight: 2,
        marginLeft: 0,
        width: '100%',
        '@media (min-width: 600px)': {
          marginLeft: 3,
          width: 'auto',
        },
      }}
    >
      <Box sx={{ p: '2px 4px', display: 'flex', alignItems: 'center', width: 400 }}>
        <IconButton sx={{ p: '10px', color: 'inherit' }} aria-label="search">
          <SearchIcon />
        </IconButton>
        <InputBase
          sx={{ ml: 1, flex: 1, color: 'inherit' }}
          placeholder="Search..."
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          inputProps={{ 'aria-label': 'search' }}
        />
      </Box>
    </Box>
  );
}
