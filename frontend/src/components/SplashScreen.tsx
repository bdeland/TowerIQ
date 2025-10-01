import React, { useEffect, useState } from 'react';
import { Box, Fade, CircularProgress, Typography } from '@mui/material';
import splashImage from '../assets/splash.png';

interface SplashScreenProps {
  onComplete: () => void;
  minDisplayTime?: number; // Minimum time to show splash screen (default 3 seconds)
}

const SplashScreen: React.FC<SplashScreenProps> = ({ onComplete, minDisplayTime = 3000 }) => {
  const [show, setShow] = useState(false);
  const [startTime] = useState(Date.now());

  useEffect(() => {
    // Start fade in after a brief delay
    const fadeInTimer = setTimeout(() => {
      setShow(true);
    }, 100);

    return () => {
      clearTimeout(fadeInTimer);
    };
  }, []);

  const handleComplete = () => {
    const elapsedTime = Date.now() - startTime;
    const remainingTime = Math.max(0, minDisplayTime - elapsedTime);

    setShow(false);
    // Wait for fade out animation to complete before calling onComplete
    setTimeout(() => {
      onComplete();
    }, 500); // Fade out duration
  };

  return (
    <Box
      sx={{
        position: 'fixed',
        top: 0,
        left: 0,
        width: '100vw',
        height: '100vh',
        backgroundColor: '#111217', // Match Grafana dark theme
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        zIndex: 9999,
      }}
    >
      <Fade in={show} timeout={500}>
        <Box sx={{ textAlign: 'center' }}>
          <Box
            component="img"
            src={splashImage}
            alt="TowerIQ Splash"
            sx={{
              maxWidth: '300px',
              maxHeight: '300px',
              width: 'auto',
              height: 'auto',
              filter: 'drop-shadow(0 4px 8px rgba(0, 0, 0, 0.3))',
              mb: 3,
            }}
          />
          <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 2 }}>
            <CircularProgress size={20} sx={{ color: 'var(--tiq-brand-secondary)' }} />
            <Typography variant="body2" sx={{ color: 'var(--tiq-text-secondary)' }}>
              Starting TowerIQ...
            </Typography>
          </Box>
        </Box>
      </Fade>
    </Box>
  );
};

export default SplashScreen;
