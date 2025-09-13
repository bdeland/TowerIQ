import { useState, useLayoutEffect, useCallback, useRef } from 'react';

interface ContentDimensions {
  width: number;
  height: number;
  offsetX: number;
  offsetY: number;
}

export function useContentDimensions(): ContentDimensions {
  const [dimensions, setDimensions] = useState<ContentDimensions>({
    width: 0,
    height: 0,
    offsetX: 0,
    offsetY: 0,
  });

  // Use ref to store previous dimensions to prevent unnecessary updates
  const prevDimensionsRef = useRef<ContentDimensions | null>(null);

  // Throttle resize updates to prevent excessive re-renders
  const throttledUpdateDimensions = useCallback((newDimensions: ContentDimensions) => {
    const prev = prevDimensionsRef.current;
    
    // Only update if dimensions actually changed significantly (more than 1px difference)
    if (!prev || 
        Math.abs(newDimensions.width - prev.width) > 1 || 
        Math.abs(newDimensions.height - prev.height) > 1 ||
        Math.abs(newDimensions.offsetX - prev.offsetX) > 1 ||
        Math.abs(newDimensions.offsetY - prev.offsetY) > 1) {
      
      prevDimensionsRef.current = newDimensions;
      setDimensions(newDimensions);
    }
  }, []);

  useLayoutEffect(() => {
    const contentContainer = document.querySelector('[data-content-container="true"]');

    if (!contentContainer) {
      // Fallback to the viewport if no container is found
      const updateDimensions = () => {
        const newDimensions = {
          width: window.innerWidth,
          height: window.innerHeight,
          offsetX: 0,
          offsetY: 0,
        };
        throttledUpdateDimensions(newDimensions);
      };
      
      // Use requestAnimationFrame to throttle resize events
      let timeoutId: number;
      const throttledResize = () => {
        if (timeoutId) {
          cancelAnimationFrame(timeoutId);
        }
        timeoutId = requestAnimationFrame(updateDimensions);
      };
      
      window.addEventListener('resize', throttledResize);
      updateDimensions();

      return () => {
        window.removeEventListener('resize', throttledResize);
        if (timeoutId) {
          cancelAnimationFrame(timeoutId);
        }
      };
    }

    const resizeObserver = new ResizeObserver(entries => {
      for (const entry of entries) {
        const rect = entry.target.getBoundingClientRect();
        
        // For fullscreen, we want to fill the entire content container
        // but keep the 8px right and bottom padding
        const computedStyle = getComputedStyle(entry.target);
        const paddingRight = parseFloat(computedStyle.paddingRight);
        const paddingBottom = parseFloat(computedStyle.paddingBottom);
        
        const newDimensions = {
          width: rect.width - paddingRight, // Subtract right padding to keep 8px margin
          height: rect.height - paddingBottom, // Subtract bottom padding to keep 8px margin
          offsetX: rect.left,
          offsetY: rect.top,
        };
        
        throttledUpdateDimensions(newDimensions);
      }
    });

    resizeObserver.observe(contentContainer);

    return () => {
      resizeObserver.disconnect();
    };
  }, [throttledUpdateDimensions]);

  return dimensions;
}