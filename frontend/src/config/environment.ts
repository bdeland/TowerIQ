// Environment configuration
export const API_CONFIG = {
  BASE_URL: import.meta.env.VITE_API_BASE_URL || "http://localhost:8080/api",
  QUERY_PREVIEW_URL:
    import.meta.env.VITE_QUERY_PREVIEW_URL ||
    "http://localhost:8080/api/query/preview",
} as const;
