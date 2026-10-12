export const localFetch = (path, options = {}) => fetch(`http://127.0.0.1:8400${path}`, {
  ...options,
  headers: { ...options.headers, 'X-Specula-Local-Boot': '1' }
});
