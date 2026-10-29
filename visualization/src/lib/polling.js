// Serial refreshes while a view is visible; stop prevents any future scheduling.
export function startPolling(task, interval = 10000) {
  let stopped = false;
  let running = false;
  let timer;
  async function refresh() {
    if (stopped || running || document.hidden) return;
    clearTimeout(timer);
    running = true;
    try { await task(); }
    finally {
      running = false;
      if (!stopped && !document.hidden) timer = setTimeout(onVisible, interval);
    }
  }
  function onVisible() {
    clearTimeout(timer);
    if (!document.hidden) void refresh().catch(console.error);
  }
  document.addEventListener('visibilitychange', onVisible);
  window.addEventListener('focus', onVisible);
  onVisible();
  return {
    refresh,
    stop() {
      stopped = true;
      clearTimeout(timer);
      document.removeEventListener('visibilitychange', onVisible);
      window.removeEventListener('focus', onVisible);
    },
  };
}
