const API_BASE_URL = 'http://localhost:8000'; // Change to https://api.nomadik.site in production

export function connectSentinelStream(onEvent, onError) {
  const eventSource = new EventSource(`${API_BASE_URL}/api/v1/sentinel/stream`);

  // Handle initial connection handshake
  eventSource.addEventListener('connected', (e) => {
    console.log('[Sentinel SSE] Stream connected:', JSON.parse(e.data));
  });

  // Handle incoming telemetry events (Status checks, packet hits, auth failures)
  eventSource.addEventListener('telemetry', (e) => {
    const payload = JSON.parse(e.data);
    onEvent(payload);
  });

  // Heartbeat ping (keeps connection alive across proxies/Cloudflare)
  eventSource.addEventListener('ping', (e) => {
    console.debug('[Sentinel SSE] Heartbeat ping received');
  });

  // Handle errors and automatic reconnection
  eventSource.onerror = (err) => {
    console.error('[Sentinel SSE] Connection dropped or failed:', err);
    if (onError) onError(err);

    if (eventSource.readyState === EventSource.CLOSED) {
      console.warn('[Sentinel SSE] Stream closed by server.');
    }
  };

  // Return teardown function for clean cleanup
  return () => {
    eventSource.close();
    console.log('[Sentinel SSE] Stream closed by client.');
  };
}
