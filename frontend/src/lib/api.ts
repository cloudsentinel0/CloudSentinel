import { AWSCredentials, HealthResponse, ScanRequest, ScanSummary, ScanDetail, SSEEvent } from './types';

export const API_BASE_URL = 'http://localhost:8000';

export async function checkHealth(): Promise<HealthResponse> {
  const res = await fetch(`${API_BASE_URL}/health`);
  if (!res.ok) throw new Error('Health check failed');
  return res.json();
}

export async function startScan(
  request: ScanRequest,
  credentials: AWSCredentials | null,
  onEvent: (event: SSEEvent) => void,
  signal?: AbortSignal
): Promise<void> {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
  };

  if (credentials) {
    headers['X-AWS-Access-Key-Id'] = credentials.accessKey;
    headers['X-AWS-Secret-Access-Key'] = credentials.secretKey;
    if (credentials.sessionToken) {
      headers['X-AWS-Session-Token'] = credentials.sessionToken;
    }
  }

  const res = await fetch(`${API_BASE_URL}/scan`, {
    method: 'POST',
    headers,
    body: JSON.stringify(request),
    signal,
  });

  if (!res.ok) throw new Error(`Scan failed: ${res.statusText}`);
  if (!res.body) throw new Error('No response body');

  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let buffer = '';

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;

    buffer += decoder.decode(value, { stream: true });
    const lines = buffer.split('\n');
    buffer = lines.pop() || '';

    for (const line of lines) {
      const trimmed = line.trim();
      if (trimmed.startsWith('data: ')) {
        try {
          const event: SSEEvent = JSON.parse(trimmed.slice(6));
          onEvent(event);
        } catch {
          // skip malformed
        }
      }
    }
  }
}

export async function cancelScan(sessionId: string): Promise<void> {
  const res = await fetch(`${API_BASE_URL}/scans/${encodeURIComponent(sessionId)}/cancel`, {
    method: 'POST',
  });

  if (!res.ok && res.status !== 404) {
    throw new Error('Failed to cancel scan');
  }
}

// ── Scan history ────────────────────────────────────────────────────────────

export async function listScans(limit = 50): Promise<ScanSummary[]> {
  const res = await fetch(`${API_BASE_URL}/scans?limit=${limit}`);
  if (!res.ok) throw new Error('Failed to fetch scan history');
  const data = await res.json();
  return data.scans;
}

export async function getScan(id: string): Promise<ScanDetail> {
  const res = await fetch(`${API_BASE_URL}/scans/${encodeURIComponent(id)}`);
  if (!res.ok) throw new Error('Failed to fetch scan detail');
  return res.json();
}

export async function deleteSession(sessionId: string): Promise<void> {
  const res = await fetch(`${API_BASE_URL}/scans/${encodeURIComponent(sessionId)}`, {
    method: 'DELETE',
  });
  if (!res.ok) throw new Error('Failed to delete session');
}
