/**
 * Waymark API Client
 * 
 * Centralized HTTP client for all backend API calls.
 * Points to the FastAPI server at localhost:8000.
 */

const API_BASE = process.env.NEXT_PUBLIC_API_URL || `http://${typeof window !== 'undefined' ? window.location.hostname : 'localhost'}:8000/api/v1`;

class ApiError extends Error {
  status: number;
  detail: string;
  
  constructor(status: number, detail: string) {
    super(detail);
    this.status = status;
    this.detail = detail;
  }
}

async function request<T>(
  path: string,
  options: RequestInit = {}
): Promise<T> {
  const url = `${API_BASE}${path}`;
  
  const res = await fetch(url, {
    headers: {
      "Content-Type": "application/json",
      ...options.headers,
    },
    ...options,
  });

  if (!res.ok) {
    const body = await res.json().catch(() => ({ detail: res.statusText }));
    throw new ApiError(res.status, body.detail || res.statusText);
  }

  if (res.status === 204) return null as T;
  return res.json();
}

// ── Companies ─────────────────────────────────────────────────────────

export interface Company {
  id: string;
  org_id: string;
  name: string;
  description: string | null;
  bug_bounty_url: string | null;
  scope_authorized: boolean;
  scope_authorized_at: string | null;
  created_at: string;
}

export const companies = {
  list: () => request<Company[]>("/companies/"),
  get: (id: string) => request<Company>(`/companies/${id}`),
  create: (data: { name: string; description?: string; bug_bounty_url?: string; scope_authorized: boolean }) =>
    request<Company>("/companies/", { method: "POST", body: JSON.stringify(data) }),
  delete: (id: string) => fetch(`${API_BASE}/companies/${id}`, { method: 'DELETE' }),
  update: (id: string, data: any) => fetch(`${API_BASE}/companies/${id}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data)
  }).then(r => r.json()),
};

// ── Wildcards & Subdomains ────────────────────────────────────────────

export interface Wildcard {
  id: string;
  company_id: string;
  root_domain: string;
  scope_status: string;
  created_at: string;
}

export interface Subdomain {
  id: string;
  wildcard_id: string;
  fqdn: string;
  ip_address: string | null;
  status_code: number | null;
  title: string | null;
  technologies: string[];
  roi_score: number;
  scope_status: string;
  is_alive: boolean;
  first_seen_at: string;
  last_seen_at: string;
}

export const wildcards = {
  listForCompany: (companyId: string) =>
    request<Wildcard[]>(`/companies/${companyId}/wildcards`),
  create: (companyId: string, data: { root_domain: string; scope_status?: string }) =>
    request<Wildcard>(`/companies/${companyId}/wildcards`, { method: "POST", body: JSON.stringify(data) }),
  delete: (id: string) => fetch(`${API_BASE}/wildcards/${id}`, { method: 'DELETE' }),
};

export const assets = {
  subdomains: (wildcardId: string) =>
    request<Subdomain[]>(`/wildcards/${wildcardId}/subdomains`),
  subdomain: (id: string) =>
    request<Subdomain>(`/subdomains/${id}`),
};

// ── Scans ─────────────────────────────────────────────────────────────

export interface ScanJob {
  id: string;
  target_type: string;
  target_id: string;
  profile: string;
  status: string;
  current_tier: string;
  is_paused: boolean;
  rate_limit: number;
  started_at: string | null;
  completed_at: string | null;
}

export interface ToolRun {
  id: string;
  plugin_name: string;
  status: string;
  execution_order: number;
  started_at: string | null;
  completed_at: string | null;
  result_count: number;
}

export interface ScanControlResponse {
  scan_id: string;
  action: string;
  status: string;
  message: string;
}

export const scans = {
  list: () => request<ScanJob[]>("/scans/"),
  create: (data: any) => fetch(`${API_BASE}/scans/`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data)
  }).then(r => r.json()),
  
  get: (id: string) => request<ScanJob>(`/scans/${id}`),
  toolRuns: (id: string) => request<ToolRun[]>(`/scans/${id}/tool-runs`),
  results: (id: string) => fetch(`${API_BASE}/scans/${id}/results`).then(r => r.json()),
  
  pause: (id: string) => request<ScanControlResponse>(`/scans/${id}/pause`, { method: "POST" }),
  resume: (id: string) => request<ScanControlResponse>(`/scans/${id}/resume`, { method: "POST" }),
  skipTool: (id: string) => request<ScanControlResponse>(`/scans/${id}/skip-tool`, { method: "POST" }),
  cancel: (id: string) => request<ScanControlResponse>(`/scans/${id}/cancel`, { method: "POST" }),
};

// ── Findings ──────────────────────────────────────────────────────────

export interface Finding {
  id: string;
  subdomain_id: string;
  title: string;
  description: string | null;
  severity: string;
  status: string;
  discovery_tool: string;
  matched_at: string | null;
  is_false_positive: boolean;
  created_at: string;
}

export const findings = {
  list: (params?: { severity?: string; status?: string }) => {
    const query = new URLSearchParams(params as Record<string, string>).toString();
    return request<Finding[]>(`/findings/${query ? `?${query}` : ""}`);
  },
};

// ── Education ─────────────────────────────────────────────────────────

export interface EducationGuide {
  id: string;
  title: string;
  category: string;
  difficulty: string;
  summary: string;
  what_it_does: string;
  why_it_matters: string;
  tips: string[];
  questions: { question: string; answers: string[] }[];
}

export interface PlaybookMatch {
  playbook_slug: string;
  title: string;
  category: string;
  severity_potential: string;
  match_reasons: string[];
  confidence: number;
  steps_preview: string[];
}

export const education = {
  list: (category?: string) =>
    request<EducationGuide[]>(`/education/${category ? `?category=${category}` : ""}`),
  get: (contentId: string) =>
    request<EducationGuide>(`/education/guides/${contentId}`),
  recommend: (fqdn: string, statusCode?: number, technologies?: string) => {
    const params = new URLSearchParams({ fqdn });
    if (statusCode) params.set("status_code", String(statusCode));
    if (technologies) params.set("technologies", technologies);
    return request<PlaybookMatch[]>(`/education/playbooks/recommend?${params}`);
  },
};

// ── Wordlists ─────────────────────────────────────────────────────────

export interface WordlistInfo {
  id: string;
  name: string;
  category: string;
  description: string | null;
  line_count: number;
  size_bytes: number;
  is_builtin: boolean;
}

export const wordlists = {
  list: (category?: string) =>
    request<WordlistInfo[]>(`/wordlists/${category ? `?category=${category}` : ""}`),
};

// ── WebSocket ─────────────────────────────────────────────────────────

const WS_BASE = process.env.NEXT_PUBLIC_WS_URL || `ws://${typeof window !== 'undefined' ? window.location.hostname : 'localhost'}:8000`;

export function connectScanWS(
  scanId: string,
  onMessage: (event: Record<string, unknown>) => void,
  onClose?: () => void
): WebSocket {
  const ws = new WebSocket(`${WS_BASE}/ws/scans/${scanId}`);
  
  ws.onmessage = (evt) => {
    try {
      const data = JSON.parse(evt.data);
      onMessage(data);
    } catch {
      // ignore non-JSON messages
    }
  };
  
  ws.onclose = () => onClose?.();
  
  return ws;
}

// ── Integrations: Schedules, Webhooks & Notifications ─────────────────

export interface Schedule {
  id: string;
  org_id: string;
  wildcard_id: string;
  frequency: "daily" | "weekly" | "monthly" | "custom" | string;
  cron_expression: string | null;
  scan_mode: string;
  is_active: boolean;
  last_run_at: string | null;
  next_run_at: string | null;
  created_at: string;
}

export interface Webhook {
  id: string;
  org_id: string;
  name: string;
  url: string;
  secret_key: string | null;
  is_active: boolean;
  event_types: string[];
  min_severity: string | null;
  created_at: string;
}

export interface Notification {
  id: string;
  org_id: string;
  type: "new_subdomain" | "new_finding" | "scan_complete" | "content_change" | "certificate_expiry" | string;
  title: string;
  message: string | null;
  related_entity_type: string | null;
  related_entity_id: string | null;
  is_read: boolean;
  created_at: string;
}

export const schedules = {
  list: (wildcardId?: string) =>
    request<Schedule[]>(`/schedules/${wildcardId ? `?wildcard_id=${wildcardId}` : ""}`),
  create: (data: {
    wildcard_id: string;
    frequency: string;
    cron_expression?: string;
    scan_mode?: string;
    is_active?: boolean;
  }) => request<Schedule>("/schedules/", { method: "POST", body: JSON.stringify(data) }),
  delete: (id: string) => request<{ status: string }>(`/schedules/${id}`, { method: "DELETE" }),
  toggle: (id: string) => request<Schedule>(`/schedules/${id}/toggle`, { method: "PATCH" }),
};

export const webhooks = {
  list: () => request<Webhook[]>("/webhooks/"),
  create: (data: {
    name: string;
    url: string;
    secret_key?: string;
    is_active?: boolean;
    event_types?: string[];
    min_severity?: string;
  }) => request<Webhook>("/webhooks/", { method: "POST", body: JSON.stringify(data) }),
  delete: (id: string) => request<{ status: string }>(`/webhooks/${id}`, { method: "DELETE" }),
  toggle: (id: string) => request<Webhook>(`/webhooks/${id}/toggle`, { method: "PATCH" }),
};

export const notifications = {
  list: () => request<Notification[]>("/notifications/"),
  markRead: (id: string) =>
    request<Notification>(`/notifications/${id}/read`, { method: "POST" }),
  markAllRead: () =>
    request<{ status: string }>("/notifications/read-all", { method: "POST" }),
  delete: (id: string) =>
    request<{ status: string }>(`/notifications/${id}`, { method: "DELETE" }),
};

// ── Exports ───────────────────────────────────────────────────────────
export const exports = {
  subdomainsTxt: (wildcardId: string) =>
    `${API_BASE}/export/subdomains/${wildcardId}?format=txt`,
  subdomainsCsv: (wildcardId: string) =>
    `${API_BASE}/export/subdomains/${wildcardId}?format=csv`,
  subdomainsJson: (wildcardId: string) =>
    `${API_BASE}/export/subdomains/${wildcardId}?format=json`,
  findingsCsv: (severity?: string) =>
    `${API_BASE}/export/findings?format=csv${severity ? `&severity=${severity}` : ''}`,
  findingsJson: (severity?: string) =>
    `${API_BASE}/export/findings?format=json${severity ? `&severity=${severity}` : ''}`,
  scanReport: (scanId: string) =>
    `${API_BASE}/export/scan/${scanId}/report`,
  rawLogs: (scanId: string) =>
    `${API_BASE}/export/scan/${scanId}/logs`,
};

// ── Traffic (Attack Surface) ──────────────────────────────────────────
export interface TrafficLog {
  id: string;
  method: string;
  url: string;
  path: string;
  query_params: Record<string, any>;
  request_headers: Record<string, any>;
  request_body: string | null;
  response_status: number | null;
  response_headers: Record<string, any>;
  response_body: string | null;
  source: string;
  created_at: string;
}

export const traffic = {
  list: (limit = 50, skip = 0) =>
    request<TrafficLog[]>(`/traffic/?limit=${limit}&skip=${skip}`),
  analyze: (id: string) =>
    request<{ analysis: string }>(`/traffic/${id}/analyze`, { method: "POST" }),
  clearAll: () => request<{ status: string }>("/traffic/", { method: "DELETE" }),
  getStatus: () => request<{ capture_enabled: boolean }>("/traffic/config/status"),
  toggleCapture: () => request<{ capture_enabled: boolean }>("/traffic/config/toggle", { method: "POST" }),
  exportUrl: () => `${API_BASE}/traffic/action/export`,
  importTraffic: (file: File) => {
    const formData = new FormData();
    formData.append("file", file);
    return fetch(`${API_BASE}/traffic/action/import`, {
      method: 'POST',
      body: formData
    }).then(r => r.json());
  },
};



// ── Scope Rules ───────────────────────────────────────────────────────

export interface ScopeRule {
  id: string;
  wildcard_id: string;
  rule_type: string;
  pattern: string;
  is_regex: boolean;
  description?: string;
  created_at: string;
}

export const scopeRules = {
  list: (wildcardId: string) => request<ScopeRule[]>(`/wildcards/${wildcardId}/scope-rules`),
  create: (wildcardId: string, data: Partial<ScopeRule>) => request<ScopeRule>(`/wildcards/${wildcardId}/scope-rules`, {
    method: "POST",
    body: JSON.stringify(data),
  }),
  delete: (id: string) => request<void>(`/scope-rules/${id}`, { method: "DELETE" }),
};

// ── Chains ────────────────────────────────────────────────────────────

export const chains = {
  list: async () => {
    const res = await fetch(`${API_BASE}/chains/`);
    if (!res.ok) throw new Error('Failed to fetch chains');
    return res.json();
  },
  get: async (id: string) => {
    const res = await fetch(`${API_BASE}/chains/${id}`);
    if (!res.ok) throw new Error('Failed to fetch chain');
    return res.json();
  },
  create: async (data: { name: string; description?: string; hypothesis?: string }) => {
    const res = await fetch(`${API_BASE}/chains/`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    });
    if (!res.ok) throw new Error('Failed to create chain');
    return res.json();
  },
  delete: async (id: string) => {
    const res = await fetch(`${API_BASE}/chains/${id}`, { method: 'DELETE' });
    if (!res.ok) throw new Error('Failed to delete chain');
    return res.json();
  },
  addStep: async (chainId: string, data: { traffic_log_id: string; note?: string; step_order: number }) => {
    const res = await fetch(`${API_BASE}/chains/${chainId}/steps`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    });
    if (!res.ok) throw new Error('Failed to add step');
    return res.json();
  },
  updateStep: async (chainId: string, stepId: string, data: { note?: string; step_order?: number }) => {
    const res = await fetch(`${API_BASE}/chains/${chainId}/steps/${stepId}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    });
    if (!res.ok) throw new Error('Failed to update step');
    return res.json();
  },
  removeStep: async (chainId: string, stepId: string) => {
    const res = await fetch(`${API_BASE}/chains/${chainId}/steps/${stepId}`, { method: 'DELETE' });
    if (!res.ok) throw new Error('Failed to remove step');
    return res.json();
  },
  reorderSteps: async (chainId: string, stepIds: string[]) => {
    const res = await fetch(`${API_BASE}/chains/${chainId}/steps/reorder`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ step_ids: stepIds }),
    });
    if (!res.ok) throw new Error('Failed to reorder steps');
    return res.json();
  },
  analyze: async (id: string) => {
    const res = await fetch(`${API_BASE}/chains/${id}/analyze`, { method: 'POST' });
    if (!res.ok) throw new Error('Failed to analyze chain');
    return res.json();
  },
};



