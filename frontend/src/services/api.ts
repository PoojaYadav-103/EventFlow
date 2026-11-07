import type {
  DashboardStats,
  Endpoint,
  EndpointCreateInput,
  EventDetail,
  EventItem,
  EventPublishInput,
  DeliveryDetail,
  DeliveryItem,
  MockReceiverConfig,
  MockWebhookLog,
} from '../types';

const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:8000/api/v1';
const ROOT_BASE = API_BASE.replace(/\/api\/v1\/?$/, '');

async function request<T>(path: string, options: RequestInit = {}): Promise<T> {
  const url = `${API_BASE}${path}`;
  const response = await fetch(url, {
    headers: {
      'Content-Type': 'application/json',
      ...options.headers,
    },
    ...options,
  });

  if (!response.ok) {
    let errorDetail = `Request failed: ${response.status} ${response.statusText}`;
    try {
      const errJson = await response.json();
      if (errJson.detail) {
        errorDetail = typeof errJson.detail === 'string' ? errJson.detail : JSON.stringify(errJson.detail);
      }
    } catch {
      // ignore
    }
    throw new Error(errorDetail);
  }

  if (response.status === 204) {
    return {} as T;
  }

  return response.json();
}

export const api = {
  // Health - checks backend root /health endpoint
  checkHealth: async () => {
    const res = await fetch(`${ROOT_BASE}/health`);
    return res.json();
  },

  // Dashboard
  getDashboardStats: () => request<DashboardStats>('/dashboard/stats'),

  // Endpoints
  getEndpoints: (isActive?: boolean) => {
    const query = isActive !== undefined ? `?is_active=${isActive}` : '';
    return request<Endpoint[]>(`/endpoints${query}`);
  },
  getEndpoint: (id: string) => request<Endpoint>(`/endpoints/${id}`),
  createEndpoint: (data: EndpointCreateInput) =>
    request<Endpoint>('/endpoints', {
      method: 'POST',
      body: JSON.stringify(data),
    }),
  updateEndpoint: (id: string, data: Partial<Endpoint>) =>
    request<Endpoint>(`/endpoints/${id}`, {
      method: 'PATCH',
      body: JSON.stringify(data),
    }),
  rollSecret: (id: string) =>
    request<{ endpoint_id: string; signing_secret: string; signing_secret_masked: string; message: string }>(
      `/endpoints/${id}/roll-secret`,
      { method: 'POST' }
    ),
  deleteEndpoint: (id: string) =>
    request<void>(`/endpoints/${id}`, {
      method: 'DELETE',
    }),

  // Events
  getEvents: (eventType?: string) => {
    const query = eventType ? `?event_type=${encodeURIComponent(eventType)}` : '';
    return request<EventItem[]>(`/events${query}`);
  },
  getEvent: (id: string) => request<EventDetail>(`/events/${id}`),
  publishEvent: (data: EventPublishInput) =>
    request<EventItem>('/events', {
      method: 'POST',
      body: JSON.stringify(data),
    }),

  // Outbox Status
  getOutboxStatus: () =>
    request<{ pending: number; published: number; failed: number }>('/outbox/status'),

  // Deliveries
  getDeliveries: (status?: string, eventId?: string, endpointId?: string) => {
    const params = new URLSearchParams();
    if (status && status !== 'ALL') params.append('status', status);
    if (eventId) params.append('event_id', eventId);
    if (endpointId) params.append('endpoint_id', endpointId);
    const query = params.toString() ? `?${params.toString()}` : '';
    return request<DeliveryItem[]>(`/deliveries${query}`);
  },
  getDelivery: (id: string) => request<DeliveryDetail>(`/deliveries/${id}`),
  retryDelivery: (id: string) =>
    request<{ delivery_id: string; status: string; message: string }>(`/deliveries/${id}/retry`, {
      method: 'POST',
    }),

  // Mock Receiver
  getMockLogs: () => request<MockWebhookLog[]>('/mock-receiver/logs'),
  clearMockLogs: () => request<void>('/mock-receiver/logs', { method: 'DELETE' }),
  getMockConfig: () => request<MockReceiverConfig>('/mock-receiver/config'),
  updateMockConfig: (config: MockReceiverConfig) =>
    request<MockReceiverConfig>('/mock-receiver/config', {
      method: 'POST',
      body: JSON.stringify(config),
    }),
};

