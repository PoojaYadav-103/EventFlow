export type DeliveryStatus =
  | 'PENDING'
  | 'PROCESSING'
  | 'DELIVERING'
  | 'SUCCESS'
  | 'RETRYING'
  | 'FAILED'
  | 'DEAD_LETTER';

export interface Endpoint {
  id: string;
  url: string;
  description?: string;
  is_active: boolean;
  event_types: string[];
  rate_limit_per_minute?: number;
  signing_secret_masked: string;
  signing_secret?: string; // Only present when newly created or rotated
  created_at: string;
  updated_at: string;
  deliveries_count: number;
}

export interface EndpointCreateInput {
  url: string;
  description?: string;
  event_types: string[];
  rate_limit_per_minute?: number;
}

export interface EventItem {
  id: string;
  event_type: string;
  payload: Record<string, any>;
  idempotency_key?: string;
  created_at: string;
  deliveries_count: number;
  successful_deliveries_count: number;
}

export interface DeliverySummary {
  id: string;
  endpoint_id: string;
  endpoint_url: string;
  status: DeliveryStatus;
  attempt_count: number;
  last_http_status?: number;
  created_at: string;
}

export interface EventDetail extends EventItem {
  deliveries: DeliverySummary[];
}

export interface EventPublishInput {
  event_type: string;
  payload: Record<string, any>;
  idempotency_key?: string;
}

export interface DeliveryAttempt {
  id: string;
  delivery_id: string;
  attempt_number: number;
  status: 'STARTED' | 'SUCCESS' | 'FAILED' | 'UNKNOWN';
  http_status?: number;
  response_time_ms?: number;
  request_headers?: Record<string, string>;
  response_headers?: Record<string, string>;
  response_body?: string;
  error_message?: string;
  executed_at: string;
}

export interface DeliveryItem {
  id: string;
  event_id: string;
  endpoint_id: string;
  endpoint_url: string;
  event_type: string;
  status: DeliveryStatus;
  attempt_count: number;
  max_attempts: number;
  next_retry_at?: string;
  last_http_status?: number;
  last_error?: string;
  created_at: string;
  updated_at: string;
}

export interface DeliveryDetail extends DeliveryItem {
  event_payload?: Record<string, any>;
  signing_secret_masked?: string;
  attempts: DeliveryAttempt[];
}

export interface DashboardStats {
  total_events: number;
  total_deliveries: number;
  successful_deliveries: number;
  failed_deliveries: number;
  pending_deliveries: number;
  dead_letter_deliveries: number;
  success_rate: number;
  active_endpoints: number;
  total_endpoints: number;
  processing_deliveries?: number;
  retrying_deliveries?: number;
  recent_deliveries: DeliveryItem[];
}

export interface MockWebhookLog {
  id: string;
  received_at: string;
  event_id?: string;
  delivery_id?: string;
  event_type?: string;
  signature_header?: string;
  signature_valid?: boolean;
  headers: Record<string, string>;
  payload: Record<string, any>;
}

export interface MockReceiverConfig {
  status_code: number;
  delay_seconds: number;
  reject_all: boolean;
  signing_secret?: string | null;
}

