# EventFlow — Reliable Webhook Delivery Platform

EventFlow is an industry-grade, asynchronous webhook delivery developer platform engineered in Python (FastAPI, SQLAlchemy, Celery), PostgreSQL, Redis, and React (TypeScript + Vite).

It solves the challenges of reliable webhook dispatch in distributed systems: zero dual-write risk via a **Transactional Outbox**, crash-resilient delivery, explicit topic-based event subscriptions, cryptographic HMAC-SHA256 signing, and an interactive developer dashboard.

---

## Architecture Overview

```
E-Commerce Simulator / API Client
               │
               ▼
   FastAPI Event Ingestion Layer
               │
               ▼ (Atomic Single Transaction)
    PostgreSQL Database
    ├── events (idempotency deduplication)
    ├── endpoints (topic subscriptions)
    ├── deliveries (status: PENDING)
    └── outbox_events (status: PENDING)
               │
               ▼ (SELECT FOR UPDATE SKIP LOCKED)
      Outbox Relay Sweeper
               │
               ▼ (Enqueues Task)
          Redis Queue
               │
               ▼
     Celery Delivery Workers
               │
               ▼ (HTTP POST with HMAC-SHA256 & ID Headers)
   Subscribed Webhook Receivers
   (Inventory, Notifications, Mock Receiver)
               │
               ▼
   Delivery Attempt History & Status Update
```

---

## Milestone 1 Implemented Features

1. **Relational Data Layer & Alembic Migrations**:
   - `endpoints`: Webhook destinations with topic subscriptions (`["order.placed"]` or `["*"]`), masked secrets, and soft deletion to preserve historical logs.
   - `events`: Domain events with unique index deduplication via `idempotency_key`.
   - `deliveries`: Tracks individual delivery pipelines with unique constraint `(event_id, endpoint_id)`.
   - `delivery_attempts`: Immutable audit log of every executed HTTP call (latency ms, HTTP status code, request headers, response headers).
   - `outbox_events`: Transactional outbox records ensuring zero direct queue dual-writes.
2. **Explicit Topic Subscriptions**:
   - Endpoints subscribe to specific event types or wildcard `*`.
   - Ingestion creates delivery records **only** for matching active, non-deleted endpoints.
3. **Primary Transactional Outbox**:
   - `POST /api/v1/events` persists Event + Deliveries + Outbox records in **one atomic PostgreSQL transaction**.
   - FastAPI routes **never directly enqueue tasks to Redis**.
4. **Outbox Relay Processor**:
   - Background worker sweeps pending outbox entries using `SELECT ... FOR UPDATE SKIP LOCKED` and publishes tasks to Redis.
5. **Celery Worker & Delivery Engine**:
   - Executes HTTP POST requests with strict timeouts, latency measurement, and attempt tracking.
6. **Built-in Mock Webhook Receiver**:
   - Interactive local test endpoint (`/api/v1/mock-receiver/webhook`) logging incoming webhooks, headers, and HMAC signatures.
7. **Developer Dashboard (React + TypeScript + Vite + Tailwind CSS)**:
   - **Overview**: Real-time metrics cards, delivery success rate, recent activity stream.
   - **Endpoints**: Registration modal with copyable signing secret, active/inactive toggle, soft deletion.
   - **Events**: Historical events list, payload inspector, e-commerce simulation modal (`order.placed`, `order.shipped`, etc.).
   - **Deliveries**: Live statuses (`PENDING`, `PROCESSING`, `SUCCESS`, `RETRYING`, `DEAD_LETTER`), attempt counts, HTTP codes, error inspection.
   - **Mock Console**: Live stream of webhooks received with HMAC validity badge.
8. **Containerization**:
   - Multi-container `docker-compose.yml` orchestrating PostgreSQL, Redis, FastAPI, Celery worker, Celery beat, and React frontend.

---

## Milestone 2: Reliability Engineering

Module 2 hardens EventFlow with distributed systems concurrency, lease fencing, and crash-resilient attempt reconciliation:

1. **Atomic Worker Leasing & Concurrency Fencing**:
   - Deliveries are claimed using `FOR UPDATE OF deliveries SKIP LOCKED`.
   - Each worker claims a delivery by generating a unique `lease_token` (UUIDv4), associating `lease_worker_id`, and setting `lease_expires_at = NOW() + 30s`.
   - Guard against premature retry execution: worker claim validates `next_retry_at IS NULL OR next_retry_at <= NOW()`.
   - Post-HTTP CAS fencing check (`WHERE id = :id AND lease_token = :token AND lease_expires_at > NOW()`). If lease expired or reclaimed, worker is fenced off and cannot mutate `deliveries`.

2. **Pre-flight 3-Phase Attempt Tracking**:
   - Worker pre-flight commits `DeliveryAttempt(status=STARTED)` to the database **before** opening the HTTP socket.
   - If a worker process crashes or is killed during network I/O, the attempt record is guaranteed to exist.

3. **Crash Recovery Reaper (`reap_stuck_deliveries_task`)**:
   - Periodic Celery Beat task (every 15s) queries `deliveries` WHERE `status = 'PROCESSING' AND lease_expires_at <= NOW()` with `FOR UPDATE SKIP LOCKED`.
   - Reconciles orphaned `STARTED` attempts to `UNKNOWN` with audit metadata (`[CRASH REAPER]`).
   - Transitions deliveries to `RETRYING` (with backoff + OutboxEvent) or `DEAD_LETTER` if max attempts are exhausted.

4. **Stale Worker Late Completion Reconciliation**:
   - If Worker A experiences a network delay exceeding its lease duration, the Crash Reaper reclaims the delivery and assigns it to Worker B.
   - When Worker A's slow HTTP request eventually arrives, Worker A's CAS check fails.
   - Worker A **never mutates the `deliveries` table**.
   - Worker A reconciles its own attempt (`STARTED` → `UNKNOWN` → `SUCCESS` or `FAILED`) with an audit trail note (`[STALE WORKER RECONCILIATION]`).

5. **Exponential Backoff with Uniform Additive Jitter & Retry-After**:
   - Formula: $\text{delay} = \min(\text{max\_delay}, \min(\text{max\_delay}, \text{base} \times 2^{\text{attempt}-1}) + \text{uniform}(0, \text{jitter}))$
   - Standard defaults: Base = 5.0s, Max = 3600.0s, Jitter = 2.0s.
   - Uniform additive jitter spreads retry spikes evenly across concurrent clients to avoid thundering herds.
   - Respects receiver `Retry-After` headers on HTTP 429 and 503 (supports delay-seconds and RFC 7231 HTTP-date).

6. **Sequential Attempt Tracking vs. Active Retry Quotas**:
   - `deliveries.attempt_count`: Tracks attempts within the *active* retry cycle (1 ... 5). Reset to 0 on manual retry to grant a fresh automatic cycle quota.
   - `delivery_attempts.attempt_number`: Globally sequential counter ($1, 2, 3, 4, 5, 6 \dots$) preserved across all manual retry cycles with composite uniqueness constraint `(delivery_id, attempt_number)`.

7. **Universal Transactional Outbox Invariant**:
   - Initial dispatch, automatic retries, and manual retries **all** dispatch strictly via the PostgreSQL transactional outbox.
   - Manual retry route `POST /api/v1/deliveries/{id}/retry` creates an `OutboxEvent` within the exact same database transaction that resets delivery state.

---

### Option A: Running with Docker Compose (Recommended)

1. Clone or navigate to the repository:
   ```bash
   cd EventFlow
   ```
2. Start all services:
   ```bash
   docker compose up --build
   ```
3. Open the applications:
   - **Developer Dashboard**: `http://localhost:3000`
   - **FastAPI Interactive Swagger Docs**: `http://localhost:8000/docs`
   - **Mock Receiver URL**: `http://localhost:8000/api/v1/mock-receiver/webhook`

---

### Option B: Running Locally (Development Mode)

#### 1. Backend Setup
```bash
# Navigate to backend
cd backend

# Create virtual environment & activate
python -m venv .venv
.\.venv\Scripts\activate   # Windows
# source .venv/bin/activate # Linux/macOS

# Install dependencies
pip install -r requirements.txt

# Run migrations (or tables auto-create on startup)
alembic upgrade head

# Start FastAPI server
uvicorn app.main:app --reload --port 8000
```

#### 2. Start Celery Worker & Beat (Requires local Redis)
```bash
# In a second terminal (Celery Worker):
celery -A app.workers.celery_app worker --loglevel=info

# In a third terminal (Outbox Relay Beat):
celery -A app.workers.celery_app beat --loglevel=info
```

#### 3. Frontend Setup
```bash
cd frontend
pnpm install
pnpm run dev
```
Open `http://localhost:5173` in your browser.

---

## Running the Automated Test Suite

EventFlow includes a comprehensive automated Pytest test suite covering all core requirements:

```bash
python -m pytest backend/tests -v
```

### Verified Test Scenarios:
1. `test_successful_webhook_delivery`: Delivery record creation and successful HTTP 200 delivery.
2. `test_failed_webhook_response`: HTTP 500 failure handling and transition to RETRYING.
3. `test_register_webhook_success`: Endpoint registration and secret generation.
4. `test_list_endpoints_masks_secrets`: Cryptographic secret masking in listings.
5. `test_register_invalid_input`: URL scheme and required field validation.
6. `test_toggle_endpoint_active_status`: Endpoint enable/disable toggle.
7. `test_roll_signing_secret`: Secret rotation.
8. `test_soft_delete_preserves_history`: Soft deletion preserving delivery audit records.
9. `test_publish_event_success`: Event publishing via transactional outbox.
10. `test_inactive_endpoint_does_not_receive_events`: Deactivated endpoint isolation.
11. `test_event_type_filtering`: Topic subscription matching.
12. `test_client_idempotency_key_prevents_duplicate_events`: Ingestion idempotency.
13. `test_delivery_execution_idempotency`: Task execution idempotency.
14. `test_mock_receiver_flow`: Built-in mock receiver logging & HMAC header verification.
15. `test_mock_receiver_error_simulation`: Mock receiver failure simulation.
16. `test_dead_letter_on_exhausted_retries`: Dead-letter queue transition upon reaching max attempts.
17. `test_retry_failed_delivery_and_succeed`: Backoff recovery on subsequent attempt.
18. `test_manual_retry_action`: Manual retry creating outbox record.
19. `test_ssrf_blocks_private_and_metadata_ips`: SSRF protection against private CIDRs and AWS/GCP metadata IP.
20. `test_ssrf_rejects_non_http_schemes`: Rejection of file://, ftp:// schemes.
21. `test_hmac_signature_generation_and_verification`: HMAC-SHA256 signature verification & replay tolerance.

---

## API Endpoints Reference

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/health` | System health & database connection check |
| `POST` | `/api/v1/endpoints` | Register webhook endpoint (returns secret once) |
| `GET` | `/api/v1/endpoints` | List endpoints (masked secrets, delivery counts) |
| `GET` | `/api/v1/endpoints/{id}` | Get endpoint details |
| `PATCH` | `/api/v1/endpoints/{id}` | Update endpoint (toggle active, change URL) |
| `POST` | `/api/v1/endpoints/{id}/roll-secret` | Rotate HMAC signing secret |
| `DELETE` | `/api/v1/endpoints/{id}` | Soft delete endpoint (preserves historical logs) |
| `POST` | `/api/v1/events` | Publish domain event (writes to Outbox atomically) |
| `GET` | `/api/v1/events` | List published events |
| `GET` | `/api/v1/events/{id}` | Event details with payload & delivery statuses |
| `POST` | `/api/v1/outbox/process` | Trigger Transactional Outbox sweep manually |
| `GET` | `/api/v1/deliveries` | List deliveries (filter by status, event, endpoint) |
| `GET` | `/api/v1/deliveries/{id}` | Get delivery attempt timeline & latency logs |
| `POST` | `/api/v1/deliveries/{id}/retry` | Manual retry (atomically writes new Outbox record) |
| `GET` | `/api/v1/dashboard/stats` | Aggregated dashboard telemetry |
| `POST` | `/api/v1/mock-receiver/webhook` | Built-in test webhook destination |
| `GET` | `/api/v1/mock-receiver/logs` | Inspect webhooks received by mock receiver |
| `POST` | `/api/v1/mock-receiver/config` | Configure mock receiver response (HTTP 200, 500, delay) |

