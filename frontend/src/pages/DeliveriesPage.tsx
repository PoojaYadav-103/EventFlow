import React, { useEffect, useState } from 'react';
import {
  RotateCcw,
  Eye,
  RefreshCw,
  Clock,
  Radio,
  X,
  Code2,
} from 'lucide-react';
import { api } from '../services/api';
import type { DeliveryItem, DeliveryDetail } from '../types';
import { StatusBadge } from '../components/StatusBadge';

interface DeliveriesPageProps {
  refreshTrigger?: number;
}

export const DeliveriesPage: React.FC<DeliveriesPageProps> = ({ refreshTrigger }) => {
  const [deliveries, setDeliveries] = useState<DeliveryItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [statusFilter, setStatusFilter] = useState('ALL');
  const [refreshing, setRefreshing] = useState(false);
  const [retryingId, setRetryingId] = useState<string | null>(null);

  // Detail Modal
  const [selectedDelivery, setSelectedDelivery] = useState<DeliveryDetail | null>(null);

  const fetchDeliveries = async (status = statusFilter) => {
    try {
      const data = await api.getDeliveries(status === 'ALL' ? undefined : status);
      setDeliveries(data);
    } catch (err) {
      console.error('Failed to load deliveries', err);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => {
    fetchDeliveries(statusFilter);
    const interval = setInterval(() => fetchDeliveries(statusFilter), 5000);
    return () => clearInterval(interval);
  }, [statusFilter, refreshTrigger]);

  const handleManualRetry = async (delId: string) => {
    setRetryingId(delId);
    try {
      await api.retryDelivery(delId);
      fetchDeliveries();
    } catch (err: any) {
      alert(`Retry failed: ${err.message}`);
    } finally {
      setRetryingId(null);
    }
  };

  const handleInspect = async (delId: string) => {
    try {
      const detail = await api.getDelivery(delId);
      setSelectedDelivery(detail);
    } catch (err: any) {
      alert(`Failed to load delivery details: ${err.message}`);
    }
  };

  const statusOptions = ['ALL', 'SUCCESS', 'PROCESSING', 'RETRYING', 'DEAD_LETTER', 'PENDING', 'FAILED'];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-white">Webhook Deliveries</h1>
          <p className="text-sm text-slate-400">
            Lifecycle logs, latency metrics, HTTP status codes, and manual retry controls
          </p>
        </div>
        <button
          onClick={() => {
            setRefreshing(true);
            fetchDeliveries();
          }}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-medium transition-colors self-start sm:self-auto"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${refreshing ? 'animate-spin' : ''}`} />
          <span>Refresh</span>
        </button>
      </div>

      {/* Filter Tabs */}
      <div className="flex items-center gap-1.5 overflow-x-auto pb-1">
        {statusOptions.map((st) => (
          <button
            key={st}
            onClick={() => setStatusFilter(st)}
            className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-colors shrink-0 ${statusFilter === st
                ? 'bg-indigo-600 text-white shadow'
                : 'bg-slate-900 text-slate-400 hover:text-slate-200 border border-slate-800'
              }`}
          >
            {st}
          </button>
        ))}
      </div>

      {/* Deliveries Table */}
      <div className="p-6 rounded-2xl bg-slate-900 border border-slate-800 shadow-sm overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="border-b border-slate-800 text-slate-400">
                <th className="pb-3 font-medium">Delivery ID</th>
                <th className="pb-3 font-medium">Event Type</th>
                <th className="pb-3 font-medium">Target URL</th>
                <th className="pb-3 font-medium">Status</th>
                <th className="pb-3 font-medium">Tries</th>
                <th className="pb-3 font-medium">Last HTTP Code</th>
                <th className="pb-3 font-medium">Error / Reason</th>
                <th className="pb-3 font-medium text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-mono">
              {loading ? (
                <tr>
                  <td colSpan={8} className="py-8 text-center text-slate-500 font-sans">
                    Loading deliveries...
                  </td>
                </tr>
              ) : deliveries.length > 0 ? (
                deliveries.map((del) => (
                  <tr key={del.id} className="hover:bg-slate-800/40 transition-colors">
                    <td className="py-4 text-slate-300 font-semibold truncate max-w-[120px]">
                      {del.id.substring(0, 8)}...
                    </td>
                    <td className="py-4 font-sans">
                      <span className="px-2 py-0.5 rounded bg-slate-800 text-indigo-300 border border-slate-700 text-[11px] font-medium">
                        {del.event_type}
                      </span>
                    </td>
                    <td className="py-4 font-sans text-slate-300 truncate max-w-[200px]" title={del.endpoint_url}>
                      {del.endpoint_url}
                    </td>
                    <td className="py-4 font-sans">
                      <StatusBadge status={del.status} />
                    </td>
                    <td className="py-4 text-slate-300">
                      {del.attempt_count} / {del.max_attempts}
                    </td>
                    <td className="py-4 font-sans">
                      {del.last_http_status ? (
                        <span
                          className={`px-2 py-0.5 rounded text-[11px] font-medium ${del.last_http_status >= 200 && del.last_http_status < 300
                              ? 'bg-emerald-500/10 text-emerald-400'
                              : 'bg-rose-500/10 text-rose-400'
                            }`}
                        >
                          HTTP {del.last_http_status}
                        </span>
                      ) : (
                        <span className="text-slate-600">—</span>
                      )}
                    </td>
                    <td className="py-4 font-sans text-slate-400 truncate max-w-[180px]" title={del.last_error || ''}>
                      {del.last_error ? (
                        <span className="text-rose-400 text-[11px]">{del.last_error}</span>
                      ) : (
                        <span className="text-slate-600">—</span>
                      )}
                    </td>
                    <td className="py-4 font-sans text-right">
                      <div className="flex items-center justify-end gap-1.5">
                        <button
                          onClick={() => handleInspect(del.id)}
                          title="Inspect Attempts & Timeline"
                          className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white transition-colors"
                        >
                          <Eye className="w-3.5 h-3.5" />
                        </button>
                        <button
                          onClick={() => handleManualRetry(del.id)}
                          disabled={retryingId === del.id}
                          title="Trigger Manual Retry"
                          className="flex items-center gap-1 px-2.5 py-1 rounded-lg bg-indigo-600/20 hover:bg-indigo-600/30 text-indigo-300 border border-indigo-500/30 text-[11px] font-medium transition-colors disabled:opacity-50"
                        >
                          <RotateCcw className={`w-3 h-3 ${retryingId === del.id ? 'animate-spin' : ''}`} />
                          <span>Retry</span>
                        </button>
                      </div>
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={8} className="py-12 text-center text-slate-500 font-sans">
                    <Radio className="w-8 h-8 mx-auto mb-2 opacity-40" />
                    No delivery records found matching filter.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Inspect Detail Modal */}
      {selectedDelivery && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/75 backdrop-blur-sm">
          <div className="relative w-full max-w-2xl bg-slate-900 border border-slate-800 rounded-2xl shadow-2xl p-6 overflow-hidden max-h-[90vh] flex flex-col">
            {/* Modal Header */}
            <div className="flex items-center justify-between pb-4 border-b border-slate-800">
              <div>
                <div className="flex items-center gap-2">
                  <h3 className="text-base font-semibold text-white">Delivery Inspection</h3>
                  <StatusBadge status={selectedDelivery.status} />
                </div>
                <p className="text-xs font-mono text-slate-400 mt-0.5">ID: {selectedDelivery.id}</p>
              </div>
              <button
                onClick={() => setSelectedDelivery(null)}
                className="p-1 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Modal Content */}
            <div className="py-4 space-y-6 overflow-y-auto flex-1 text-xs">
              {/* Target & Metadata */}
              <div className="grid grid-cols-2 gap-3 p-3 rounded-xl bg-slate-950 border border-slate-800">
                <div>
                  <span className="text-slate-500 block">Destination URL</span>
                  <span className="font-mono text-white text-[11px] break-all">{selectedDelivery.endpoint_url}</span>
                </div>
                <div>
                  <span className="text-slate-500 block">Event Type</span>
                  <span className="font-medium text-indigo-300">{selectedDelivery.event_type}</span>
                </div>
                <div>
                  <span className="text-slate-500 block">Attempts Completed</span>
                  <span className="text-white font-mono">{selectedDelivery.attempt_count} / {selectedDelivery.max_attempts}</span>
                </div>
                <div>
                  <span className="text-slate-500 block">Signing Secret Used</span>
                  <span className="font-mono text-slate-400">{selectedDelivery.signing_secret_masked || 'whsec_••••'}</span>
                </div>
              </div>

              {/* Delivery Attempts Timeline */}
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-300 flex items-center gap-1.5">
                    <Clock className="w-4 h-4 text-indigo-400" />
                    <span>Attempt Execution Timeline ({selectedDelivery.attempts?.length || 0})</span>
                  </h4>
                </div>

                {selectedDelivery.attempts && selectedDelivery.attempts.length > 0 ? (
                  <div className="space-y-2">
                    {selectedDelivery.attempts.map((att) => (
                      <div
                        key={att.id}
                        className="p-3.5 rounded-xl bg-slate-950 border border-slate-800 space-y-2"
                      >
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-2">
                            <span className="font-semibold text-white">Attempt #{att.attempt_number}</span>
                            <span className={`px-2 py-0.5 rounded text-[10px] font-medium ${att.status === 'SUCCESS' ? 'bg-emerald-500/10 text-emerald-400' : 'bg-rose-500/10 text-rose-400'
                              }`}>
                              {att.status}
                            </span>
                            {att.http_status && (
                              <span className="text-slate-400 font-mono text-[11px]">
                                HTTP {att.http_status}
                              </span>
                            )}
                          </div>
                          <span className="text-slate-500 font-mono text-[11px]">
                            {att.response_time_ms ? `${att.response_time_ms} ms` : '—'}
                          </span>
                        </div>

                        {att.error_message && (
                          <div className="p-2 rounded bg-rose-950/30 border border-rose-900/40 text-rose-300 text-[11px]">
                            {att.error_message}
                          </div>
                        )}

                        {/* Request Headers Snippet */}
                        {att.request_headers && (
                          <div className="pt-1">
                            <span className="text-[10px] uppercase font-semibold text-slate-500 block mb-1">
                              Request Headers Sent (with HMAC)
                            </span>
                            <pre className="p-2 rounded bg-slate-900 text-[10px] font-mono text-slate-300 overflow-x-auto">
                              {JSON.stringify(att.request_headers, null, 2)}
                            </pre>
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 text-center text-slate-500">
                    No attempt records yet. Awaiting worker execution.
                  </div>
                )}
              </div>

              {/* Event Payload */}
              {selectedDelivery.event_payload && (
                <div className="space-y-1.5">
                  <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-300 flex items-center gap-1.5">
                    <Code2 className="w-4 h-4 text-emerald-400" />
                    <span>Domain Event Payload</span>
                  </h4>
                  <pre className="p-3 rounded-xl bg-slate-950 border border-slate-800 text-xs font-mono text-emerald-400 overflow-x-auto max-h-48">
                    {JSON.stringify(selectedDelivery.event_payload, null, 2)}
                  </pre>
                </div>
              )}
            </div>

            {/* Modal Footer */}
            <div className="pt-3 border-t border-slate-800 flex justify-end">
              <button
                onClick={() => setSelectedDelivery(null)}
                className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-white text-xs font-medium rounded-lg"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
