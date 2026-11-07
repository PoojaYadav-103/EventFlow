import React, { useEffect, useState } from 'react';
import {
  Send,
  CheckCircle2,
  AlertTriangle,
  Clock,
  Skull,
  TrendingUp,
  RefreshCw,
  Webhook,
  ArrowRight,
} from 'lucide-react';
import { api } from '../services/api';
import type { DashboardStats } from '../types';
import { StatusBadge } from '../components/StatusBadge';

interface OverviewProps {
  onNavigate: (tab: string) => void;
  onOpenSimulate: () => void;
  onOpenRegister: () => void;
  refreshTrigger?: number;
}

export const Overview: React.FC<OverviewProps> = ({
  onNavigate,
  onOpenSimulate,
  onOpenRegister,
  refreshTrigger,
}) => {
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);

  const fetchStats = async () => {
    try {
      const data = await api.getDashboardStats();
      setStats(data);
    } catch (err) {
      console.error('Failed to load dashboard statistics', err);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => {
    fetchStats();
    const interval = setInterval(fetchStats, 5000);
    return () => clearInterval(interval);
  }, [refreshTrigger]);

  const handleManualRefresh = () => {
    setRefreshing(true);
    fetchStats();
  };

  const cards = [
    {
      title: 'Total Events',
      value: stats?.total_events ?? 0,
      icon: Send,
      color: 'text-indigo-400',
      bg: 'bg-indigo-500/10',
      border: 'border-indigo-500/20',
    },
    {
      title: 'Successful Deliveries',
      value: stats?.successful_deliveries ?? 0,
      icon: CheckCircle2,
      color: 'text-emerald-400',
      bg: 'bg-emerald-500/10',
      border: 'border-emerald-500/20',
    },
    {
      title: 'Failed Deliveries',
      value: stats?.failed_deliveries ?? 0,
      icon: AlertTriangle,
      color: 'text-rose-400',
      bg: 'bg-rose-500/10',
      border: 'border-rose-500/20',
    },
    {
      title: 'Pending Deliveries',
      value: stats?.pending_deliveries ?? 0,
      icon: Clock,
      color: 'text-amber-400',
      bg: 'bg-amber-500/10',
      border: 'border-amber-500/20',
    },
    {
      title: 'Dead-Letter Queue',
      value: stats?.dead_letter_deliveries ?? 0,
      icon: Skull,
      color: 'text-red-400',
      bg: 'bg-red-500/10',
      border: 'border-red-500/20',
    },
    {
      title: 'Success Rate',
      value: `${stats?.success_rate ?? 100}%`,
      icon: TrendingUp,
      color: 'text-teal-400',
      bg: 'bg-teal-500/10',
      border: 'border-teal-500/20',
    },
  ];

  return (
    <div className="space-y-8">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-white">Platform Overview</h1>
          <p className="text-sm text-slate-400">
            Real-time delivery telemetry, outbox metrics, and webhook health
          </p>
        </div>
        <div className="flex items-center gap-2.5">
          <button
            onClick={handleManualRefresh}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-medium transition-colors"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${refreshing ? 'animate-spin' : ''}`} />
            <span>Refresh</span>
          </button>
          <button
            onClick={onOpenRegister}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-white text-xs font-medium border border-slate-700 transition-colors"
          >
            <Webhook className="w-3.5 h-3.5" />
            <span>New Endpoint</span>
          </button>
        </div>
      </div>

      {/* Metric Cards Grid */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
        {cards.map((c) => {
          const Icon = c.icon;
          return (
            <div
              key={c.title}
              className={`p-4 rounded-xl bg-slate-900 border ${c.border} shadow-sm relative overflow-hidden`}
            >
              <div className="flex items-center justify-between mb-2">
                <span className="text-xs font-medium text-slate-400 truncate">{c.title}</span>
                <div className={`p-1.5 rounded-lg ${c.bg} ${c.color}`}>
                  <Icon className="w-4 h-4" />
                </div>
              </div>
              <div className="text-2xl font-bold text-white tracking-tight">
                {loading ? '—' : c.value}
              </div>
            </div>
          );
        })}
      </div>

      {/* Interactive Quick Callouts */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {/* Outbox & Broker Status Card */}
        <div className="p-5 rounded-2xl bg-slate-900/80 border border-slate-800 flex flex-col justify-between">
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold uppercase tracking-wider text-indigo-400">
                Core Guarantee
              </span>
              <span className="px-2 py-0.5 rounded text-[10px] bg-indigo-500/10 text-indigo-300 border border-indigo-500/20 font-mono">
                At-Least-Once
              </span>
            </div>
            <h3 className="text-base font-semibold text-white">Transactional Outbox</h3>
            <p className="text-xs text-slate-400 leading-relaxed">
              Every domain event, delivery target, and outbox record is committed atomically in a single PostgreSQL transaction. The Outbox Relay sweeps pending records via row-level locks without blocking ingestion.
            </p>
          </div>
          <div className="pt-4 mt-4 border-t border-slate-800/80 flex items-center justify-between text-xs">
            <span className="text-slate-400">Active Endpoints: <strong className="text-white">{stats?.active_endpoints ?? 0}</strong></span>
            <button
              onClick={() => onNavigate('endpoints')}
              className="text-indigo-400 hover:text-indigo-300 flex items-center gap-1 font-medium"
            >
              Manage <ArrowRight className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>

        {/* E-Commerce Simulation Banner */}
        <div className="p-5 rounded-2xl bg-gradient-to-br from-indigo-950/60 to-slate-900 border border-indigo-900/40 flex flex-col justify-between">
          <div className="space-y-2">
            <span className="text-xs font-semibold uppercase tracking-wider text-indigo-400">
              Interactive Testing
            </span>
            <h3 className="text-base font-semibold text-white">E-Commerce Simulator</h3>
            <p className="text-xs text-slate-300 leading-relaxed">
              Dispatch realistic business events (order.placed, order.shipped, order.cancelled) with one click and observe async worker delivery.
            </p>
          </div>
          <button
            onClick={onOpenSimulate}
            className="mt-4 w-full py-2 bg-indigo-600 hover:bg-indigo-500 text-white rounded-lg text-xs font-semibold shadow transition-all flex items-center justify-center gap-1.5"
          >
            <Send className="w-3.5 h-3.5" />
            <span>Launch Event Simulator</span>
          </button>
        </div>

        {/* Mock Receiver Card */}
        <div className="p-5 rounded-2xl bg-slate-900/80 border border-slate-800 flex flex-col justify-between">
          <div className="space-y-2">
            <span className="text-xs font-semibold uppercase tracking-wider text-emerald-400">
              Zero Config Receiver
            </span>
            <h3 className="text-base font-semibold text-white">Built-in Mock Receiver</h3>
            <p className="text-xs text-slate-400 leading-relaxed">
              Inspect incoming webhook payloads, measure round-trip latency, and verify cryptographic HMAC-SHA256 signatures in real-time.
            </p>
          </div>
          <button
            onClick={() => onNavigate('mock')}
            className="mt-4 w-full py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg text-xs font-semibold border border-slate-700 transition-colors flex items-center justify-center gap-1.5"
          >
            <span>Open Mock Console</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      {/* Recent Deliveries Table */}
      <div className="p-6 rounded-2xl bg-slate-900 border border-slate-800 shadow-sm space-y-4">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-base font-semibold text-white">Recent Delivery Activity</h2>
            <p className="text-xs text-slate-400">Latest webhook dispatches executed across all endpoints</p>
          </div>
          <button
            onClick={() => onNavigate('deliveries')}
            className="text-xs text-indigo-400 hover:underline flex items-center gap-1 font-medium"
          >
            View all deliveries <ArrowRight className="w-3.5 h-3.5" />
          </button>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="border-b border-slate-800 text-slate-400">
                <th className="pb-3 font-medium">Delivery ID</th>
                <th className="pb-3 font-medium">Event Type</th>
                <th className="pb-3 font-medium">Destination URL</th>
                <th className="pb-3 font-medium">Status</th>
                <th className="pb-3 font-medium">Attempts</th>
                <th className="pb-3 font-medium">HTTP Code</th>
                <th className="pb-3 font-medium">Timestamp</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-mono">
              {stats?.recent_deliveries && stats.recent_deliveries.length > 0 ? (
                stats.recent_deliveries.map((del) => (
                  <tr key={del.id} className="hover:bg-slate-800/40 transition-colors">
                    <td className="py-3 text-slate-300 font-semibold truncate max-w-[120px]">
                      {del.id.substring(0, 8)}...
                    </td>
                    <td className="py-3 font-sans">
                      <span className="px-2 py-0.5 rounded bg-slate-800 text-indigo-300 border border-slate-700 text-[11px] font-medium">
                        {del.event_type}
                      </span>
                    </td>
                    <td className="py-3 font-sans text-slate-300 truncate max-w-[220px]" title={del.endpoint_url}>
                      {del.endpoint_url}
                    </td>
                    <td className="py-3 font-sans">
                      <StatusBadge status={del.status} />
                    </td>
                    <td className="py-3 text-slate-300">
                      {del.attempt_count} / {del.max_attempts}
                    </td>
                    <td className="py-3 font-sans">
                      {del.last_http_status ? (
                        <span className={`px-2 py-0.5 rounded text-[11px] font-medium ${
                          del.last_http_status >= 200 && del.last_http_status < 300
                            ? 'bg-emerald-500/10 text-emerald-400'
                            : 'bg-rose-500/10 text-rose-400'
                        }`}>
                          HTTP {del.last_http_status}
                        </span>
                      ) : (
                        <span className="text-slate-500">—</span>
                      )}
                    </td>
                    <td className="py-3 font-sans text-slate-400">
                      {new Date(del.created_at).toLocaleTimeString()}
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={7} className="py-8 text-center text-slate-500 font-sans">
                    No deliveries recorded yet. Publish an event to start!
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
