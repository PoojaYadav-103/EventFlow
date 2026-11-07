import React, { useEffect, useState } from 'react';
import { ShieldCheck, Copy, Check, Trash2, CheckCircle2, AlertCircle, Settings } from 'lucide-react';
import { api } from '../services/api';
import type { MockReceiverConfig, MockWebhookLog } from '../types';

export const MockReceiverPage: React.FC = () => {
  const [logs, setLogs] = useState<MockWebhookLog[]>([]);
  const [loading, setLoading] = useState(true);
  const [config, setConfig] = useState<MockReceiverConfig>({
    status_code: 200,
    delay_seconds: 0,
    reject_all: false,
  });
  const [copiedDocker, setCopiedDocker] = useState(false);
  const [copiedLocal, setCopiedLocal] = useState(false);
  const [savingConfig, setSavingConfig] = useState(false);

  const dockerWebhookUrl = 'http://backend:8000/api/v1/mock-receiver/webhook';
  const localhostWebhookUrl = 'http://localhost:8000/api/v1/mock-receiver/webhook';

  const fetchData = async () => {
    try {
      const [fetchedLogs, fetchedConfig] = await Promise.all([
        api.getMockLogs(),
        api.getMockConfig(),
      ]);
      setLogs(fetchedLogs);
      setConfig(fetchedConfig);
    } catch (err) {
      console.error('Failed to load mock receiver data', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 3000);
    return () => clearInterval(interval);
  }, []);

  const handleCopyDocker = () => {
    navigator.clipboard.writeText(dockerWebhookUrl);
    setCopiedDocker(true);
    setTimeout(() => setCopiedDocker(false), 2000);
  };

  const handleCopyLocal = () => {
    navigator.clipboard.writeText(localhostWebhookUrl);
    setCopiedLocal(true);
    setTimeout(() => setCopiedLocal(false), 2000);
  };

  const handleSaveConfig = async (e: React.FormEvent) => {
    e.preventDefault();
    setSavingConfig(true);
    try {
      await api.updateMockConfig(config);
      alert('Mock receiver response behavior updated.');
    } catch (err: any) {
      alert(`Failed to update config: ${err.message}`);
    } finally {
      setSavingConfig(false);
    }
  };

  const handleClearLogs = async () => {
    try {
      await api.clearMockLogs();
      setLogs([]);
    } catch (err: any) {
      alert(`Failed to clear logs: ${err.message}`);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-white">Mock Webhook Receiver</h1>
          <p className="text-sm text-slate-400">
            Built-in inspection target to test webhook delivery, failure recovery, and HMAC verification
          </p>
        </div>
        <button
          onClick={handleClearLogs}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-rose-900/40 text-slate-400 hover:text-rose-300 text-xs font-medium border border-slate-700/60 transition-colors self-start sm:self-auto"
        >
          <Trash2 className="w-3.5 h-3.5" />
          <span>Clear Logs</span>
        </button>
      </div>

      {/* Target URL Banners */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* Docker Compose Target */}
        <div className="p-4 rounded-2xl bg-indigo-950/40 border border-indigo-500/30 shadow-md flex flex-col justify-between gap-3">
          <div>
            <div className="flex items-center justify-between mb-1">
              <span className="text-[11px] font-semibold uppercase tracking-wider text-indigo-400">
                Docker Compose Network (Recommended)
              </span>
              <span className="text-[10px] px-2 py-0.5 rounded-full bg-indigo-500/20 text-indigo-300 border border-indigo-500/30 font-mono">
                container-to-container
              </span>
            </div>
            <div className="font-mono text-xs text-white font-medium break-all select-all py-1">
              {dockerWebhookUrl}
            </div>
            <p className="text-[11px] text-slate-400 mt-1">
              Use when Celery worker runs in Docker Compose so requests route through internal DNS.
            </p>
          </div>
          <button
            onClick={handleCopyDocker}
            className="flex items-center justify-center gap-2 px-3 py-1.5 bg-indigo-600 hover:bg-indigo-500 text-white rounded-xl text-xs font-semibold shadow transition-all self-start"
          >
            {copiedDocker ? <Check className="w-3.5 h-3.5 text-emerald-300" /> : <Copy className="w-3.5 h-3.5" />}
            <span>{copiedDocker ? 'Copied Docker URL!' : 'Copy Docker URL'}</span>
          </button>
        </div>

        {/* Localhost / Bare-Metal Target */}
        <div className="p-4 rounded-2xl bg-slate-900 border border-slate-800 shadow-md flex flex-col justify-between gap-3">
          <div>
            <div className="flex items-center justify-between mb-1">
              <span className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">
                Localhost / Bare Metal
              </span>
              <span className="text-[10px] px-2 py-0.5 rounded-full bg-slate-800 text-slate-400 border border-slate-700 font-mono">
                host machine
              </span>
            </div>
            <div className="font-mono text-xs text-white font-medium break-all select-all py-1">
              {localhostWebhookUrl}
            </div>
            <p className="text-[11px] text-slate-400 mt-1">
              Use when running backend and workers directly on your local host without container isolation.
            </p>
          </div>
          <button
            onClick={handleCopyLocal}
            className="flex items-center justify-center gap-2 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-white rounded-xl text-xs font-semibold shadow transition-all self-start"
          >
            {copiedLocal ? <Check className="w-3.5 h-3.5 text-emerald-300" /> : <Copy className="w-3.5 h-3.5" />}
            <span>{copiedLocal ? 'Copied Localhost URL!' : 'Copy Localhost URL'}</span>
          </button>
        </div>
      </div>

      {/* Configuration Box */}
      <div className="p-5 rounded-2xl bg-slate-900 border border-slate-800 shadow-sm space-y-4">
        <div className="flex items-center gap-2 text-white font-semibold text-sm">
          <Settings className="w-4 h-4 text-indigo-400" />
          <span>Simulated Response Behavior</span>
        </div>
        <form onSubmit={handleSaveConfig} className="grid grid-cols-1 sm:grid-cols-3 gap-4 text-xs">
          <div>
            <label className="text-slate-400 block mb-1 font-medium">Return Status Code</label>
            <select
              value={config.status_code}
              onChange={(e) => setConfig({ ...config, status_code: Number(e.target.value) })}
              className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-white font-mono focus:outline-none focus:border-indigo-500"
            >
              <option value={200}>200 OK (Successful delivery)</option>
              <option value={400}>400 Bad Request (Client error)</option>
              <option value={500}>500 Internal Error (Triggers retry)</option>
              <option value={503}>503 Service Unavailable (Triggers retry)</option>
            </select>
          </div>
          <div>
            <label className="text-slate-400 block mb-1 font-medium">Simulated Latency (Seconds)</label>
            <input
              type="number"
              step="0.5"
              min="0"
              max="15"
              value={config.delay_seconds}
              onChange={(e) => setConfig({ ...config, delay_seconds: Number(e.target.value) })}
              className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-white font-mono focus:outline-none focus:border-indigo-500"
            />
          </div>
          <div className="flex items-end">
            <button
              type="submit"
              disabled={savingConfig}
              className="w-full py-2 bg-slate-800 hover:bg-slate-700 text-white rounded-lg font-medium transition-colors border border-slate-700"
            >
              {savingConfig ? 'Saving...' : 'Apply Behavior'}
            </button>
          </div>
        </form>
      </div>

      {/* Received Webhook Stream */}
      <div className="p-6 rounded-2xl bg-slate-900 border border-slate-800 shadow-sm space-y-4">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-base font-semibold text-white">Received Webhook Stream</h2>
            <p className="text-xs text-slate-400">Incoming HTTP POST requests logged with cryptographic headers</p>
          </div>
          <span className="text-xs font-mono text-slate-500">{logs.length} logged</span>
        </div>

        {loading ? (
          <div className="py-8 text-center text-xs text-slate-500">Loading incoming stream...</div>
        ) : logs.length > 0 ? (
          <div className="space-y-3">
            {logs.map((log) => (
              <div
                key={log.id}
                className="p-4 rounded-xl bg-slate-950 border border-slate-800/80 space-y-3 text-xs"
              >
                {/* Meta row */}
                <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-850 pb-2">
                  <div className="flex items-center gap-2">
                    <span className="px-2 py-0.5 rounded bg-indigo-500/10 text-indigo-300 border border-indigo-500/20 font-semibold font-mono">
                      {log.event_type || 'Unknown Type'}
                    </span>
                    <span className="text-slate-400 font-mono text-[11px]">
                      Delivery ID: {log.delivery_id || '—'}
                    </span>
                  </div>
                  <div className="flex items-center gap-3">
                    {log.signature_valid ? (
                      <span className="inline-flex items-center gap-1 text-[11px] text-emerald-400 font-medium">
                        <CheckCircle2 className="w-3.5 h-3.5" />
                        Signature Valid (HMAC-SHA256)
                      </span>
                    ) : (
                      <span className="inline-flex items-center gap-1 text-[11px] text-rose-400 font-medium">
                        <AlertCircle className="w-3.5 h-3.5" />
                        Signature Invalid
                      </span>
                    )}
                    <span className="text-slate-500 text-[11px]">
                      {new Date(log.received_at).toLocaleTimeString()}
                    </span>
                  </div>
                </div>

                {/* Signature Header */}
                {log.signature_header && (
                  <div className="text-[11px] font-mono text-slate-400 truncate">
                    <span className="text-slate-500">Header X-EventFlow-Signature: </span>
                    <span className="text-emerald-400">{log.signature_header}</span>
                  </div>
                )}

                {/* Payload viewer */}
                <div>
                  <span className="text-[10px] uppercase font-semibold text-slate-500 block mb-1">
                    Delivered Payload
                  </span>
                  <pre className="p-3 rounded-lg bg-slate-900 border border-slate-800 font-mono text-[11px] text-emerald-400 overflow-x-auto max-h-40">
                    {JSON.stringify(log.payload, null, 2)}
                  </pre>
                </div>
              </div>
            ))}
          </div>
        ) : (
          <div className="py-12 text-center text-slate-500 text-xs">
            <ShieldCheck className="w-8 h-8 mx-auto mb-2 opacity-30" />
            No webhooks received yet. Publish an event subscribed to this endpoint!
          </div>
        )}
      </div>
    </div>
  );
};
