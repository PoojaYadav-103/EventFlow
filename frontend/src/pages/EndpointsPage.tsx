import React, { useEffect, useState } from 'react';
import { Webhook, Plus, RotateCw, Trash2, Power, Check, Copy, KeyRound, ShieldAlert } from 'lucide-react';
import { api } from '../services/api';
import type { Endpoint } from '../types';

interface EndpointsPageProps {
  onOpenRegister: () => void;
  refreshTrigger?: number;
}

export const EndpointsPage: React.FC<EndpointsPageProps> = ({ onOpenRegister, refreshTrigger }) => {
  const [endpoints, setEndpoints] = useState<Endpoint[]>([]);
  const [loading, setLoading] = useState(true);
  const [rollingId, setRollingId] = useState<string | null>(null);
  const [rolledSecret, setRolledSecret] = useState<{ id: string; secret: string } | null>(null);
  const [copied, setCopied] = useState(false);

  const fetchEndpoints = async () => {
    try {
      const data = await api.getEndpoints();
      setEndpoints(data);
    } catch (err) {
      console.error('Failed to fetch endpoints', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchEndpoints();
    const interval = setInterval(fetchEndpoints, 5000);
    return () => clearInterval(interval);
  }, [refreshTrigger]);

  const handleToggleActive = async (ep: Endpoint) => {
    try {
      const updated = await api.updateEndpoint(ep.id, { is_active: !ep.is_active });
      setEndpoints(endpoints.map((item) => (item.id === ep.id ? { ...item, is_active: updated.is_active } : item)));
    } catch (err: any) {
      alert(`Failed to update status: ${err.message}`);
    }
  };

  const handleRollSecret = async (epId: string) => {
    if (!confirm('Are you sure you want to rotate this signing secret? Downstream verification keys must be updated.')) {
      return;
    }
    setRollingId(epId);
    try {
      const res = await api.rollSecret(epId);
      setRolledSecret({ id: epId, secret: res.signing_secret });
      fetchEndpoints();
    } catch (err: any) {
      alert(`Failed to rotate secret: ${err.message}`);
    } finally {
      setRollingId(null);
    }
  };

  const handleDelete = async (epId: string) => {
    if (!confirm('Are you sure you want to delete this endpoint? (Historical delivery logs will be preserved).')) {
      return;
    }
    try {
      await api.deleteEndpoint(epId);
      setEndpoints(endpoints.filter((item) => item.id !== epId));
    } catch (err: any) {
      alert(`Failed to delete endpoint: ${err.message}`);
    }
  };

  const handleCopy = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-white">Registered Endpoints</h1>
          <p className="text-sm text-slate-400">
            Destination HTTP/HTTPS targets and their topic subscription routing rules
          </p>
        </div>
        <button
          onClick={onOpenRegister}
          className="flex items-center gap-2 px-3.5 py-2 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-semibold shadow-md shadow-indigo-600/20 transition-all self-start sm:self-auto"
        >
          <Plus className="w-4 h-4" />
          <span>Register New Endpoint</span>
        </button>
      </div>

      {/* Rolled Secret Banner if active */}
      {rolledSecret && (
        <div className="p-4 rounded-xl bg-slate-900 border border-indigo-500/30 shadow-lg space-y-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2 text-indigo-400 text-xs font-semibold">
              <KeyRound className="w-4 h-4" />
              <span>New Signing Secret Rotated for Endpoint {rolledSecret.id.substring(0, 8)}...</span>
            </div>
            <button
              onClick={() => setRolledSecret(null)}
              className="text-xs text-slate-400 hover:text-white"
            >
              Dismiss
            </button>
          </div>
          <div className="flex items-center gap-2">
            <input
              type="text"
              readOnly
              value={rolledSecret.secret}
              className="flex-1 px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-xs font-mono text-emerald-400 select-all focus:outline-none"
            />
            <button
              onClick={() => handleCopy(rolledSecret.secret)}
              className="flex items-center gap-1.5 px-3 py-2 bg-slate-800 hover:bg-slate-700 text-white rounded-lg text-xs font-medium"
            >
              {copied ? <Check className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
              <span>{copied ? 'Copied' : 'Copy'}</span>
            </button>
          </div>
          <div className="flex items-center gap-1.5 text-[11px] text-amber-300">
            <ShieldAlert className="w-3.5 h-3.5 shrink-0" />
            <span>Store this secret immediately. It will not be shown in plaintext again.</span>
          </div>
        </div>
      )}

      {/* Endpoints Table */}
      <div className="p-6 rounded-2xl bg-slate-900 border border-slate-800 shadow-sm overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="border-b border-slate-800 text-slate-400">
                <th className="pb-3 font-medium">Status</th>
                <th className="pb-3 font-medium">Destination URL & Description</th>
                <th className="pb-3 font-medium">Subscribed Topics</th>
                <th className="pb-3 font-medium">Signing Secret</th>
                <th className="pb-3 font-medium">Deliveries</th>
                <th className="pb-3 font-medium text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {loading ? (
                <tr>
                  <td colSpan={6} className="py-8 text-center text-slate-500">
                    Loading registered endpoints...
                  </td>
                </tr>
              ) : endpoints.length > 0 ? (
                endpoints.map((ep) => (
                  <tr key={ep.id} className="hover:bg-slate-800/40 transition-colors">
                    {/* Active Toggle */}
                    <td className="py-4">
                      <button
                        onClick={() => handleToggleActive(ep)}
                        title={ep.is_active ? 'Disable Endpoint' : 'Enable Endpoint'}
                        className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[11px] font-medium border transition-colors ${
                          ep.is_active
                            ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20 hover:bg-emerald-500/20'
                            : 'bg-slate-800 text-slate-400 border-slate-700 hover:bg-slate-700'
                        }`}
                      >
                        <Power className="w-3 h-3" />
                        <span>{ep.is_active ? 'Active' : 'Disabled'}</span>
                      </button>
                    </td>

                    {/* URL and Description */}
                    <td className="py-4 max-w-[320px]">
                      <div className="font-mono text-white font-medium truncate" title={ep.url}>
                        {ep.url}
                      </div>
                      {ep.description && (
                        <div className="text-[11px] text-slate-400 truncate mt-0.5">
                          {ep.description}
                        </div>
                      )}
                    </td>

                    {/* Subscribed Topics */}
                    <td className="py-4">
                      <div className="flex flex-wrap gap-1 max-w-[240px]">
                        {ep.event_types.map((type) => (
                          <span
                            key={type}
                            className={`px-2 py-0.5 rounded text-[10px] font-mono font-medium ${
                              type === '*'
                                ? 'bg-indigo-500/10 text-indigo-300 border border-indigo-500/20'
                                : 'bg-slate-800 text-slate-300 border border-slate-700'
                            }`}
                          >
                            {type}
                          </span>
                        ))}
                      </div>
                    </td>

                    {/* Masked Secret */}
                    <td className="py-4">
                      <span className="font-mono text-[11px] text-slate-400 px-2 py-1 bg-slate-950 rounded border border-slate-800">
                        {ep.signing_secret_masked}
                      </span>
                    </td>

                    {/* Deliveries Count */}
                    <td className="py-4 text-slate-300 font-medium font-mono">
                      {ep.deliveries_count}
                    </td>

                    {/* Actions */}
                    <td className="py-4 text-right">
                      <div className="flex items-center justify-end gap-1.5">
                        <button
                          onClick={() => handleRollSecret(ep.id)}
                          disabled={rollingId === ep.id}
                          title="Rotate Signing Secret"
                          className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white transition-colors disabled:opacity-50"
                        >
                          <RotateCw className={`w-3.5 h-3.5 ${rollingId === ep.id ? 'animate-spin' : ''}`} />
                        </button>
                        <button
                          onClick={() => handleDelete(ep.id)}
                          title="Delete Endpoint (Soft delete)"
                          className="p-1.5 rounded-lg bg-slate-800 hover:bg-rose-900/40 text-slate-400 hover:text-rose-300 transition-colors"
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={6} className="py-12 text-center text-slate-500">
                    <Webhook className="w-8 h-8 mx-auto mb-2 opacity-40" />
                    No webhook endpoints registered yet. Click &quot;Register New Endpoint&quot; to begin.
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
