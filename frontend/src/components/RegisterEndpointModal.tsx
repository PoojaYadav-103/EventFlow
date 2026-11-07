import React, { useState } from 'react';
import { X, Copy, Check, ShieldAlert, KeyRound } from 'lucide-react';
import { api } from '../services/api';
import type { Endpoint } from '../types';

interface RegisterEndpointModalProps {
  isOpen: boolean;
  onClose: () => void;
  onCreated: (endpoint: Endpoint) => void;
}

const AVAILABLE_TOPICS = [
  'order.placed',
  'order.confirmed',
  'order.shipped',
  'order.delivered',
  'order.cancelled',
];

export const RegisterEndpointModal: React.FC<RegisterEndpointModalProps> = ({
  isOpen,
  onClose,
  onCreated,
}) => {
  const [url, setUrl] = useState('');
  const [description, setDescription] = useState('');
  const [subscribeAll, setSubscribeAll] = useState(true);
  const [selectedTopics, setSelectedTopics] = useState<string[]>([]);
  const [rateLimit, setRateLimit] = useState<number | ''>('');
  
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  
  // State for revealed secret after creation
  const [revealedSecret, setRevealedSecret] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  if (!isOpen) return null;

  const handleToggleTopic = (topic: string) => {
    if (selectedTopics.includes(topic)) {
      setSelectedTopics(selectedTopics.filter((t) => t !== topic));
    } else {
      setSelectedTopics([...selectedTopics, topic]);
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!url.trim()) {
      setError('Destination URL is required.');
      return;
    }

    const event_types = subscribeAll ? ['*'] : selectedTopics.length > 0 ? selectedTopics : ['*'];

    setIsSubmitting(true);
    setError(null);

    try {
      const created = await api.createEndpoint({
        url: url.trim(),
        description: description.trim() || undefined,
        event_types,
        rate_limit_per_minute: rateLimit ? Number(rateLimit) : undefined,
      });

      if (created.signing_secret) {
        setRevealedSecret(created.signing_secret);
      }
      onCreated(created);
    } catch (err: any) {
      setError(err.message || 'Failed to register endpoint.');
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleCopySecret = () => {
    if (revealedSecret) {
      navigator.clipboard.writeText(revealedSecret);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  const handleFinish = () => {
    setRevealedSecret(null);
    setUrl('');
    setDescription('');
    setSelectedTopics([]);
    setSubscribeAll(true);
    setRateLimit('');
    setError(null);
    onClose();
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm">
      <div className="relative w-full max-w-lg bg-slate-900 border border-slate-800 rounded-2xl shadow-2xl p-6 overflow-hidden">
        {/* Header */}
        <div className="flex items-center justify-between pb-4 border-b border-slate-800">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-lg bg-indigo-500/10 text-indigo-400 flex items-center justify-center border border-indigo-500/20">
              <KeyRound className="w-4 h-4" />
            </div>
            <div>
              <h3 className="text-base font-semibold text-white">Register Webhook Endpoint</h3>
              <p className="text-xs text-slate-400">Configure target HTTP destination and subscribed topics</p>
            </div>
          </div>
          <button
            onClick={revealedSecret ? handleFinish : onClose}
            className="p-1 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Revealed Secret View */}
        {revealedSecret ? (
          <div className="py-6 space-y-4">
            <div className="p-4 rounded-xl bg-emerald-500/10 border border-emerald-500/20 text-emerald-300 text-sm">
              <span className="font-semibold">Endpoint registered successfully!</span> Below is the generated HMAC-SHA256 signing secret.
            </div>

            <div className="space-y-1.5">
              <label className="text-xs font-medium text-slate-400">Signing Secret (Store securely)</label>
              <div className="flex items-center gap-2">
                <input
                  type="text"
                  readOnly
                  value={revealedSecret}
                  className="flex-1 px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-xs font-mono text-emerald-400 select-all focus:outline-none"
                />
                <button
                  onClick={handleCopySecret}
                  className="flex items-center gap-1.5 px-3 py-2 bg-slate-800 hover:bg-slate-700 text-white rounded-lg text-xs font-medium transition-colors"
                >
                  {copied ? <Check className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
                  <span>{copied ? 'Copied' : 'Copy'}</span>
                </button>
              </div>
            </div>

            <div className="p-3 rounded-lg bg-amber-500/10 border border-amber-500/20 flex items-start gap-2.5 text-xs text-amber-300">
              <ShieldAlert className="w-4 h-4 mt-0.5 shrink-0" />
              <span>
                This is the only time this signing secret will be revealed in plaintext. Store it securely in your consumer service to verify incoming webhook signatures.
              </span>
            </div>

            <div className="pt-2 flex justify-end">
              <button
                onClick={handleFinish}
                className="px-4 py-2 bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-semibold rounded-lg shadow transition-colors"
              >
                Done & Close
              </button>
            </div>
          </div>
        ) : (
          /* Form View */
          <form onSubmit={handleSubmit} className="py-4 space-y-4">
            {error && (
              <div className="p-3 rounded-lg bg-rose-500/10 border border-rose-500/20 text-xs text-rose-400">
                {error}
              </div>
            )}

            {/* URL */}
            <div className="space-y-1.5">
              <label className="text-xs font-medium text-slate-300">
                Destination URL <span className="text-rose-400">*</span>
              </label>
              <input
                type="url"
                required
                placeholder="https://api.yourdomain.com/webhooks or http://backend:8000/api/v1/mock-receiver/webhook"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-sm text-white placeholder-slate-500 focus:outline-none focus:border-indigo-500 transition-colors"
              />
              <div className="flex flex-wrap items-center gap-2 pt-1 text-[11px]">
                <span className="text-slate-500">Quick presets:</span>
                <button
                  type="button"
                  onClick={() => setUrl('http://backend:8000/api/v1/mock-receiver/webhook')}
                  className="text-indigo-400 hover:text-indigo-300 hover:underline font-mono"
                >
                  Docker (backend:8000)
                </button>
                <span className="text-slate-700">·</span>
                <button
                  type="button"
                  onClick={() => setUrl('http://localhost:8000/api/v1/mock-receiver/webhook')}
                  className="text-slate-400 hover:text-slate-200 hover:underline font-mono"
                >
                  Localhost (localhost:8000)
                </button>
              </div>
            </div>

            {/* Description */}
            <div className="space-y-1.5">
              <label className="text-xs font-medium text-slate-300">Description / Service Name</label>
              <input
                type="text"
                placeholder="e.g. Inventory Service, Notification Consumer"
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-sm text-white placeholder-slate-500 focus:outline-none focus:border-indigo-500 transition-colors"
              />
            </div>

            {/* Event Subscriptions */}
            <div className="space-y-2">
              <label className="text-xs font-medium text-slate-300">Event Subscriptions</label>
              
              <div className="flex items-center gap-2 mb-2">
                <input
                  type="checkbox"
                  id="sub-all"
                  checked={subscribeAll}
                  onChange={(e) => setSubscribeAll(e.target.checked)}
                  className="rounded border-slate-700 bg-slate-950 text-indigo-600 focus:ring-0"
                />
                <label htmlFor="sub-all" className="text-xs text-slate-200 font-medium">
                  Subscribe to all events (<code className="text-indigo-400">*</code>)
                </label>
              </div>

              {!subscribeAll && (
                <div className="grid grid-cols-2 gap-2 pt-1">
                  {AVAILABLE_TOPICS.map((topic) => (
                    <label
                      key={topic}
                      className="flex items-center gap-2 p-2 rounded-lg bg-slate-950 border border-slate-800 text-xs text-slate-300 cursor-pointer hover:border-slate-700"
                    >
                      <input
                        type="checkbox"
                        checked={selectedTopics.includes(topic)}
                        onChange={() => handleToggleTopic(topic)}
                        className="rounded border-slate-700 bg-slate-900 text-indigo-600 focus:ring-0"
                      />
                      <span>{topic}</span>
                    </label>
                  ))}
                </div>
              )}
            </div>

            {/* Rate limit (optional) */}
            <div className="space-y-1.5">
              <label className="text-xs font-medium text-slate-300">Rate Limit (Per Minute, Optional)</label>
              <input
                type="number"
                min="1"
                placeholder="e.g. 60"
                value={rateLimit}
                onChange={(e) => setRateLimit(e.target.value ? Number(e.target.value) : '')}
                className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-sm text-white placeholder-slate-500 focus:outline-none focus:border-indigo-500 transition-colors"
              />
            </div>

            {/* Footer Buttons */}
            <div className="pt-3 flex items-center justify-end gap-3 border-t border-slate-800">
              <button
                type="button"
                onClick={onClose}
                className="px-3.5 py-2 text-xs font-medium text-slate-400 hover:text-white rounded-lg transition-colors"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={isSubmitting}
                className="px-4 py-2 bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-white text-xs font-semibold rounded-lg shadow-md shadow-indigo-600/20 transition-all"
              >
                {isSubmitting ? 'Registering...' : 'Register Webhook'}
              </button>
            </div>
          </form>
        )}
      </div>
    </div>
  );
};
