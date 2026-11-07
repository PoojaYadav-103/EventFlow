import React, { useState } from 'react';
import { X, Send, Sparkles, RefreshCw, CheckCircle2 } from 'lucide-react';
import { api } from '../services/api';
import type { EventItem } from '../types';

interface SimulateEventModalProps {
  isOpen: boolean;
  onClose: () => void;
  onPublished: (event: EventItem) => void;
}

const TEMPLATES: Record<string, { event_type: string; payload: Record<string, any> }> = {
  'order.placed': {
    event_type: 'order.placed',
    payload: {
      order_id: 'ord_' + Math.floor(100000 + Math.random() * 900000),
      customer: {
        id: 'cust_8821',
        name: 'Alex Johnson',
        email: 'alex.j@example.com',
      },
      items: [
        { sku: 'TECH-MBP-16', name: 'MacBook Pro 16"', qty: 1, price: 2499.0 },
        { sku: 'ACC-USB-HUB', name: 'Thunderbolt 4 Dock', qty: 1, price: 199.0 },
      ],
      total: 2698.0,
      currency: 'USD',
      shipping_address: {
        street: '742 Evergreen Terrace',
        city: 'Springfield',
        state: 'OR',
        postal_code: '97477',
      },
    },
  },
  'order.confirmed': {
    event_type: 'order.confirmed',
    payload: {
      order_id: 'ord_918231',
      confirmation_code: 'CNF-2026-X89',
      payment_status: 'AUTHORIZED',
      gateway: 'Stripe',
      amount_charged: 2698.0,
    },
  },
  'order.shipped': {
    event_type: 'order.shipped',
    payload: {
      order_id: 'ord_918231',
      carrier: 'FedEx Express',
      tracking_number: '7829-1029-4820',
      estimated_delivery: '2026-11-10T18:00:00Z',
      package_count: 1,
    },
  },
  'order.delivered': {
    event_type: 'order.delivered',
    payload: {
      order_id: 'ord_918231',
      delivered_at: new Date().toISOString(),
      signed_by: 'Alex Johnson',
      delivery_location: 'Front Porch',
    },
  },
  'order.cancelled': {
    event_type: 'order.cancelled',
    payload: {
      order_id: 'ord_918231',
      reason: 'Customer requested cancellation prior to fulfillment',
      refund_amount: 2698.0,
      refund_id: 'ref_982138',
    },
  },
};

export const SimulateEventModal: React.FC<SimulateEventModalProps> = ({
  isOpen,
  onClose,
  onPublished,
}) => {
  const [selectedTemplate, setSelectedTemplate] = useState('order.placed');
  const [eventType, setEventType] = useState(TEMPLATES['order.placed'].event_type);
  const [payloadText, setPayloadText] = useState(
    JSON.stringify(TEMPLATES['order.placed'].payload, null, 2)
  );
  const [idempotencyKey, setIdempotencyKey] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [successInfo, setSuccessInfo] = useState<string | null>(null);

  if (!isOpen) return null;

  const handleTemplateChange = (templateKey: string) => {
    setSelectedTemplate(templateKey);
    const tmpl = TEMPLATES[templateKey];
    if (tmpl) {
      setEventType(tmpl.event_type);
      setPayloadText(JSON.stringify(tmpl.payload, null, 2));
    }
  };

  const handleGenerateIdempotencyKey = () => {
    setIdempotencyKey('idemp_' + Math.random().toString(36).substring(2, 12));
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setSuccessInfo(null);

    let parsedPayload: Record<string, any>;
    try {
      parsedPayload = JSON.parse(payloadText);
    } catch {
      setError('Payload must be valid JSON.');
      return;
    }

    setIsSubmitting(true);
    try {
      const res = await api.publishEvent({
        event_type: eventType.trim(),
        payload: parsedPayload,
        idempotency_key: idempotencyKey.trim() || undefined,
      });

      setSuccessInfo(
        `Event published to Transactional Outbox! Created ${res.deliveries_count} delivery record(s).`
      );
      onPublished(res);
      setTimeout(() => {
        onClose();
        setSuccessInfo(null);
      }, 1400);
    } catch (err: any) {
      setError(err.message || 'Failed to publish event.');
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm">
      <div className="relative w-full max-w-xl bg-slate-900 border border-slate-800 rounded-2xl shadow-2xl p-6 overflow-hidden max-h-[90vh] flex flex-col">
        {/* Header */}
        <div className="flex items-center justify-between pb-4 border-b border-slate-800">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-lg bg-indigo-500/10 text-indigo-400 flex items-center justify-center border border-indigo-500/20">
              <Sparkles className="w-4 h-4" />
            </div>
            <div>
              <h3 className="text-base font-semibold text-white">Publish Domain Event</h3>
              <p className="text-xs text-slate-400">Simulate real-world e-commerce lifecycle events</p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Content */}
        <form onSubmit={handleSubmit} className="py-4 space-y-4 overflow-y-auto flex-1">
          {error && (
            <div className="p-3 rounded-lg bg-rose-500/10 border border-rose-500/20 text-xs text-rose-400">
              {error}
            </div>
          )}
          {successInfo && (
            <div className="p-3 rounded-lg bg-emerald-500/10 border border-emerald-500/20 text-xs text-emerald-400 flex items-center gap-2">
              <CheckCircle2 className="w-4 h-4 shrink-0" />
              <span>{successInfo}</span>
            </div>
          )}

          {/* Quick Templates Selection */}
          <div className="space-y-1.5">
            <label className="text-xs font-medium text-slate-300">Quick E-Commerce Scenario</label>
            <div className="grid grid-cols-2 sm:grid-cols-3 gap-2">
              {Object.keys(TEMPLATES).map((key) => (
                <button
                  type="button"
                  key={key}
                  onClick={() => handleTemplateChange(key)}
                  className={`px-2.5 py-1.5 rounded-lg text-xs font-medium transition-all text-left border ${
                    selectedTemplate === key
                      ? 'bg-indigo-600/20 border-indigo-500 text-indigo-300'
                      : 'bg-slate-950 border-slate-800 text-slate-400 hover:border-slate-700'
                  }`}
                >
                  {key}
                </button>
              ))}
            </div>
          </div>

          {/* Event Type */}
          <div className="space-y-1.5">
            <label className="text-xs font-medium text-slate-300">
              Event Classification <span className="text-rose-400">*</span>
            </label>
            <input
              type="text"
              required
              value={eventType}
              onChange={(e) => setEventType(e.target.value)}
              className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-sm text-white placeholder-slate-500 focus:outline-none focus:border-indigo-500 font-mono transition-colors"
            />
          </div>

          {/* Idempotency Key */}
          <div className="space-y-1.5">
            <div className="flex items-center justify-between">
              <label className="text-xs font-medium text-slate-300">
                Idempotency Key <span className="text-slate-500">(Optional)</span>
              </label>
              <button
                type="button"
                onClick={handleGenerateIdempotencyKey}
                className="text-[11px] text-indigo-400 hover:underline flex items-center gap-1"
              >
                <RefreshCw className="w-3 h-3" />
                Generate UUID
              </button>
            </div>
            <input
              type="text"
              placeholder="e.g. idemp_checkout_91283"
              value={idempotencyKey}
              onChange={(e) => setIdempotencyKey(e.target.value)}
              className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-xs font-mono text-white placeholder-slate-600 focus:outline-none focus:border-indigo-500 transition-colors"
            />
          </div>

          {/* JSON Payload */}
          <div className="space-y-1.5">
            <label className="text-xs font-medium text-slate-300">JSON Payload</label>
            <textarea
              rows={8}
              value={payloadText}
              onChange={(e) => setPayloadText(e.target.value)}
              className="w-full p-3 bg-slate-950 border border-slate-800 rounded-lg text-xs font-mono text-slate-200 placeholder-slate-600 focus:outline-none focus:border-indigo-500 transition-colors resize-none"
            />
          </div>

          {/* Footer */}
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
              className="flex items-center gap-2 px-4 py-2 bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-white text-xs font-semibold rounded-lg shadow-md shadow-indigo-600/20 transition-all"
            >
              <Send className="w-3.5 h-3.5" />
              <span>{isSubmitting ? 'Publishing...' : 'Publish & Dispatch'}</span>
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};
