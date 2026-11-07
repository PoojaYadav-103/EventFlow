import React, { useEffect, useState } from 'react';
import { Send, Plus, Filter, ChevronDown, ChevronRight, Hash, Layers } from 'lucide-react';
import { api } from '../services/api';
import type { EventItem } from '../types';

interface EventsPageProps {
  onOpenSimulate: () => void;
  refreshTrigger?: number;
}

export const EventsPage: React.FC<EventsPageProps> = ({ onOpenSimulate, refreshTrigger }) => {
  const [events, setEvents] = useState<EventItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [filterType, setFilterType] = useState('');
  const [expandedEventId, setExpandedEventId] = useState<string | null>(null);

  const fetchEvents = async (type?: string) => {
    try {
      const data = await api.getEvents(type || undefined);
      setEvents(data);
    } catch (err) {
      console.error('Failed to load events', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchEvents(filterType);
    const interval = setInterval(() => fetchEvents(filterType), 5000);
    return () => clearInterval(interval);
  }, [filterType, refreshTrigger]);

  const toggleExpand = (id: string) => {
    setExpandedEventId(expandedEventId === id ? null : id);
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-white">Published Events</h1>
          <p className="text-sm text-slate-400">
            Immutable domain events recorded and routed to subscribed destinations
          </p>
        </div>
        <button
          onClick={onOpenSimulate}
          className="flex items-center gap-2 px-3.5 py-2 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-semibold shadow-md shadow-indigo-600/20 transition-all self-start sm:self-auto"
        >
          <Plus className="w-4 h-4" />
          <span>Publish New Event</span>
        </button>
      </div>

      {/* Filter Bar */}
      <div className="flex items-center gap-2 bg-slate-900 border border-slate-800 p-2 rounded-xl text-xs w-full sm:w-80">
        <Filter className="w-4 h-4 text-slate-500 ml-1 shrink-0" />
        <input
          type="text"
          placeholder="Filter by event type (e.g. order.placed)..."
          value={filterType}
          onChange={(e) => setFilterType(e.target.value)}
          className="bg-transparent border-none text-slate-200 placeholder-slate-500 focus:outline-none w-full"
        />
        {filterType && (
          <button onClick={() => setFilterType('')} className="text-slate-500 hover:text-white px-1">
            ✕
          </button>
        )}
      </div>

      {/* Events Table */}
      <div className="p-6 rounded-2xl bg-slate-900 border border-slate-800 shadow-sm overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="border-b border-slate-800 text-slate-400">
                <th className="pb-3 w-8"></th>
                <th className="pb-3 font-medium">Event ID</th>
                <th className="pb-3 font-medium">Event Classification</th>
                <th className="pb-3 font-medium">Idempotency Key</th>
                <th className="pb-3 font-medium">Deliveries Dispatched</th>
                <th className="pb-3 font-medium">Timestamp</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-mono">
              {loading ? (
                <tr>
                  <td colSpan={6} className="py-8 text-center text-slate-500 font-sans">
                    Loading published events...
                  </td>
                </tr>
              ) : events.length > 0 ? (
                events.map((ev) => {
                  const isExpanded = expandedEventId === ev.id;
                  return (
                    <React.Fragment key={ev.id}>
                      <tr
                        onClick={() => toggleExpand(ev.id)}
                        className="hover:bg-slate-800/40 transition-colors cursor-pointer"
                      >
                        <td className="py-4 text-slate-500">
                          {isExpanded ? (
                            <ChevronDown className="w-4 h-4 text-indigo-400" />
                          ) : (
                            <ChevronRight className="w-4 h-4" />
                          )}
                        </td>
                        <td className="py-4 text-slate-300 font-semibold truncate max-w-[150px]">
                          {ev.id}
                        </td>
                        <td className="py-4 font-sans">
                          <span className="px-2.5 py-1 rounded bg-indigo-500/10 text-indigo-300 border border-indigo-500/20 text-xs font-medium">
                            {ev.event_type}
                          </span>
                        </td>
                        <td className="py-4 text-slate-400 truncate max-w-[160px]">
                          {ev.idempotency_key ? (
                            <span className="flex items-center gap-1 text-[11px] text-slate-400">
                              <Hash className="w-3 h-3 text-slate-600" />
                              {ev.idempotency_key}
                            </span>
                          ) : (
                            <span className="text-slate-600">—</span>
                          )}
                        </td>
                        <td className="py-4 font-sans text-slate-300">
                          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-slate-800 text-xs font-medium">
                            <Layers className="w-3 h-3 text-indigo-400" />
                            {ev.successful_deliveries_count} / {ev.deliveries_count} delivered
                          </span>
                        </td>
                        <td className="py-4 font-sans text-slate-400 text-[11px]">
                          {new Date(ev.created_at).toLocaleString()}
                        </td>
                      </tr>

                      {/* Expanded Payload Viewer */}
                      {isExpanded && (
                        <tr>
                          <td colSpan={6} className="bg-slate-950 p-4 border-b border-slate-800">
                            <div className="space-y-2 font-sans">
                              <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
                                Event Payload (JSON)
                              </div>
                              <pre className="p-3 rounded-lg bg-slate-900 border border-slate-800 text-xs font-mono text-emerald-400 overflow-x-auto max-h-64">
                                {JSON.stringify(ev.payload, null, 2)}
                              </pre>
                            </div>
                          </td>
                        </tr>
                      )}
                    </React.Fragment>
                  );
                })
              ) : (
                <tr>
                  <td colSpan={6} className="py-12 text-center text-slate-500 font-sans">
                    <Send className="w-8 h-8 mx-auto mb-2 opacity-40" />
                    No events published yet. Click &quot;Publish New Event&quot; to test.
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
