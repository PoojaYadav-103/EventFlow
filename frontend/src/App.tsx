import React, { useState } from 'react';
import { Navbar } from './components/Navbar';
import { Overview } from './pages/Overview';
import { EndpointsPage } from './pages/EndpointsPage';
import { EventsPage } from './pages/EventsPage';
import { DeliveriesPage } from './pages/DeliveriesPage';
import { MockReceiverPage } from './pages/MockReceiverPage';
import { RegisterEndpointModal } from './components/RegisterEndpointModal';
import { SimulateEventModal } from './components/SimulateEventModal';

export const App: React.FC = () => {
  const [activeTab, setActiveTab] = useState<string>('overview');
  const [isSimulateOpen, setIsSimulateOpen] = useState(false);
  const [isRegisterOpen, setIsRegisterOpen] = useState(false);
  const [refreshTrigger, setRefreshTrigger] = useState<number>(0);

  const handleRefreshAll = () => {
    setRefreshTrigger((prev) => prev + 1);
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col">
      {/* Top Navigation */}
      <Navbar
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        onOpenSimulate={() => setIsSimulateOpen(true)}
      />

      {/* Main Content Area */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {activeTab === 'overview' && (
          <Overview
            onNavigate={setActiveTab}
            onOpenSimulate={() => setIsSimulateOpen(true)}
            onOpenRegister={() => setIsRegisterOpen(true)}
            refreshTrigger={refreshTrigger}
          />
        )}

        {activeTab === 'endpoints' && (
          <EndpointsPage
            onOpenRegister={() => setIsRegisterOpen(true)}
            refreshTrigger={refreshTrigger}
          />
        )}

        {activeTab === 'events' && (
          <EventsPage
            onOpenSimulate={() => setIsSimulateOpen(true)}
            refreshTrigger={refreshTrigger}
          />
        )}

        {activeTab === 'deliveries' && (
          <DeliveriesPage refreshTrigger={refreshTrigger} />
        )}

        {activeTab === 'mock' && <MockReceiverPage />}
      </main>

      {/* Modals */}
      <RegisterEndpointModal
        isOpen={isRegisterOpen}
        onClose={() => setIsRegisterOpen(false)}
        onCreated={() => {
          handleRefreshAll();
        }}
      />

      <SimulateEventModal
        isOpen={isSimulateOpen}
        onClose={() => setIsSimulateOpen(false)}
        onPublished={() => {
          handleRefreshAll();
        }}
      />

      {/* Footer */}
      <footer className="border-t border-slate-900 bg-slate-950/60 py-6 text-center text-xs text-slate-500">
        <div className="max-w-7xl mx-auto px-4 flex flex-col sm:flex-row items-center justify-between gap-2">
          <span>EventFlow — Reliable Webhook Delivery Platform</span>
          <span className="font-mono text-[11px] text-slate-600">
            PostgreSQL · Transactional Outbox · Redis · Celery · React 19 · Vite
          </span>
        </div>
      </footer>
    </div>
  );
};

export default App;
