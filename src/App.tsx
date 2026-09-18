import React, { useState, useEffect } from 'react';
import { Navbar } from './components/Navbar';
import { ScannerView } from './components/ScannerView';
import { FeedsView } from './components/FeedsView';
import { TriageMatrixView } from './components/TriageMatrixView';
import { PythonGuideView } from './components/PythonGuideView';
import { TriageModal } from './components/TriageModal';
import { DEFAULT_FEEDS, INITIAL_IOC_DATABASE } from './data/defaultFeeds';
import { SAMPLE_LOGS } from './data/sampleLogs';
import { FeedInfo, IOCRecord, MatchResult, ScanMetrics } from './types';
import { scanLogsAgainstFeeds } from './utils/iocExtractor';
import { ShieldCheck, Crosshair, Terminal, Sparkles, AlertCircle } from 'lucide-react';

export default function App() {
  const [activeTab, setActiveTab] = useState<'scanner' | 'feeds' | 'triage' | 'python_guide'>('scanner');
  const [feeds, setFeeds] = useState<FeedInfo[]>(DEFAULT_FEEDS);
  const [iocDatabase, setIocDatabase] = useState<IOCRecord[]>(INITIAL_IOC_DATABASE);
  const [results, setResults] = useState<MatchResult[]>([]);
  const [metrics, setMetrics] = useState<ScanMetrics | null>(null);
  const [isScanning, setIsScanning] = useState<boolean>(false);
  const [isRefreshing, setIsRefreshing] = useState<boolean>(false);
  const [currentLogName, setCurrentLogName] = useState<string>(SAMPLE_LOGS[0].name);
  const [selectedTriageMatch, setSelectedTriageMatch] = useState<MatchResult | null>(null);
  const [notification, setNotification] = useState<string | null>(null);

  const showNotification = (msg: string) => {
    setNotification(msg);
    setTimeout(() => setNotification(null), 3000);
  };

  // Run initial scan on load so the interface is immediately populated with realistic threat telemetry
  useEffect(() => {
    const initial = scanLogsAgainstFeeds(SAMPLE_LOGS[0].content, INITIAL_IOC_DATABASE, {
      excludePrivateIps: true,
    });
    setResults(initial.results);
    setMetrics(initial.metrics);
  }, []);

  const handleScan = (logContent: string, logName: string, excludePrivate: boolean) => {
    setIsScanning(true);
    setCurrentLogName(logName);

    // Filter database to only enabled feeds
    const enabledFeedNames = new Set(feeds.filter(f => f.enabled).map(f => f.name));
    const activeIocs = iocDatabase.filter(ioc => enabledFeedNames.has(ioc.feed));

    setTimeout(() => {
      const scanOutput = scanLogsAgainstFeeds(logContent, activeIocs, {
        excludePrivateIps: excludePrivate,
      });

      setResults(scanOutput.results);
      setMetrics(scanOutput.metrics);
      setIsScanning(false);
      showNotification(`Escaneo completado: ${scanOutput.results.length} coincidencias en ${scanOutput.metrics.scanDurationMs}ms`);
    }, 450);
  };

  const handleToggleFeed = (id: string) => {
    setFeeds(prev =>
      prev.map(f => (f.id === id ? { ...f, enabled: !f.enabled } : f))
    );
    showNotification('Configuración de feeds actualizada');
  };

  const handleRefreshAllFeeds = () => {
    setIsRefreshing(true);
    setTimeout(() => {
      setFeeds(prev =>
        prev.map(f => ({
          ...f,
          lastUpdated: 'Recién actualizado (Ahora mismo)',
          status: 'active',
        }))
      );
      setIsRefreshing(false);
      showNotification('Todos los feeds sincronizados con éxito');
    }, 1000);
  };

  const handleAddCustomIOC = (customIOC: Partial<IOCRecord>) => {
    const newRecord: IOCRecord = {
      id: `custom-${Date.now()}`,
      value: customIOC.value || '',
      type: customIOC.type || 'ip',
      severity: customIOC.severity || 'HIGH',
      feed: 'Custom Feed',
      malwareFamily: customIOC.malwareFamily || 'Indicador Local',
      confidence: 100,
      firstSeen: new Date().toISOString().slice(0, 10),
      description: customIOC.description || 'Agregado manualmente por el analista SOC.',
    };

    setIocDatabase(prev => [newRecord, ...prev]);
    showNotification(`IOC añadido: ${newRecord.value}`);
  };

  const handleTriageStatusChange = (id: string, status: 'unreviewed' | 'confirmed' | 'false_positive') => {
    setResults(prev =>
      prev.map(r => (r.id === id ? { ...r, triageStatus: status } : r))
    );
    if (selectedTriageMatch && selectedTriageMatch.id === id) {
      setSelectedTriageMatch(prev => prev ? { ...prev, triageStatus: status } : null);
    }
    showNotification(`Estado de triaje actualizado a: ${status}`);
  };

  const activeFeedsCount = feeds.filter(f => f.enabled).length;

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans selection:bg-emerald-500/30 selection:text-emerald-200">
      {/* Toast Notification */}
      {notification && (
        <div className="fixed bottom-5 right-5 z-50 bg-slate-900 border border-emerald-500/40 text-emerald-300 text-xs px-4 py-2.5 rounded-lg shadow-xl flex items-center space-x-2 animate-in fade-in slide-in-from-bottom-3 duration-200">
          <ShieldCheck className="h-4 w-4 text-emerald-400" />
          <span>{notification}</span>
        </div>
      )}

      {/* Navigation Header */}
      <Navbar
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        activeFeedsCount={activeFeedsCount}
        totalIOCsCount={iocDatabase.length}
      />

      {/* Main View Body */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-6 sm:py-8">
        {activeTab === 'scanner' && (
          <ScannerView
            iocDatabase={iocDatabase}
            onScan={handleScan}
            results={results}
            metrics={metrics}
            isScanning={isScanning}
            onOpenTriage={(match) => setSelectedTriageMatch(match)}
            currentLogName={currentLogName}
          />
        )}

        {activeTab === 'feeds' && (
          <FeedsView
            feeds={feeds}
            iocDatabase={iocDatabase}
            onToggleFeed={handleToggleFeed}
            onRefreshAllFeeds={handleRefreshAllFeeds}
            onAddCustomIOC={handleAddCustomIOC}
            isRefreshing={isRefreshing}
          />
        )}

        {activeTab === 'triage' && (
          <TriageMatrixView
            results={results}
            onOpenTriage={(match) => setSelectedTriageMatch(match)}
          />
        )}

        {activeTab === 'python_guide' && (
          <PythonGuideView />
        )}
      </main>

      {/* Detailed Investigation Triage Modal */}
      <TriageModal
        match={selectedTriageMatch}
        onClose={() => setSelectedTriageMatch(null)}
        onStatusChange={handleTriageStatusChange}
      />

      {/* SOC Footer */}
      <footer className="border-t border-slate-900 bg-slate-950 py-6 text-xs text-slate-500">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex flex-col sm:flex-row items-center justify-between gap-3">
          <div className="flex items-center space-x-2">
            <Crosshair className="h-4 w-4 text-emerald-500" />
            <span className="font-mono text-slate-400">
              IOC Hunter Threat Intelligence Platform
            </span>
            <span>• Feeds: URLhaus | AbuseIPDB | AlienVault OTX | Feodo Tracker</span>
          </div>

          <div className="flex items-center space-x-4 text-slate-400">
            <span>Formato seguro: RFC 1918 Excluido</span>
            <span>•</span>
            <button
              onClick={() => setActiveTab('python_guide')}
              className="text-cyan-400 hover:text-cyan-300 font-medium transition-colors"
            >
              Ver Código Python & Despliegue Gratis
            </button>
          </div>
        </div>
      </footer>
    </div>
  );
}
