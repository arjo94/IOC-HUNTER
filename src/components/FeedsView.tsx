import React, { useState } from 'react';
import { 
  Globe, 
  RefreshCw, 
  Plus, 
  ExternalLink, 
  ShieldCheck, 
  AlertTriangle, 
  Key, 
  Database,
  Search,
  Filter,
  CheckCircle2,
  Trash2,
  Info
} from 'lucide-react';
import { FeedInfo, IOCRecord, IOCType, Severity } from '../types';
import { defang } from '../utils/iocExtractor';

interface FeedsViewProps {
  feeds: FeedInfo[];
  iocDatabase: IOCRecord[];
  onToggleFeed: (id: string) => void;
  onRefreshAllFeeds: () => void;
  onAddCustomIOC: (ioc: Partial<IOCRecord>) => void;
  isRefreshing: boolean;
}

export const FeedsView: React.FC<FeedsViewProps> = ({
  feeds,
  iocDatabase,
  onToggleFeed,
  onRefreshAllFeeds,
  onAddCustomIOC,
  isRefreshing,
}) => {
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedType, setSelectedType] = useState<string>('all');
  const [selectedFeed, setSelectedFeed] = useState<string>('all');

  // Custom IOC form state
  const [showAddModal, setShowAddModal] = useState(false);
  const [newVal, setNewVal] = useState('');
  const [newType, setNewType] = useState<IOCType>('ip');
  const [newSeverity, setNewSeverity] = useState<Severity>('HIGH');
  const [newMalware, setNewMalware] = useState('');
  const [newDesc, setNewDesc] = useState('');

  const handleAddSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!newVal.trim()) return;

    onAddCustomIOC({
      value: newVal.trim(),
      type: newType,
      severity: newSeverity,
      feed: 'Custom Feed',
      malwareFamily: newMalware.trim() || 'Indicador Personalizado',
      description: newDesc.trim() || 'Añadido manualmente por el analista.',
      confidence: 100,
      firstSeen: new Date().toISOString().slice(0, 10),
    });

    setNewVal('');
    setNewMalware('');
    setNewDesc('');
    setShowAddModal(false);
  };

  // Filter IOC Database
  const filteredIOCs = iocDatabase.filter(item => {
    const matchesSearch = 
      item.value.toLowerCase().includes(searchQuery.toLowerCase()) ||
      (item.malwareFamily && item.malwareFamily.toLowerCase().includes(searchQuery.toLowerCase())) ||
      item.description.toLowerCase().includes(searchQuery.toLowerCase());

    const matchesType = selectedType === 'all' || item.type === selectedType;
    const matchesFeed = selectedFeed === 'all' || item.feed === selectedFeed;

    return matchesSearch && matchesType && matchesFeed;
  });

  return (
    <div className="space-y-6">
      {/* Top Banner / Controls */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 bg-slate-900 border border-slate-800 p-5 rounded-xl">
        <div>
          <h2 className="text-lg font-bold text-slate-100 flex items-center space-x-2">
            <Globe className="h-5 w-5 text-emerald-400" />
            <span>Feeds de Threat Intelligence (Inteligencia de Amenazas)</span>
          </h2>
          <p className="text-xs text-slate-400 mt-1 max-w-2xl">
            Suscripción a fuentes abiertas de reputación cibernética: URLhaus (malware/phishing), AbuseIPDB (brute-force IPs), AlienVault OTX (pulses comunitarios) y Feodo Tracker (C2 botnets).
          </p>
        </div>

        <div className="flex items-center space-x-2">
          <button
            onClick={() => setShowAddModal(true)}
            className="bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 text-xs px-3.5 py-2 rounded-lg font-medium flex items-center space-x-1.5 transition-colors"
          >
            <Plus className="h-4 w-4 text-emerald-400" />
            <span>Añadir IOC Manual</span>
          </button>

          <button
            onClick={onRefreshAllFeeds}
            disabled={isRefreshing}
            className="bg-emerald-600 hover:bg-emerald-500 text-white text-xs px-3.5 py-2 rounded-lg font-medium flex items-center space-x-1.5 transition-colors disabled:opacity-50"
          >
            <RefreshCw className={`h-4 w-4 ${isRefreshing ? 'animate-spin' : ''}`} />
            <span>{isRefreshing ? 'Actualizando Feeds...' : 'Sincronizar Feeds'}</span>
          </button>
        </div>
      </div>

      {/* Feed Cards Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {feeds.map((feed) => (
          <div
            key={feed.id}
            className={`border rounded-xl p-4 transition-all ${
              feed.enabled
                ? 'bg-slate-900/80 border-slate-700 shadow-sm'
                : 'bg-slate-950/40 border-slate-800 opacity-60'
            }`}
          >
            <div className="flex items-start justify-between">
              <div>
                <div className="flex items-center space-x-2">
                  <h3 className="text-sm font-bold text-slate-100">{feed.name}</h3>
                  <span className="text-[10px] bg-slate-800 text-slate-300 px-2 py-0.5 rounded font-mono border border-slate-700">
                    {feed.type.join(', ').toUpperCase()}
                  </span>
                </div>
                <p className="text-xs text-slate-400 mt-1 line-clamp-2">
                  {feed.description}
                </p>
              </div>

              {/* Feed Toggle */}
              <button
                onClick={() => onToggleFeed(feed.id)}
                className={`relative inline-flex h-5 w-9 shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus:outline-hidden ${
                  feed.enabled ? 'bg-emerald-600' : 'bg-slate-800'
                }`}
                role="switch"
                aria-checked={feed.enabled}
              >
                <span
                  className={`pointer-events-none inline-block h-4 w-4 transform rounded-full bg-white shadow-sm ring-0 transition duration-200 ease-in-out ${
                    feed.enabled ? 'translate-x-4' : 'translate-x-0'
                  }`}
                />
              </button>
            </div>

            <div className="mt-4 pt-3 border-t border-slate-800 flex items-center justify-between text-xs text-slate-400">
              <div className="flex items-center space-x-1.5 font-mono">
                <Database className="h-3.5 w-3.5 text-slate-500" />
                <span>{feed.count.toLocaleString()} firmas</span>
              </div>
              <span className="text-[11px] text-emerald-400 font-medium">
                {feed.lastUpdated}
              </span>
            </div>

            {feed.requiresApiKey && (
              <div className="mt-2.5 p-2 rounded bg-slate-950/80 border border-slate-800 flex items-center space-x-2 text-[11px] text-amber-300">
                <Key className="h-3 w-3 shrink-0" />
                <span className="line-clamp-1">{feed.freeTierDocs}</span>
              </div>
            )}
          </div>
        ))}
      </div>

      {/* Threat Intel Database Browser */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
        <div className="p-4 border-b border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-3 bg-slate-950">
          <div>
            <h3 className="text-sm font-bold text-slate-100 flex items-center space-x-2">
              <Database className="h-4 w-4 text-emerald-400" />
              <span>Base de Datos de Indicadores Activos ({filteredIOCs.length})</span>
            </h3>
            <p className="text-xs text-slate-400">
              Muestras de firmas sincronizadas y preparadas para correlación en memoria.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            {/* Search Input */}
            <div className="relative">
              <Search className="h-3.5 w-3.5 absolute left-2.5 top-2.5 text-slate-400" />
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Buscar IOC, malware, IP..."
                className="bg-slate-900 border border-slate-700 rounded-lg pl-8 pr-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-hidden focus:border-emerald-500 w-44 sm:w-56"
              />
            </div>

            {/* Type filter */}
            <select
              value={selectedType}
              onChange={(e) => setSelectedType(e.target.value)}
              className="bg-slate-900 border border-slate-700 rounded-lg px-2.5 py-1.5 text-xs text-slate-200 focus:outline-hidden"
            >
              <option value="all">Todos los Tipos</option>
              <option value="ip">IPs</option>
              <option value="domain">Dominios</option>
              <option value="url">URLs</option>
              <option value="sha256">SHA256</option>
              <option value="md5">MD5</option>
            </select>

            {/* Feed filter */}
            <select
              value={selectedFeed}
              onChange={(e) => setSelectedFeed(e.target.value)}
              className="bg-slate-900 border border-slate-700 rounded-lg px-2.5 py-1.5 text-xs text-slate-200 focus:outline-hidden"
            >
              <option value="all">Todos los Feeds</option>
              <option value="URLhaus">URLhaus</option>
              <option value="AbuseIPDB">AbuseIPDB</option>
              <option value="AlienVault OTX">AlienVault OTX</option>
              <option value="ThreatFox">ThreatFox</option>
              <option value="Feodo Tracker">Feodo Tracker</option>
              <option value="Custom Feed">Personalizados</option>
            </select>
          </div>
        </div>

        {/* Database Table */}
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs text-slate-300">
            <thead className="bg-slate-950/70 border-b border-slate-800 uppercase font-mono text-[11px] text-slate-400">
              <tr>
                <th className="px-4 py-3">Indicador (Defanged)</th>
                <th className="px-4 py-3">Tipo</th>
                <th className="px-4 py-3">Severidad</th>
                <th className="px-4 py-3">Feed Fuente</th>
                <th className="px-4 py-3">Familia de Malware</th>
                <th className="px-4 py-3">Confianza</th>
                <th className="px-4 py-3">Táctica MITRE</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800">
              {filteredIOCs.length === 0 ? (
                <tr>
                  <td colSpan={7} className="text-center py-8 text-slate-500">
                    No se encontraron firmas con los filtros especificados.
                  </td>
                </tr>
              ) : (
                filteredIOCs.map((item) => (
                  <tr key={item.id} className="hover:bg-slate-800/40 transition-colors">
                    <td className="px-4 py-2.5 font-mono text-slate-200 font-medium">
                      {defang(item.value)}
                    </td>
                    <td className="px-4 py-2.5 uppercase text-[11px] font-mono text-slate-400">
                      {item.type}
                    </td>
                    <td className="px-4 py-2.5">
                      <span className={`px-2 py-0.5 text-[10px] font-bold rounded font-mono ${
                        item.severity === 'CRITICAL' ? 'bg-red-950 text-red-300 border border-red-800' :
                        item.severity === 'HIGH' ? 'bg-amber-950 text-amber-300 border border-amber-800' :
                        'bg-blue-950 text-blue-300 border border-blue-800'
                      }`}>
                        {item.severity}
                      </span>
                    </td>
                    <td className="px-4 py-2.5 font-medium text-slate-300">
                      {item.feed}
                    </td>
                    <td className="px-4 py-2.5 text-red-400 font-mono">
                      {item.malwareFamily || '—'}
                    </td>
                    <td className="px-4 py-2.5 font-mono text-slate-300">
                      {item.confidence}%
                    </td>
                    <td className="px-4 py-2.5 text-slate-400">
                      {item.mitreTactic || '—'}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Add Custom IOC Modal */}
      {showAddModal && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-xs flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-700 rounded-xl max-w-lg w-full p-5 shadow-2xl space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h3 className="text-sm font-bold text-slate-100 flex items-center space-x-2">
                <Plus className="h-4 w-4 text-emerald-400" />
                <span>Añadir Nuevo IOC a la Base Local</span>
              </h3>
              <button
                onClick={() => setShowAddModal(false)}
                className="text-slate-400 hover:text-slate-200"
              >
                ✕
              </button>
            </div>

            <form onSubmit={handleAddSubmit} className="space-y-3 text-xs">
              <div>
                <label className="block text-slate-300 font-medium mb-1">
                  Valor del IOC (IP, Dominio, URL, Hash SHA256 o MD5):
                </label>
                <input
                  type="text"
                  required
                  value={newVal}
                  onChange={(e) => setNewVal(e.target.value)}
                  placeholder="Ej: 195.12.34.56 o malware-drop.xyz o hash"
                  className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-slate-200 font-mono focus:outline-hidden focus:border-emerald-500"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-slate-300 font-medium mb-1">Tipo de IOC:</label>
                  <select
                    value={newType}
                    onChange={(e) => setNewType(e.target.value as IOCType)}
                    className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-slate-200 focus:outline-hidden"
                  >
                    <option value="ip">Dirección IP</option>
                    <option value="domain">Dominio (FQDN)</option>
                    <option value="url">URL</option>
                    <option value="sha256">Hash SHA256</option>
                    <option value="md5">Hash MD5</option>
                  </select>
                </div>

                <div>
                  <label className="block text-slate-300 font-medium mb-1">Severidad:</label>
                  <select
                    value={newSeverity}
                    onChange={(e) => setNewSeverity(e.target.value as Severity)}
                    className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-slate-200 focus:outline-hidden"
                  >
                    <option value="CRITICAL">CRITICAL</option>
                    <option value="HIGH">HIGH</option>
                    <option value="MEDIUM">MEDIUM</option>
                    <option value="LOW">LOW</option>
                  </select>
                </div>
              </div>

              <div>
                <label className="block text-slate-300 font-medium mb-1">
                  Familia de Malware / Campaña:
                </label>
                <input
                  type="text"
                  value={newMalware}
                  onChange={(e) => setNewMalware(e.target.value)}
                  placeholder="Ej: Emotet C2, DarkGate, Phishing Office365"
                  className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-slate-200 focus:outline-hidden focus:border-emerald-500"
                />
              </div>

              <div>
                <label className="block text-slate-300 font-medium mb-1">
                  Descripción o Notas del Analista:
                </label>
                <textarea
                  rows={2}
                  value={newDesc}
                  onChange={(e) => setNewDesc(e.target.value)}
                  placeholder="Detalles sobre por qué este indicador es sospechoso..."
                  className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-slate-200 focus:outline-hidden focus:border-emerald-500"
                />
              </div>

              <div className="flex justify-end space-x-2 pt-2 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setShowAddModal(false)}
                  className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg font-medium"
                >
                  Cancelar
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg font-medium"
                >
                  Guardar IOC
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
