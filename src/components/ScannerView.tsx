import React, { useState, useRef } from 'react';
import { 
  UploadCloud, 
  FileText, 
  Play, 
  Download, 
  FileSpreadsheet, 
  FileDown, 
  ShieldAlert, 
  ShieldCheck, 
  CheckCircle2, 
  AlertTriangle, 
  Clock, 
  Hash, 
  ExternalLink, 
  Copy, 
  Check, 
  ChevronDown, 
  ChevronRight, 
  Search, 
  Filter, 
  Layers, 
  RefreshCw,
  Terminal,
  FileCode,
  SlidersHorizontal,
  Code
} from 'lucide-react';
import { IOCRecord, MatchResult, ScanMetrics, LogSample } from '../types';
import { defang } from '../utils/iocExtractor';
import { SAMPLE_LOGS } from '../data/sampleLogs';
import { exportToCSV, exportToPDF, exportSuricataRules, exportIptables, exportSTIX } from '../utils/exporter';

interface ScannerViewProps {
  iocDatabase: IOCRecord[];
  onScan: (logContent: string, logName: string, excludePrivate: boolean) => void;
  results: MatchResult[];
  metrics: ScanMetrics | null;
  isScanning: boolean;
  onOpenTriage: (match: MatchResult) => void;
  currentLogName: string;
}

export const ScannerView: React.FC<ScannerViewProps> = ({
  iocDatabase,
  onScan,
  results,
  metrics,
  isScanning,
  onOpenTriage,
  currentLogName,
}) => {
  const [rawText, setRawText] = useState<string>(SAMPLE_LOGS[0].content);
  const [logName, setLogName] = useState<string>(SAMPLE_LOGS[0].name);
  const [excludePrivateIps, setExcludePrivateIps] = useState<boolean>(true);
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [filterType, setFilterType] = useState<string>('all');
  const [filterSeverity, setFilterSeverity] = useState<string>('all');
  const [filterFeed, setFilterFeed] = useState<string>('all');
  const [expandedRow, setExpandedRow] = useState<string | null>(null);
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = (event) => {
      const content = event.target?.result as string;
      setRawText(content);
      setLogName(file.name);
    };
    reader.readAsText(file);
  };

  const handleSelectSample = (sample: LogSample) => {
    setRawText(sample.content);
    setLogName(sample.name);
  };

  const handleTriggerScan = () => {
    if (!rawText.trim()) return;
    onScan(rawText, logName, excludePrivateIps);
  };

  const copyToClipboard = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  // Filter results
  const filteredResults = results.filter(r => {
    const matchesSearch = 
      r.ioc.value.toLowerCase().includes(searchQuery.toLowerCase()) ||
      (r.ioc.malwareFamily && r.ioc.malwareFamily.toLowerCase().includes(searchQuery.toLowerCase())) ||
      r.ioc.description.toLowerCase().includes(searchQuery.toLowerCase());

    const matchesType = filterType === 'all' || r.ioc.type === filterType;
    const matchesSeverity = filterSeverity === 'all' || r.ioc.severity === filterSeverity;
    const matchesFeed = filterFeed === 'all' || r.ioc.feed === filterFeed;

    return matchesSearch && matchesType && matchesSeverity && matchesFeed;
  });

  return (
    <div className="space-y-6">
      {/* Ingestion & Upload Section */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800 pb-3">
          <div className="flex items-center space-x-2">
            <UploadCloud className="h-5 w-5 text-emerald-400" />
            <h2 className="text-sm font-bold text-slate-100 uppercase tracking-wide font-mono">
              Ingesta de Logs (CSV, JSON, Syslog, Apache o Texto Plano)
            </h2>
          </div>
          <div className="flex items-center space-x-2 text-xs text-slate-400">
            <span className="font-mono text-emerald-400 font-semibold">{iocDatabase.length} IOCs activos</span>
            <span>para correlación cruzada</span>
          </div>
        </div>

        {/* Preset Sample Logs Selector */}
        <div>
          <label className="text-xs text-slate-400 font-medium block mb-1.5">
            Cargar Casos de Incidente de Prueba Rápidos:
          </label>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-2">
            {SAMPLE_LOGS.map((sample) => (
              <button
                key={sample.id}
                onClick={() => handleSelectSample(sample)}
                className={`text-left p-2.5 rounded-lg border text-xs transition-all ${
                  logName === sample.name
                    ? 'bg-emerald-950/40 border-emerald-500/50 text-emerald-300 ring-1 ring-emerald-500/20'
                    : 'bg-slate-950/60 border-slate-800 text-slate-300 hover:border-slate-700 hover:bg-slate-950'
                }`}
              >
                <div className="font-semibold line-clamp-1">{sample.name}</div>
                <div className="text-[10px] text-slate-400 line-clamp-1 mt-0.5">
                  Formato: {sample.format.toUpperCase()}
                </div>
              </button>
            ))}
          </div>
        </div>

        {/* Text Area & Drag-Drop File Ingestion */}
        <div className="relative">
          <div className="flex items-center justify-between bg-slate-950 px-3 py-1.5 border-t border-l border-r border-slate-800 rounded-t-lg text-xs text-slate-400">
            <span className="font-mono text-slate-300 truncate max-w-xs sm:max-w-md">
              Archivo activo: <strong className="text-emerald-400">{logName}</strong>
            </span>
            <div className="flex items-center space-x-2">
              <input
                type="file"
                ref={fileInputRef}
                onChange={handleFileUpload}
                accept=".log,.txt,.csv,.json,.syslog"
                className="hidden"
              />
              <button
                onClick={() => fileInputRef.current?.click()}
                className="text-[11px] bg-slate-800 hover:bg-slate-700 text-slate-200 px-2.5 py-1 rounded font-medium transition-colors"
              >
                Subir Archivo Local (.csv, .json, .log, .txt)
              </button>
              <button
                onClick={() => setRawText('')}
                className="text-[11px] text-slate-500 hover:text-slate-300"
              >
                Limpiar
              </button>
            </div>
          </div>
          <textarea
            rows={6}
            value={rawText}
            onChange={(e) => {
              setRawText(e.target.value);
              setLogName('custom_pasted_logs.txt');
            }}
            placeholder="Pega aquí los logs crudos o arrastra un archivo..."
            className="w-full bg-slate-950 border border-slate-800 rounded-b-lg p-3 text-xs font-mono text-slate-200 focus:outline-hidden focus:border-emerald-500 transition-colors leading-relaxed"
          />
        </div>

        {/* Scan Configuration & Action Button */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pt-1">
          <div className="flex items-center space-x-4 text-xs text-slate-300">
            <label className="flex items-center space-x-2 cursor-pointer select-none">
              <input
                type="checkbox"
                checked={excludePrivateIps}
                onChange={(e) => setExcludePrivateIps(e.target.checked)}
                className="rounded bg-slate-950 border-slate-700 text-emerald-500 focus:ring-emerald-500/20"
              />
              <span>Ignorar IPs privadas RFC 1918 (10.x, 192.168.x, 172.16-31.x)</span>
            </label>
          </div>

          <button
            onClick={handleTriggerScan}
            disabled={isScanning || !rawText.trim()}
            className="bg-emerald-600 hover:bg-emerald-500 text-white text-xs px-6 py-2.5 rounded-lg font-bold flex items-center justify-center space-x-2 shadow-lg shadow-emerald-900/20 transition-all disabled:opacity-50"
          >
            {isScanning ? (
              <>
                <RefreshCw className="h-4 w-4 animate-spin" />
                <span>Analizando & Correlacionando...</span>
              </>
            ) : (
              <>
                <Play className="h-4 w-4 fill-white" />
                <span>Escanear Logs y Cazar IOCs</span>
              </>
            )}
          </button>
        </div>
      </div>

      {/* Metrics Section */}
      {metrics && (
        <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-6 gap-3">
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-3.5">
            <div className="flex items-center justify-between text-slate-400 mb-1">
              <span className="text-[11px] font-medium uppercase tracking-wider">Líneas Analizadas</span>
              <FileText className="h-4 w-4 text-slate-500" />
            </div>
            <div className="text-xl font-bold font-mono text-slate-100">
              {metrics.totalLinesProcessed.toLocaleString()}
            </div>
          </div>

          <div className="bg-slate-900 border border-slate-800 rounded-xl p-3.5">
            <div className="flex items-center justify-between text-slate-400 mb-1">
              <span className="text-[11px] font-medium uppercase tracking-wider">Artefactos Hallados</span>
              <Hash className="h-4 w-4 text-slate-500" />
            </div>
            <div className="text-xl font-bold font-mono text-slate-100">
              {metrics.extractedArtifactsCount}
            </div>
          </div>

          <div className="bg-slate-900 border border-slate-800 rounded-xl p-3.5">
            <div className="flex items-center justify-between text-slate-400 mb-1">
              <span className="text-[11px] font-medium uppercase tracking-wider">IOCs Confirmados</span>
              <ShieldAlert className="h-4 w-4 text-emerald-400" />
            </div>
            <div className="text-xl font-bold font-mono text-emerald-400">
              {metrics.maliciousHitsCount}
            </div>
          </div>

          <div className="bg-slate-900 border border-slate-800 rounded-xl p-3.5">
            <div className="flex items-center justify-between text-slate-400 mb-1">
              <span className="text-[11px] font-medium uppercase tracking-wider">Críticos</span>
              <span className="h-2 w-2 rounded-full bg-red-500"></span>
            </div>
            <div className="text-xl font-bold font-mono text-red-400">
              {metrics.criticalCount}
            </div>
          </div>

          <div className="bg-slate-900 border border-slate-800 rounded-xl p-3.5">
            <div className="flex items-center justify-between text-slate-400 mb-1">
              <span className="text-[11px] font-medium uppercase tracking-wider">Altos</span>
              <span className="h-2 w-2 rounded-full bg-amber-500"></span>
            </div>
            <div className="text-xl font-bold font-mono text-amber-400">
              {metrics.highCount}
            </div>
          </div>

          <div className="bg-slate-900 border border-slate-800 rounded-xl p-3.5">
            <div className="flex items-center justify-between text-slate-400 mb-1">
              <span className="text-[11px] font-medium uppercase tracking-wider">Tiempo de Escaneo</span>
              <Clock className="h-4 w-4 text-slate-500" />
            </div>
            <div className="text-xl font-bold font-mono text-cyan-400">
              {metrics.scanDurationMs} ms
            </div>
          </div>
        </div>
      )}

      {/* Results Section */}
      {metrics && (
        <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-sm space-y-0">
          {/* Header & Export Actions Toolbar */}
          <div className="p-4 border-b border-slate-800 bg-slate-950 flex flex-col lg:flex-row lg:items-center justify-between gap-4">
            <div>
              <h3 className="text-sm font-bold text-slate-100 flex items-center space-x-2 font-mono">
                <Terminal className="h-4 w-4 text-emerald-400" />
                <span>Resultados de Detección & Correlación ({filteredResults.length})</span>
              </h3>
              <p className="text-xs text-slate-400 mt-0.5">
                Amenazas identificadas cruzando los logs contra URLhaus, AbuseIPDB, AlienVault OTX y Feodo Tracker.
              </p>
            </div>

            {/* Export Toolbar */}
            <div className="flex flex-wrap items-center gap-2">
              <button
                onClick={() => exportToCSV(filteredResults, `report_${logName.replace(/\s+/g, '_')}.csv`)}
                disabled={filteredResults.length === 0}
                className="bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 text-xs px-3 py-1.5 rounded-md font-medium flex items-center space-x-1.5 transition-colors disabled:opacity-40"
              >
                <FileSpreadsheet className="h-3.5 w-3.5 text-emerald-400" />
                <span>Exportar CSV</span>
              </button>

              <button
                onClick={() => exportToPDF(filteredResults, metrics, logName)}
                disabled={filteredResults.length === 0}
                className="bg-red-950 hover:bg-red-900 text-red-200 border border-red-800 text-xs px-3 py-1.5 rounded-md font-medium flex items-center space-x-1.5 transition-colors disabled:opacity-40"
              >
                <FileDown className="h-3.5 w-3.5 text-red-400" />
                <span>Reporte PDF Ejecutivo</span>
              </button>

              <button
                onClick={() => exportSuricataRules(filteredResults)}
                disabled={filteredResults.length === 0}
                className="bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 text-xs px-2.5 py-1.5 rounded-md font-medium flex items-center space-x-1 transition-colors disabled:opacity-40"
                title="Generar reglas para Suricata / Snort"
              >
                <Code className="h-3.5 w-3.5 text-cyan-400" />
                <span>Suricata</span>
              </button>

              <button
                onClick={() => exportIptables(filteredResults)}
                disabled={filteredResults.length === 0}
                className="bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 text-xs px-2.5 py-1.5 rounded-md font-medium flex items-center space-x-1 transition-colors disabled:opacity-40"
                title="Descargar script iptables DROP"
              >
                <Terminal className="h-3.5 w-3.5 text-amber-400" />
                <span>iptables</span>
              </button>

              <button
                onClick={() => exportSTIX(filteredResults)}
                disabled={filteredResults.length === 0}
                className="bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 text-xs px-2.5 py-1.5 rounded-md font-medium flex items-center space-x-1 transition-colors disabled:opacity-40"
                title="Exportar formato estándar STIX 2.1"
              >
                <Layers className="h-3.5 w-3.5 text-indigo-400" />
                <span>STIX 2.1</span>
              </button>
            </div>
          </div>

          {/* Filters Bar */}
          <div className="p-3 bg-slate-950/60 border-b border-slate-800 flex flex-wrap items-center gap-2">
            <div className="relative flex-1 min-w-[180px]">
              <Search className="h-3.5 w-3.5 absolute left-2.5 top-2.5 text-slate-400" />
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Filtrar por IOC, malware, descripción..."
                className="w-full bg-slate-900 border border-slate-800 rounded-lg pl-8 pr-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-hidden focus:border-emerald-500"
              />
            </div>

            <select
              value={filterType}
              onChange={(e) => setFilterType(e.target.value)}
              className="bg-slate-900 border border-slate-800 rounded-lg px-2.5 py-1.5 text-xs text-slate-200 focus:outline-hidden"
            >
              <option value="all">Tipos (Todos)</option>
              <option value="ip">IPs</option>
              <option value="domain">Dominios</option>
              <option value="url">URLs</option>
              <option value="sha256">SHA256</option>
              <option value="md5">MD5</option>
            </select>

            <select
              value={filterSeverity}
              onChange={(e) => setFilterSeverity(e.target.value)}
              className="bg-slate-900 border border-slate-800 rounded-lg px-2.5 py-1.5 text-xs text-slate-200 focus:outline-hidden"
            >
              <option value="all">Severidad (Todas)</option>
              <option value="CRITICAL">Crítica</option>
              <option value="HIGH">Alta</option>
              <option value="MEDIUM">Media</option>
              <option value="LOW">Baja</option>
            </select>

            <select
              value={filterFeed}
              onChange={(e) => setFilterFeed(e.target.value)}
              className="bg-slate-900 border border-slate-800 rounded-lg px-2.5 py-1.5 text-xs text-slate-200 focus:outline-hidden"
            >
              <option value="all">Feeds (Todos)</option>
              <option value="URLhaus">URLhaus</option>
              <option value="AbuseIPDB">AbuseIPDB</option>
              <option value="AlienVault OTX">AlienVault OTX</option>
              <option value="ThreatFox">ThreatFox</option>
              <option value="Feodo Tracker">Feodo Tracker</option>
            </select>
          </div>

          {/* Detections Table */}
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs text-slate-300">
              <thead className="bg-slate-950 uppercase font-mono text-[11px] text-slate-400 border-b border-slate-800">
                <tr>
                  <th className="w-8 px-3 py-3"></th>
                  <th className="px-3 py-3">Severidad</th>
                  <th className="px-3 py-3">IOC (Defanged)</th>
                  <th className="px-3 py-3">Tipo</th>
                  <th className="px-3 py-3">Fuente Feed</th>
                  <th className="px-3 py-3">Familia / Amenaza</th>
                  <th className="px-3 py-3 text-center">Hits</th>
                  <th className="px-3 py-3 text-right">Acciones</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800">
                {filteredResults.length === 0 ? (
                  <tr>
                    <td colSpan={8} className="text-center py-10 text-slate-500">
                      {results.length === 0 
                        ? 'No se detectaron IOCs maliciosos en este archivo de logs. ¡Limpio!'
                        : 'No hay coincidencias con los filtros aplicados.'}
                    </td>
                  </tr>
                ) : (
                  filteredResults.map((result) => {
                    const isExpanded = expandedRow === result.id;
                    const defangedVal = defang(result.ioc.value);

                    return (
                      <React.Fragment key={result.id}>
                        <tr className={`hover:bg-slate-800/40 transition-colors ${
                          isExpanded ? 'bg-slate-800/20' : ''
                        }`}>
                          <td className="px-3 py-3">
                            <button
                              onClick={() => setExpandedRow(isExpanded ? null : result.id)}
                              className="text-slate-400 hover:text-slate-200"
                            >
                              {isExpanded ? (
                                <ChevronDown className="h-4 w-4" />
                              ) : (
                                <ChevronRight className="h-4 w-4" />
                              )}
                            </button>
                          </td>

                          <td className="px-3 py-3">
                            <span className={`px-2 py-0.5 text-[10px] font-bold rounded font-mono ${
                              result.ioc.severity === 'CRITICAL' ? 'bg-red-950 text-red-300 border border-red-800' :
                              result.ioc.severity === 'HIGH' ? 'bg-amber-950 text-amber-300 border border-amber-800' :
                              'bg-blue-950 text-blue-300 border border-blue-800'
                            }`}>
                              {result.ioc.severity}
                            </span>
                          </td>

                          <td className="px-3 py-3 font-mono font-medium text-slate-200">
                            <div className="flex items-center space-x-2">
                              <span className="truncate max-w-[180px] sm:max-w-[260px]" title={result.ioc.value}>
                                {defangedVal}
                              </span>
                              <button
                                onClick={() => copyToClipboard(result.ioc.value, result.id)}
                                className="text-slate-500 hover:text-slate-300"
                                title="Copiar IOC"
                              >
                                {copiedId === result.id ? (
                                  <Check className="h-3 w-3 text-emerald-400" />
                                ) : (
                                  <Copy className="h-3 w-3" />
                                )}
                              </button>
                            </div>
                          </td>

                          <td className="px-3 py-3 uppercase text-[10px] font-mono text-slate-400">
                            {result.ioc.type}
                          </td>

                          <td className="px-3 py-3 font-medium text-slate-300">
                            <span className="px-1.5 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700 text-[11px]">
                              {result.ioc.feed}
                            </span>
                          </td>

                          <td className="px-3 py-3 text-red-400 font-mono text-xs">
                            {result.ioc.malwareFamily || result.ioc.description}
                          </td>

                          <td className="px-3 py-3 text-center">
                            <span className="inline-flex items-center justify-center px-2 py-0.5 rounded-full text-xs font-bold font-mono bg-emerald-950 text-emerald-400 border border-emerald-800">
                              {result.count}
                            </span>
                          </td>

                          <td className="px-3 py-3 text-right">
                            <button
                              onClick={() => onOpenTriage(result)}
                              className="text-xs bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 px-2.5 py-1 rounded font-medium transition-colors"
                            >
                              Triaje & Playbook
                            </button>
                          </td>
                        </tr>

                        {/* Expanded Context Row: Show exact log lines */}
                        {isExpanded && (
                          <tr className="bg-slate-950/90">
                            <td colSpan={8} className="p-4 border-t border-b border-slate-800">
                              <div className="space-y-2">
                                <div className="flex items-center justify-between">
                                  <span className="text-[11px] font-semibold text-emerald-400 uppercase tracking-wider font-mono">
                                    Evidencia en los Logs ({result.matchedLines.length} muestras):
                                  </span>
                                  <span className="text-[11px] text-slate-500 font-mono">
                                    Presiona "Triaje & Playbook" para mitigación completa
                                  </span>
                                </div>
                                <div className="bg-slate-900 p-3 rounded-lg border border-slate-800 font-mono text-xs space-y-1.5 max-h-40 overflow-y-auto">
                                  {result.matchedLines.map((line, idx) => (
                                    <div key={idx} className="flex space-x-2 text-slate-300">
                                      <span className="text-slate-500 select-none w-8 text-right">
                                        L{line.lineNum}:
                                      </span>
                                      <span className="break-all">{line.rawText}</span>
                                    </div>
                                  ))}
                                </div>
                              </div>
                            </td>
                          </tr>
                        )}
                      </React.Fragment>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
};
