import React from 'react';
import { 
  ShieldAlert, 
  Layers, 
  Crosshair, 
  ExternalLink, 
  AlertOctagon, 
  CheckCircle2, 
  XCircle,
  FileText,
  Activity
} from 'lucide-react';
import { MatchResult } from '../types';
import { defang } from '../utils/iocExtractor';

interface TriageMatrixViewProps {
  results: MatchResult[];
  onOpenTriage: (match: MatchResult) => void;
}

export const TriageMatrixView: React.FC<TriageMatrixViewProps> = ({ results, onOpenTriage }) => {
  // Group results by MITRE tactic or severity
  const criticalResults = results.filter(r => r.ioc.severity === 'CRITICAL');
  const highResults = results.filter(r => r.ioc.severity === 'HIGH');
  const otherResults = results.filter(r => r.ioc.severity !== 'CRITICAL' && r.ioc.severity !== 'HIGH');

  // MITRE Tactics breakdown
  const tacticGroups: Record<string, MatchResult[]> = {};
  for (const r of results) {
    const tactic = r.ioc.mitreTactic || 'Sin Táctica Asignada';
    if (!tacticGroups[tactic]) tacticGroups[tactic] = [];
    tacticGroups[tactic].push(r);
  }

  return (
    <div className="space-y-6">
      {/* Overview Banner */}
      <div className="bg-slate-900 border border-slate-800 p-5 rounded-xl">
        <div className="flex items-center space-x-3">
          <div className="p-2 rounded-lg bg-indigo-500/10 border border-indigo-500/30 text-indigo-400">
            <Layers className="h-6 w-6" />
          </div>
          <div>
            <h2 className="text-base font-bold text-slate-100">
              Matriz MITRE ATT&CK® & Triaje de Amenazas
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Correlación táctica de los indicadores de compromiso detectados según la metodología ATT&CK de ciberseguridad defensiva.
            </p>
          </div>
        </div>
      </div>

      {/* MITRE ATT&CK Tactic Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {Object.entries(tacticGroups).map(([tactic, items]) => (
          <div key={tactic} className="bg-slate-900 border border-slate-800 rounded-xl p-4 space-y-3">
            <div className="flex items-center justify-between border-b border-slate-800 pb-2.5">
              <h3 className="text-xs font-bold font-mono text-indigo-300 uppercase tracking-wide">
                {tactic}
              </h3>
              <span className="text-xs font-mono font-bold bg-indigo-950 text-indigo-300 border border-indigo-800 px-2 py-0.5 rounded-full">
                {items.length} {items.length === 1 ? 'IOC' : 'IOCs'}
              </span>
            </div>

            <div className="space-y-2 max-h-60 overflow-y-auto">
              {items.map((item) => (
                <div
                  key={item.id}
                  onClick={() => onOpenTriage(item)}
                  className="bg-slate-950 border border-slate-800 hover:border-slate-700 p-2.5 rounded-lg cursor-pointer transition-all text-xs space-y-1"
                >
                  <div className="flex items-center justify-between">
                    <span className="font-mono font-semibold text-slate-200 truncate max-w-[180px]">
                      {defang(item.ioc.value)}
                    </span>
                    <span className={`text-[9px] font-bold px-1.5 py-0.5 rounded font-mono ${
                      item.ioc.severity === 'CRITICAL' ? 'bg-red-950 text-red-300 border border-red-800' :
                      item.ioc.severity === 'HIGH' ? 'bg-amber-950 text-amber-300 border border-amber-800' :
                      'bg-blue-950 text-blue-300 border border-blue-800'
                    }`}>
                      {item.ioc.severity}
                    </span>
                  </div>

                  <div className="text-[11px] text-red-400 font-mono">
                    {item.ioc.malwareFamily || item.ioc.description}
                  </div>

                  <div className="flex items-center justify-between text-[10px] text-slate-500 pt-1">
                    <span>{item.ioc.feed}</span>
                    <span className="text-emerald-400 font-mono font-medium">{item.count} hits</span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        ))}
      </div>

      {/* Triaged Status Breakdown */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
        <h3 className="text-sm font-bold text-slate-100 flex items-center space-x-2">
          <Activity className="h-4 w-4 text-emerald-400" />
          <span>Resumen de Casos de Amenaza y Estado de Revisión</span>
        </h3>

        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
          <div className="bg-slate-950 p-3 rounded-lg border border-slate-800">
            <div className="flex items-center justify-between text-xs text-slate-400">
              <span>Confirmados Maliciosos</span>
              <CheckCircle2 className="h-4 w-4 text-red-400" />
            </div>
            <div className="text-xl font-bold font-mono text-red-400 mt-1">
              {results.filter(r => r.triageStatus === 'confirmed').length}
            </div>
          </div>

          <div className="bg-slate-950 p-3 rounded-lg border border-slate-800">
            <div className="flex items-center justify-between text-xs text-slate-400">
              <span>Pendientes de Revisión</span>
              <AlertOctagon className="h-4 w-4 text-amber-400" />
            </div>
            <div className="text-xl font-bold font-mono text-amber-400 mt-1">
              {results.filter(r => r.triageStatus === 'unreviewed').length}
            </div>
          </div>

          <div className="bg-slate-950 p-3 rounded-lg border border-slate-800">
            <div className="flex items-center justify-between text-xs text-slate-400">
              <span>Descartados / Falsos Positivos</span>
              <XCircle className="h-4 w-4 text-emerald-400" />
            </div>
            <div className="text-xl font-bold font-mono text-emerald-400 mt-1">
              {results.filter(r => r.triageStatus === 'false_positive').length}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
