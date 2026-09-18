import React from 'react';
import { 
  ShieldAlert, 
  ExternalLink, 
  Copy, 
  Check, 
  FileText, 
  AlertTriangle, 
  CheckCircle2, 
  XCircle,
  HelpCircle,
  Layers,
  Terminal,
  ShieldCheck,
  Server
} from 'lucide-react';
import { MatchResult } from '../types';
import { defang } from '../utils/iocExtractor';

interface TriageModalProps {
  match: MatchResult | null;
  onClose: () => void;
  onStatusChange: (id: string, status: 'unreviewed' | 'confirmed' | 'false_positive') => void;
}

export const TriageModal: React.FC<TriageModalProps> = ({ match, onClose, onStatusChange }) => {
  const [copied, setCopied] = React.useState(false);

  if (!match) return null;

  const { ioc, count, matchedLines, triageStatus } = match;
  const defangedVal = defang(ioc.value);

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  // Third party investigation links
  const vtUrl = ioc.type === 'ip' 
    ? `https://www.virustotal.com/gui/ip-address/${ioc.value}`
    : ioc.type === 'domain'
    ? `https://www.virustotal.com/gui/domain/${ioc.value}`
    : ioc.type === 'url'
    ? `https://www.virustotal.com/gui/url/${encodeURIComponent(ioc.value)}`
    : `https://www.virustotal.com/gui/file/${ioc.value}`;

  const abuseIpdbUrl = ioc.type === 'ip' ? `https://www.abuseipdb.com/check/${ioc.value}` : null;
  const urlhausUrl = ioc.type === 'domain' || ioc.type === 'url' ? `https://urlhaus.abuse.ch/browse/` : null;

  return (
    <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-xs flex items-center justify-center p-4 overflow-y-auto">
      <div className="bg-slate-900 border border-slate-700 rounded-xl max-w-3xl w-full shadow-2xl overflow-hidden my-8 animate-in fade-in zoom-in-95 duration-150">
        {/* Header */}
        <div className="bg-slate-950 px-6 py-4 border-b border-slate-800 flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <div className={`p-2 rounded-lg ${
              ioc.severity === 'CRITICAL' ? 'bg-red-500/20 text-red-400 border border-red-500/30' :
              ioc.severity === 'HIGH' ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30' :
              'bg-blue-500/20 text-blue-400 border border-blue-500/30'
            }`}>
              <ShieldAlert className="h-5 w-5" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <h2 className="text-base font-bold text-slate-100 font-mono">
                  {defangedVal}
                </h2>
                <button
                  onClick={() => copyToClipboard(ioc.value)}
                  className="text-slate-400 hover:text-slate-200"
                  title="Copiar valor canónico"
                >
                  {copied ? <Check className="h-4 w-4 text-emerald-400" /> : <Copy className="h-4 w-4" />}
                </button>
              </div>
              <p className="text-xs text-slate-400">
                {ioc.type.toUpperCase()} • Coincidencias en log: <span className="font-semibold text-emerald-400">{count}</span>
              </p>
            </div>
          </div>

          <div className="flex items-center space-x-3">
            <span className={`px-2.5 py-1 text-xs font-bold rounded-md font-mono border ${
              ioc.severity === 'CRITICAL' ? 'bg-red-950/80 text-red-300 border-red-800' :
              ioc.severity === 'HIGH' ? 'bg-amber-950/80 text-amber-300 border-amber-800' :
              'bg-blue-950/80 text-blue-300 border-blue-800'
            }`}>
              SEVERIDAD: {ioc.severity}
            </span>
            <button
              onClick={onClose}
              className="text-slate-400 hover:text-slate-200 text-lg font-bold px-2 py-1 rounded-md hover:bg-slate-800"
            >
              ✕
            </button>
          </div>
        </div>

        {/* Body Content */}
        <div className="p-6 space-y-6 max-h-[75vh] overflow-y-auto">
          {/* Metadata Grid */}
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
            <div className="bg-slate-950/70 border border-slate-800 rounded-lg p-3">
              <span className="text-[11px] font-medium text-slate-400 uppercase tracking-wider block">Fuente Feed</span>
              <span className="text-sm font-semibold text-slate-200 flex items-center space-x-1 mt-1">
                <span>{ioc.feed}</span>
              </span>
            </div>

            <div className="bg-slate-950/70 border border-slate-800 rounded-lg p-3">
              <span className="text-[11px] font-medium text-slate-400 uppercase tracking-wider block">Familia de Malware</span>
              <span className="text-sm font-semibold text-red-400 mt-1 block">
                {ioc.malwareFamily || 'No clasificado'}
              </span>
            </div>

            <div className="bg-slate-950/70 border border-slate-800 rounded-lg p-3">
              <span className="text-[11px] font-medium text-slate-400 uppercase tracking-wider block">Nivel de Confianza</span>
              <div className="flex items-center space-x-2 mt-1">
                <div className="w-full bg-slate-800 rounded-full h-2">
                  <div 
                    className="bg-emerald-500 h-2 rounded-full" 
                    style={{ width: `${ioc.confidence}%` }}
                  ></div>
                </div>
                <span className="text-xs font-mono font-bold text-slate-200">{ioc.confidence}%</span>
              </div>
            </div>
          </div>

          {/* Description & Threat Actor */}
          <div className="bg-slate-950/50 border border-slate-800 rounded-lg p-4 space-y-2">
            <h4 className="text-xs font-semibold text-slate-300 uppercase tracking-wider flex items-center space-x-1.5">
              <FileText className="h-4 w-4 text-emerald-400" />
              <span>Inteligencia Contextual de la Amenaza</span>
            </h4>
            <p className="text-sm text-slate-300 leading-relaxed">
              {ioc.description || 'Indicador identificado en correlación de feeds de reputación.'}
            </p>
            {ioc.threatActor && (
              <div className="text-xs text-amber-400 font-mono pt-1">
                Actor Asociado: <span className="font-bold underline">{ioc.threatActor}</span>
              </div>
            )}
          </div>

          {/* MITRE ATT&CK Mapping */}
          {(ioc.mitreTactic || ioc.mitreTechnique) && (
            <div className="bg-indigo-950/20 border border-indigo-900/50 rounded-lg p-4">
              <div className="flex items-center space-x-2 mb-2">
                <Layers className="h-4 w-4 text-indigo-400" />
                <h4 className="text-xs font-semibold text-indigo-300 uppercase tracking-wider">
                  Mapeo MITRE ATT&CK®
                </h4>
              </div>
              <div className="flex flex-wrap gap-2 text-xs">
                {ioc.mitreTactic && (
                  <span className="px-2.5 py-1 rounded bg-indigo-900/40 border border-indigo-700/60 text-indigo-200 font-mono">
                    Táctica: {ioc.mitreTactic}
                  </span>
                )}
                {ioc.mitreTechnique && (
                  <span className="px-2.5 py-1 rounded bg-indigo-900/40 border border-indigo-700/60 text-indigo-200 font-mono">
                    Técnica: {ioc.mitreTechnique}
                  </span>
                )}
              </div>
            </div>
          )}

          {/* Log Context Snippets */}
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <h4 className="text-xs font-semibold text-slate-300 uppercase tracking-wider flex items-center space-x-1.5">
                <Terminal className="h-4 w-4 text-emerald-400" />
                <span>Líneas Exactas del Log donde fue Detectado ({matchedLines.length})</span>
              </h4>
              <span className="text-[11px] text-slate-500">Muestra hasta 15 líneas</span>
            </div>
            
            <div className="bg-slate-950 rounded-lg border border-slate-800 p-3 space-y-2 max-h-48 overflow-y-auto font-mono text-xs text-slate-300">
              {matchedLines.map((line, idx) => (
                <div key={idx} className="flex space-x-2 border-b border-slate-900/80 pb-1.5 last:border-none last:pb-0">
                  <span className="text-slate-600 select-none w-10 text-right">L{line.lineNum}</span>
                  <span className="text-slate-300 break-all">
                    {line.rawText}
                  </span>
                </div>
              ))}
            </div>
          </div>

          {/* SOC Recommended Containment Playbook */}
          <div className="bg-red-950/20 border border-red-900/40 rounded-lg p-4 space-y-2">
            <h4 className="text-xs font-semibold text-red-300 uppercase tracking-wider flex items-center space-x-1.5">
              <ShieldCheck className="h-4 w-4 text-red-400" />
              <span>Playbook de Contención para Analistas SOC</span>
            </h4>
            <ul className="text-xs text-slate-300 space-y-1.5 list-disc list-inside">
              <li>
                <strong>Bloqueo Perimetral:</strong> Insertar regla DROP en Firewall de borde / WAF para detener la comunicación con {defangedVal}.
              </li>
              <li>
                <strong>Aislamiento de Host:</strong> Aislar inmediatamente la IP de origen que inició la petición mediante EDR (CrowdStrike, Defender, SentinelOne).
              </li>
              <li>
                <strong>Rotación de Credenciales:</strong> Si se trata de un infostealer (Lumma, AgentTesla, RedLine), forzar cambio de contraseña y revocar sesiones de usuario activas.
              </li>
            </ul>
          </div>

          {/* Pivot Investigation Links */}
          <div className="flex flex-wrap gap-2 pt-1">
            <a
              href={vtUrl}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center space-x-1.5 text-xs bg-slate-800 hover:bg-slate-700 text-slate-200 px-3 py-1.5 rounded-lg border border-slate-700 transition-colors"
            >
              <span>VirusTotal</span>
              <ExternalLink className="h-3 w-3 text-slate-400" />
            </a>

            {abuseIpdbUrl && (
              <a
                href={abuseIpdbUrl}
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex items-center space-x-1.5 text-xs bg-slate-800 hover:bg-slate-700 text-slate-200 px-3 py-1.5 rounded-lg border border-slate-700 transition-colors"
              >
                <span>AbuseIPDB Report</span>
                <ExternalLink className="h-3 w-3 text-slate-400" />
              </a>
            )}

            {urlhausUrl && (
              <a
                href={urlhausUrl}
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex items-center space-x-1.5 text-xs bg-slate-800 hover:bg-slate-700 text-slate-200 px-3 py-1.5 rounded-lg border border-slate-700 transition-colors"
              >
                <span>URLhaus Intel</span>
                <ExternalLink className="h-3 w-3 text-slate-400" />
              </a>
            )}

            {ioc.referenceUrl && (
              <a
                href={ioc.referenceUrl}
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex items-center space-x-1.5 text-xs bg-slate-800 hover:bg-slate-700 text-slate-200 px-3 py-1.5 rounded-lg border border-slate-700 transition-colors"
              >
                <span>Reporte Oficial de Fuente</span>
                <ExternalLink className="h-3 w-3 text-slate-400" />
              </a>
            )}
          </div>
        </div>

        {/* Footer with Status Assignment */}
        <div className="bg-slate-950 px-6 py-4 border-t border-slate-800 flex flex-col sm:flex-row items-center justify-between gap-3">
          <div className="flex items-center space-x-2">
            <span className="text-xs text-slate-400">Estado de Triaje SOC:</span>
            <div className="flex space-x-1">
              <button
                onClick={() => onStatusChange(match.id, 'confirmed')}
                className={`text-xs px-2.5 py-1 rounded-md font-medium flex items-center space-x-1 transition-colors ${
                  triageStatus === 'confirmed'
                    ? 'bg-red-600 text-white'
                    : 'bg-slate-800 text-slate-400 hover:text-red-300'
                }`}
              >
                <CheckCircle2 className="h-3 w-3" />
                <span>Confirmado Malicioso</span>
              </button>

              <button
                onClick={() => onStatusChange(match.id, 'false_positive')}
                className={`text-xs px-2.5 py-1 rounded-md font-medium flex items-center space-x-1 transition-colors ${
                  triageStatus === 'false_positive'
                    ? 'bg-emerald-600 text-white'
                    : 'bg-slate-800 text-slate-400 hover:text-emerald-300'
                }`}
              >
                <XCircle className="h-3 w-3" />
                <span>Falso Positivo</span>
              </button>

              <button
                onClick={() => onStatusChange(match.id, 'unreviewed')}
                className={`text-xs px-2.5 py-1 rounded-md font-medium flex items-center space-x-1 transition-colors ${
                  triageStatus === 'unreviewed'
                    ? 'bg-slate-700 text-white'
                    : 'bg-slate-800 text-slate-400 hover:text-slate-200'
                }`}
              >
                <HelpCircle className="h-3 w-3" />
                <span>Pendiente</span>
              </button>
            </div>
          </div>

          <button
            onClick={onClose}
            className="w-full sm:w-auto bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs px-5 py-2 rounded-lg font-medium transition-colors"
          >
            Cerrar Ficha
          </button>
        </div>
      </div>
    </div>
  );
};
