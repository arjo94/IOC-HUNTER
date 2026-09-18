import React, { useState } from 'react';
import { 
  ShieldCheck, 
  Terminal, 
  Globe, 
  FileCode2, 
  Activity, 
  Crosshair, 
  Copy, 
  Check, 
  ExternalLink,
  Lock,
  Sparkles
} from 'lucide-react';
import { defang, refang } from '../utils/iocExtractor';

interface NavbarProps {
  activeTab: 'scanner' | 'feeds' | 'triage' | 'python_guide';
  setActiveTab: (tab: 'scanner' | 'feeds' | 'triage' | 'python_guide') => void;
  activeFeedsCount: number;
  totalIOCsCount: number;
}

export const Navbar: React.FC<NavbarProps> = ({
  activeTab,
  setActiveTab,
  activeFeedsCount,
  totalIOCsCount,
}) => {
  const [showDefangModal, setShowDefangModal] = useState(false);
  const [defangInput, setDefangInput] = useState('');
  const [copied, setCopied] = useState(false);

  const defangedResult = defang(defangInput);
  const refangedResult = refang(defangInput);

  const handleCopy = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <header className="border-b border-slate-800 bg-slate-950/90 backdrop-blur-md sticky top-0 z-40">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          {/* Logo & Platform Info */}
          <div className="flex items-center space-x-3">
            <div className="h-10 w-10 rounded-lg bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center text-emerald-400 shadow-sm shadow-emerald-500/10">
              <Crosshair className="h-5 w-5 animate-pulse" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <span className="font-bold text-lg text-slate-100 tracking-tight font-mono">
                  IOC<span className="text-emerald-400">.Hunter</span>
                </span>
                <span className="px-1.5 py-0.5 text-[10px] font-semibold tracking-wider font-mono rounded bg-slate-800 text-slate-300 border border-slate-700">
                  v2.4 SOC
                </span>
              </div>
              <p className="text-xs text-slate-400 hidden sm:block">
                Threat Intelligence & Log Analyzer perimetral
              </p>
            </div>
          </div>

          {/* Navigation Tabs */}
          <nav className="flex items-center space-x-1 sm:space-x-2">
            <button
              onClick={() => setActiveTab('scanner')}
              className={`px-3 py-1.5 rounded-md text-xs sm:text-sm font-medium transition-colors flex items-center space-x-1.5 ${
                activeTab === 'scanner'
                  ? 'bg-emerald-500/15 text-emerald-300 border border-emerald-500/30 shadow-xs'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'
              }`}
            >
              <Terminal className="h-4 w-4" />
              <span>Escáner SOC</span>
            </button>

            <button
              onClick={() => setActiveTab('feeds')}
              className={`px-3 py-1.5 rounded-md text-xs sm:text-sm font-medium transition-colors flex items-center space-x-1.5 ${
                activeTab === 'feeds'
                  ? 'bg-emerald-500/15 text-emerald-300 border border-emerald-500/30 shadow-xs'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'
              }`}
            >
              <Globe className="h-4 w-4" />
              <span>Feeds Intel</span>
              <span className="ml-1 text-[10px] bg-slate-800 text-slate-300 px-1 rounded-full font-mono">
                {activeFeedsCount}
              </span>
            </button>

            <button
              onClick={() => setActiveTab('triage')}
              className={`px-3 py-1.5 rounded-md text-xs sm:text-sm font-medium transition-colors flex items-center space-x-1.5 ${
                activeTab === 'triage'
                  ? 'bg-emerald-500/15 text-emerald-300 border border-emerald-500/30 shadow-xs'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'
              }`}
            >
              <Activity className="h-4 w-4" />
              <span>Matriz MITRE</span>
            </button>

            <button
              onClick={() => setActiveTab('python_guide')}
              className={`px-3 py-1.5 rounded-md text-xs sm:text-sm font-medium transition-colors flex items-center space-x-1.5 ${
                activeTab === 'python_guide'
                  ? 'bg-cyan-500/15 text-cyan-300 border border-cyan-500/30 shadow-xs'
                  : 'text-cyan-400 hover:text-cyan-300 hover:bg-slate-900'
              }`}
            >
              <FileCode2 className="h-4 w-4" />
              <span className="font-semibold">Código Python & Demo</span>
              <span className="hidden md:inline-flex text-[9px] px-1 py-0.2 rounded bg-cyan-900/60 text-cyan-200 border border-cyan-700/50">
                Portafolio
              </span>
            </button>
          </nav>

          {/* Quick Utility Tool & Live Status */}
          <div className="hidden lg:flex items-center space-x-3">
            <button
              onClick={() => setShowDefangModal(true)}
              className="text-xs bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-700 hover:border-slate-600 px-2.5 py-1.5 rounded-md flex items-center space-x-1.5 transition-colors"
              title="Herramienta para defang/refang rápido de URLs o IPs"
            >
              <Lock className="h-3.5 w-3.5 text-amber-400" />
              <span>Defang Tool</span>
            </button>

            <div className="flex items-center space-x-2 text-xs text-slate-400 border-l border-slate-800 pl-3">
              <span className="relative flex h-2 w-2">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
              </span>
              <span className="font-mono text-slate-300 text-[11px]">
                {totalIOCsCount} IOCs en memoria
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* Quick Defang / Refang Helper Modal */}
      {showDefangModal && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-xs flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-700 rounded-xl max-w-lg w-full p-5 shadow-2xl space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center space-x-2">
                <Lock className="h-4 w-4 text-emerald-400" />
                <h3 className="text-sm font-semibold text-slate-100">
                  Herramienta de Sanitización / Defanging de IOCs
                </h3>
              </div>
              <button
                onClick={() => setShowDefangModal(false)}
                className="text-slate-400 hover:text-slate-200 text-sm font-bold"
              >
                ✕
              </button>
            </div>

            <p className="text-xs text-slate-400">
              Transforma indicadores maliciosos a formato seguro (defanged) para compartir en reportes o tickets sin activar filtros de correo o clics accidentales.
            </p>

            <div className="space-y-2">
              <label className="text-xs font-medium text-slate-300">
                Pega tu IP, Dominio o URL:
              </label>
              <input
                type="text"
                value={defangInput}
                onChange={(e) => setDefangInput(e.target.value)}
                placeholder="Ejemplo: http://malware-drop.com/c2.exe o 185.220.101.5"
                className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-xs font-mono text-slate-200 focus:outline-hidden focus:border-emerald-500"
              />
            </div>

            {defangInput && (
              <div className="space-y-3 pt-2">
                <div className="bg-slate-950 p-2.5 rounded-lg border border-slate-800">
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-[11px] font-semibold text-emerald-400 uppercase tracking-wide">
                      Formato Seguro (Defanged):
                    </span>
                    <button
                      onClick={() => handleCopy(defangedResult)}
                      className="text-[11px] text-slate-400 hover:text-slate-200 flex items-center space-x-1"
                    >
                      {copied ? <Check className="h-3 w-3 text-emerald-400" /> : <Copy className="h-3 w-3" />}
                      <span>{copied ? 'Copiado' : 'Copiar'}</span>
                    </button>
                  </div>
                  <code className="text-xs font-mono text-slate-200 break-all select-all">
                    {defangedResult}
                  </code>
                </div>

                <div className="bg-slate-950 p-2.5 rounded-lg border border-slate-800">
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-[11px] font-semibold text-cyan-400 uppercase tracking-wide">
                      Formato Canónico (Refanged):
                    </span>
                    <button
                      onClick={() => handleCopy(refangedResult)}
                      className="text-[11px] text-slate-400 hover:text-slate-200 flex items-center space-x-1"
                    >
                      <Copy className="h-3 w-3" />
                      <span>Copiar</span>
                    </button>
                  </div>
                  <code className="text-xs font-mono text-slate-200 break-all select-all">
                    {refangedResult}
                  </code>
                </div>
              </div>
            )}

            <div className="flex justify-end pt-2">
              <button
                onClick={() => setShowDefangModal(false)}
                className="bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs px-4 py-2 rounded-lg font-medium transition-colors"
              >
                Cerrar
              </button>
            </div>
          </div>
        </div>
      )}
    </header>
  );
};
