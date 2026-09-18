import jsPDF from 'jspdf';
import { MatchResult, ScanMetrics } from '../types';
import { defang } from './iocExtractor';

export function exportToCSV(results: MatchResult[], filename: string = 'ioc_hunter_report.csv'): void {
  const headers = [
    'IOC',
    'IOC_Defanged',
    'Tipo',
    'Severidad',
    'Fuente_Feed',
    'Familia_Malware',
    'Confianza_Porcentaje',
    'Veces_Detectado',
    'Primeras_Lineas_Coincidencia',
    'Descripcion_Amenaza',
    'Tactica_MITRE',
    'Enlace_Referencia',
  ];

  const rows = results.map(r => {
    const linesSample = r.matchedLines.map(l => `L${l.lineNum}: ${l.snippet.replace(/"/g, '""')}`).join(' | ');
    return [
      `"${r.ioc.value.replace(/"/g, '""')}"`,
      `"${defang(r.ioc.value).replace(/"/g, '""')}"`,
      `"${r.ioc.type.toUpperCase()}"`,
      `"${r.ioc.severity}"`,
      `"${r.ioc.feed.replace(/"/g, '""')}"`,
      `"${(r.ioc.malwareFamily || 'N/A').replace(/"/g, '""')}"`,
      `"${r.ioc.confidence}%"`,
      r.count,
      `"${linesSample}"`,
      `"${(r.ioc.description || '').replace(/"/g, '""')}"`,
      `"${(r.ioc.mitreTechnique || r.ioc.mitreTactic || 'N/A').replace(/"/g, '""')}"`,
      `"${(r.ioc.referenceUrl || '').replace(/"/g, '""')}"`,
    ].join(',');
  });

  const csvContent = [headers.join(','), ...rows].join('\r\n');
  const blob = new Blob(['\uFEFF' + csvContent], { type: 'text/csv;charset=utf-8;' });
  triggerDownload(blob, filename);
}

export function exportToPDF(
  results: MatchResult[],
  metrics: ScanMetrics,
  logName: string = 'incident_logs.txt',
  analystName: string = 'SOC Level 2 Analyst'
): void {
  const doc = new jsPDF({
    orientation: 'portrait',
    unit: 'mm',
    format: 'a4',
  });

  const pageWidth = doc.internal.pageSize.getWidth();
  let currentY = 18;

  // Header Banner
  doc.setFillColor(15, 23, 42); // slate-900
  doc.rect(0, 0, pageWidth, 28, 'F');

  doc.setTextColor(255, 255, 255);
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(16);
  doc.text('IOC HUNTER - REPORTE DE INCIDENTE Y AMENAZAS', 14, 12);

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(9);
  doc.setTextColor(148, 163, 184); // slate-400
  doc.text(`Generado: ${new Date().toISOString()} | Analista: ${analystName}`, 14, 19);
  doc.text(`Archivo analizado: ${logName}`, 14, 24);

  currentY = 36;

  // Executive Summary Box
  doc.setFillColor(248, 250, 252); // slate-50
  doc.setDrawColor(226, 232, 240); // slate-200
  doc.roundedRect(14, currentY, pageWidth - 28, 30, 2, 2, 'FD');

  doc.setFont('helvetica', 'bold');
  doc.setFontSize(11);
  doc.setTextColor(15, 23, 42);
  doc.text('Resumen Ejecutivo de Triaje SOC', 18, currentY + 7);

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(9);
  doc.setTextColor(51, 65, 85);
  doc.text(`- Líneas de logs procesadas: ${metrics.totalLinesProcessed.toLocaleString()}`, 18, currentY + 14);
  doc.text(`- Artefactos extraídos (IPs, dominios, hashes): ${metrics.extractedArtifactsCount}`, 18, currentY + 20);
  doc.text(`- Coincidencias Maliciosas Confirmadas: ${metrics.maliciousHitsCount}`, 18, currentY + 26);

  // Threat severity badges right side
  doc.text(`• Crítico: ${metrics.criticalCount}`, 120, currentY + 14);
  doc.text(`• Alto: ${metrics.highCount}`, 120, currentY + 20);
  doc.text(`• Medio / Bajo: ${metrics.mediumCount + metrics.lowCount}`, 120, currentY + 26);

  currentY += 38;

  // Section: IOCs Detectados
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(12);
  doc.setTextColor(15, 23, 42);
  doc.text('Indicadores de Compromiso (IOCs) Detectados', 14, currentY);

  currentY += 6;

  // Table header
  doc.setFillColor(226, 232, 240); // slate-200
  doc.rect(14, currentY, pageWidth - 28, 7, 'F');

  doc.setFont('helvetica', 'bold');
  doc.setFontSize(8);
  doc.setTextColor(51, 65, 85);
  doc.text('IOC (Defanged)', 16, currentY + 5);
  doc.text('TIPO', 72, currentY + 5);
  doc.text('SEVERIDAD', 90, currentY + 5);
  doc.text('FUENTE FEED', 115, currentY + 5);
  doc.text('FAMILIA / CLASIFICACIÓN', 145, currentY + 5);

  currentY += 8;

  // Table rows
  doc.setFont('helvetica', 'normal');
  doc.setFontSize(8);

  const topResults = results.slice(0, 18); // top items for page
  for (let idx = 0; idx < topResults.length; idx++) {
    const item = topResults[idx];
    const defangedVal = defang(item.ioc.value);
    const shortVal = defangedVal.length > 30 ? defangedVal.substring(0, 28) + '...' : defangedVal;

    // Check page height
    if (currentY > 265) {
      doc.addPage();
      currentY = 20;
    }

    if (idx % 2 === 1) {
      doc.setFillColor(248, 250, 252);
      doc.rect(14, currentY - 3, pageWidth - 28, 7, 'F');
    }

    doc.setTextColor(15, 23, 42);
    doc.text(shortVal, 16, currentY + 2);
    doc.text(item.ioc.type.toUpperCase(), 72, currentY + 2);

    // Color code severity
    if (item.ioc.severity === 'CRITICAL') {
      doc.setTextColor(185, 28, 28); // red-700
    } else if (item.ioc.severity === 'HIGH') {
      doc.setTextColor(194, 65, 12); // amber-700
    } else {
      doc.setTextColor(51, 65, 85);
    }
    doc.text(item.ioc.severity, 90, currentY + 2);

    doc.setTextColor(71, 85, 105);
    doc.text(item.ioc.feed, 115, currentY + 2);

    const family = (item.ioc.malwareFamily || 'Desconocido');
    const shortFamily = family.length > 25 ? family.substring(0, 23) + '...' : family;
    doc.text(shortFamily, 145, currentY + 2);

    currentY += 7;
  }

  currentY += 6;
  if (currentY > 250) {
    doc.addPage();
    currentY = 20;
  }

  // Mitigation Section
  doc.setFillColor(254, 242, 242); // red-50
  doc.setDrawColor(254, 202, 202); // red-200
  doc.roundedRect(14, currentY, pageWidth - 28, 26, 2, 2, 'FD');

  doc.setFont('helvetica', 'bold');
  doc.setFontSize(10);
  doc.setTextColor(153, 27, 27); // red-800
  doc.text('Acciones de Contención Inmediata Recomendadas', 18, currentY + 6);

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(8.5);
  doc.setTextColor(127, 29, 29);
  doc.text('1. Aislar endpoints que se comunicaron con los servidores C2 (Feodo / Cobalt Strike).', 18, currentY + 12);
  doc.text('2. Desplegar reglas perimetrales en Firewall/Proxy bloqueando IPs y dominios de severidad Crítica.', 18, currentY + 17);
  doc.text('3. Ejecutar escaneo EDR en busca de persistencia y revocar credenciales de usuarios comprometidos.', 18, currentY + 22);

  // Footer
  const pageCount = doc.getNumberOfPages();
  for (let i = 1; i <= pageCount; i++) {
    doc.setPage(i);
    doc.setFontSize(7.5);
    doc.setTextColor(148, 163, 184);
    doc.text(`IOC Hunter Threat Intelligence | Documento Confidencial SOC | Página ${i} de ${pageCount}`, 14, 290);
  }

  doc.save(`IOC_Hunter_Report_${new Date().toISOString().slice(0, 10)}.pdf`);
}

export function exportSuricataRules(results: MatchResult[]): void {
  const rules: string[] = [];
  let sid = 1000001;

  for (const item of results) {
    if (item.ioc.type === 'ip') {
      rules.push(
        `# ${item.ioc.malwareFamily || item.ioc.description}\n` +
        `alert ip $HOME_NET any -> ${item.ioc.value} any (msg:"IOC HUNTER - C2 Malicioso Detectado [${item.ioc.feed}]"; classtype:trojan-activity; sid:${sid++}; rev:1;)`
      );
    } else if (item.ioc.type === 'domain') {
      rules.push(
        `# ${item.ioc.malwareFamily || item.ioc.description}\n` +
        `alert dns $HOME_NET any -> any any (msg:"IOC HUNTER - Consulta DNS Maliciosa [${item.ioc.value}]"; dns.query; content:"${item.ioc.value}"; nocase; sid:${sid++}; rev:1;)`
      );
    }
  }

  const content = `# =========================================================\n` +
    `# Reglas Suricata / Snort generadas por IOC Hunter\n` +
    `# Fecha: ${new Date().toISOString()}\n` +
    `# Total de reglas: ${rules.length}\n` +
    `# =========================================================\n\n` +
    rules.join('\n\n');

  const blob = new Blob([content], { type: 'text/plain;charset=utf-8;' });
  triggerDownload(blob, 'suricata_ioc_rules.rules');
}

export function exportIptables(results: MatchResult[]): void {
  const ipMatches = results.filter(r => r.ioc.type === 'ip');
  const commands = [
    `#!/bin/bash`,
    `# Script de bloqueo perimetral generado automáticamente por IOC Hunter`,
    `# Fecha: ${new Date().toISOString()}`,
    `# Advertencia: Verificar IPs internas antes de ejecutar`,
    ``,
    `echo "[+] Aplicando reglas de bloqueo iptables..."`,
    ``,
    ...ipMatches.map(r => `iptables -A INPUT -s ${r.ioc.value} -j DROP -m comment --comment "IOC_Hunter_${r.ioc.feed}_${r.ioc.severity}"`),
    ...ipMatches.map(r => `iptables -A OUTPUT -d ${r.ioc.value} -j DROP -m comment --comment "IOC_Hunter_${r.ioc.feed}_${r.ioc.severity}"`),
    ``,
    `echo "[+] Bloqueo completado. Total de IPs bloqueadas: ${ipMatches.length}"`,
  ];

  const blob = new Blob([commands.join('\n')], { type: 'text/x-sh;charset=utf-8;' });
  triggerDownload(blob, 'blocklist_iptables.sh');
}

export function exportSTIX(results: MatchResult[]): void {
  const bundle = {
    type: 'bundle',
    id: `bundle--${crypto.randomUUID()}`,
    spec_version: '2.1',
    objects: results.map(r => ({
      type: 'indicator',
      spec_version: '2.1',
      id: `indicator--${crypto.randomUUID()}`,
      created: new Date().toISOString(),
      modified: new Date().toISOString(),
      name: `IOC Hunter Detection: ${defang(r.ioc.value)}`,
      description: r.ioc.description,
      indicator_types: ['malicious-activity'],
      pattern: r.ioc.type === 'ip' 
        ? `[ipv4-addr:value = '${r.ioc.value}']`
        : r.ioc.type === 'domain'
        ? `[domain-name:value = '${r.ioc.value}']`
        : r.ioc.type === 'sha256'
        ? `[file:hashes.'SHA-256' = '${r.ioc.value}']`
        : `[url:value = '${r.ioc.value}']`,
      pattern_type: 'stix',
      confidence: r.ioc.confidence,
      labels: [r.ioc.severity.toLowerCase(), r.ioc.feed.toLowerCase().replace(/\s+/g, '-')],
    })),
  };

  const blob = new Blob([JSON.stringify(bundle, null, 2)], { type: 'application/json;charset=utf-8;' });
  triggerDownload(blob, 'ioc_hunter_stix21.json');
}

function triggerDownload(blob: Blob, filename: string): void {
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
}
