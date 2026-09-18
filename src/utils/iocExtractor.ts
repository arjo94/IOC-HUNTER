import { IOCRecord, MatchResult, MatchedLine, ScanMetrics } from '../types';

export function refang(input: string): string {
  if (!input) return '';
  return input
    .replace(/hxxp/gi, 'http')
    .replace(/\[\.\]/g, '.')
    .replace(/\(\.\)/g, '.')
    .replace(/\[:\]/g, ':')
    .replace(/\(:\)/g, ':');
}

export function defang(input: string): string {
  if (!input) return '';
  return input
    .replace(/http/gi, 'hxxp')
    .replace(/\./g, '[.]')
    .replace(/:/g, '[:]');
}

export function isPrivateIP(ip: string): boolean {
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4 || parts.some(isNaN) || parts.some(p => p < 0 || p > 255)) {
    return false;
  }
  // 10.0.0.0 - 10.255.255.255
  if (parts[0] === 10) return true;
  // 172.16.0.0 - 172.31.255.255
  if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
  // 192.168.0.0 - 192.168.255.255
  if (parts[0] === 192 && parts[1] === 168) return true;
  // Loopback 127.0.0.1
  if (parts[0] === 127) return true;
  // 0.0.0.0
  if (parts[0] === 0) return true;
  // APIPA 169.254.0.0/16
  if (parts[0] === 169 && parts[1] === 254) return true;
  return false;
}

export interface ExtractedArtifacts {
  ips: string[];
  domains: string[];
  urls: string[];
  sha256: string[];
  sha1: string[];
  md5: string[];
}

export function extractAllArtifacts(text: string, excludePrivateIps: boolean = true): ExtractedArtifacts {
  const normalized = refang(text);

  // Regex definitions
  const ipv4Regex = /\b(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g;
  const urlRegex = /https?:\/\/[a-zA-Z0-9\-\._~:\/\?#\[\]@!$&'\(\)\*\+,;=%]+/g;
  const domainRegex = /\b(?!(?:https?:\/\/))([a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,24}\b/g;
  const sha256Regex = /\b[a-fA-F0-9]{64}\b/g;
  const sha1Regex = /\b[a-fA-F0-9]{40}\b/g;
  const md5Regex = /\b[a-fA-F0-9]{32}\b/g;

  // Extract raw
  const rawIps = Array.from(new Set(normalized.match(ipv4Regex) || []));
  const filteredIps = excludePrivateIps ? rawIps.filter(ip => !isPrivateIP(ip)) : rawIps;

  const rawUrls = Array.from(new Set(normalized.match(urlRegex) || []));

  const rawDomains = Array.from(new Set(normalized.match(domainRegex) || []));
  // Filter out false positives from domains (e.g. filenames, typical file extensions or purely numbers)
  const ignoredExtensions = new Set(['png', 'jpg', 'jpeg', 'gif', 'svg', 'css', 'js', 'json', 'csv', 'txt', 'html', 'php', 'exe', 'dll', 'tar', 'gz', 'zip']);
  const filteredDomains = rawDomains.filter(d => {
    const parts = d.toLowerCase().split('.');
    const ext = parts[parts.length - 1];
    if (ignoredExtensions.has(ext)) return false;
    // Don't match IPs as domains
    if (/^\d+\.\d+\.\d+\.\d+$/.test(d)) return false;
    return true;
  });

  const sha256 = Array.from(new Set(normalized.match(sha256Regex) || [])).map(s => s.toLowerCase());
  const sha1 = Array.from(new Set(normalized.match(sha1Regex) || [])).map(s => s.toLowerCase());
  const md5 = Array.from(new Set(normalized.match(md5Regex) || [])).map(s => s.toLowerCase());

  return {
    ips: filteredIps,
    domains: filteredDomains,
    urls: rawUrls,
    sha256,
    sha1,
    md5,
  };
}

export function scanLogsAgainstFeeds(
  logContent: string,
  iocDatabase: IOCRecord[],
  options: {
    excludePrivateIps?: boolean;
    caseSensitiveHashes?: boolean;
  } = {}
): { results: MatchResult[]; metrics: ScanMetrics; unclassifiedArtifacts: ExtractedArtifacts } {
  const startTime = performance.now();
  const excludePrivate = options.excludePrivateIps ?? true;

  const lines = logContent.split(/\r?\n/);
  const totalLines = lines.length;

  // Extract all artifacts in the document
  const unclassifiedArtifacts = extractAllArtifacts(logContent, excludePrivate);

  // Build lookup index of active IOCs
  const iocMap = new Map<string, IOCRecord>();
  for (const item of iocDatabase) {
    iocMap.set(item.value.toLowerCase().trim(), item);
  }

  // Record matched lines and frequency for each IOC
  const matchesMap = new Map<string, { ioc: IOCRecord; count: number; matchedLines: MatchedLine[] }>();

  // Helper to register a hit
  const registerHit = (ioc: IOCRecord, lineNum: number, rawLine: string) => {
    const key = ioc.id;
    if (!matchesMap.has(key)) {
      matchesMap.set(key, {
        ioc,
        count: 0,
        matchedLines: [],
      });
    }

    const current = matchesMap.get(key)!;
    current.count += 1;

    // Store up to 15 snippet examples per IOC to keep memory clean
    if (current.matchedLines.length < 15) {
      const trimmed = rawLine.trim();
      current.matchedLines.push({
        lineNum: lineNum + 1,
        rawText: trimmed,
        snippet: trimmed.length > 200 ? trimmed.substring(0, 200) + '...' : trimmed,
      });
    }
  };

  // Process line by line
  for (let i = 0; i < lines.length; i++) {
    const rawLine = lines[i];
    if (!rawLine.trim()) continue;

    const normalizedLine = refang(rawLine).toLowerCase();

    for (const ioc of iocDatabase) {
      const needle = ioc.value.toLowerCase().trim();
      if (!needle) continue;

      // Skip private IP matches if configured
      if (ioc.type === 'ip' && excludePrivate && isPrivateIP(ioc.value)) {
        continue;
      }

      // Check if line contains this needle
      if (normalizedLine.includes(needle)) {
        // Confirm boundary for IPs and hashes to avoid partial matches
        let isMatch = true;
        if (ioc.type === 'ip') {
          const escapedNeedle = needle.replace(/\./g, '\\.');
          const boundaryRegex = new RegExp(`(^|[^0-9.])${escapedNeedle}([^0-9.]|$)`);
          isMatch = boundaryRegex.test(normalizedLine);
        } else if (ioc.type === 'sha256' || ioc.type === 'sha1' || ioc.type === 'md5') {
          const boundaryRegex = new RegExp(`(^|[^a-f0-9])${needle}([^a-f0-9]|$)`, 'i');
          isMatch = boundaryRegex.test(normalizedLine);
        }

        if (isMatch) {
          registerHit(ioc, i, rawLine);
        }
      }
    }
  }

  const results: MatchResult[] = Array.from(matchesMap.values()).map(m => ({
    id: `match-${m.ioc.id}`,
    ioc: m.ioc,
    count: m.count,
    matchedLines: m.matchedLines,
    triageStatus: 'unreviewed',
  }));

  // Sort by Severity (CRITICAL -> HIGH -> MEDIUM -> LOW -> INFO) and count
  const severityWeight: Record<string, number> = {
    CRITICAL: 5,
    HIGH: 4,
    MEDIUM: 3,
    LOW: 2,
    INFO: 1,
  };

  results.sort((a, b) => {
    const diff = (severityWeight[b.ioc.severity] || 0) - (severityWeight[a.ioc.severity] || 0);
    if (diff !== 0) return diff;
    return b.count - a.count;
  });

  const criticalCount = results.filter(r => r.ioc.severity === 'CRITICAL').length;
  const highCount = results.filter(r => r.ioc.severity === 'HIGH').length;
  const mediumCount = results.filter(r => r.ioc.severity === 'MEDIUM').length;
  const lowCount = results.filter(r => r.ioc.severity === 'LOW').length;

  const totalArtifactsCount = 
    unclassifiedArtifacts.ips.length +
    unclassifiedArtifacts.domains.length +
    unclassifiedArtifacts.urls.length +
    unclassifiedArtifacts.sha256.length +
    unclassifiedArtifacts.sha1.length +
    unclassifiedArtifacts.md5.length;

  const endTime = performance.now();

  const metrics: ScanMetrics = {
    totalLinesProcessed: totalLines,
    extractedArtifactsCount: totalArtifactsCount,
    maliciousHitsCount: results.length,
    criticalCount,
    highCount,
    mediumCount,
    lowCount,
    scanDurationMs: Math.round(endTime - startTime),
  };

  return { results, metrics, unclassifiedArtifacts };
}
