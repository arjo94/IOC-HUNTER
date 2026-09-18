export type IOCType = 'ip' | 'domain' | 'url' | 'md5' | 'sha1' | 'sha256';

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export type FeedSource = 
  | 'URLhaus' 
  | 'AbuseIPDB' 
  | 'AlienVault OTX' 
  | 'ThreatFox' 
  | 'Feodo Tracker' 
  | 'Custom Feed';

export interface IOCRecord {
  id: string;
  value: string;
  type: IOCType;
  severity: Severity;
  feed: FeedSource;
  malwareFamily?: string;
  threatActor?: string;
  confidence: number; // 0 to 100
  firstSeen: string;
  description: string;
  referenceUrl?: string;
  mitreTactic?: string;
  mitreTechnique?: string;
}

export interface MatchedLine {
  lineNum: number;
  rawText: string;
  snippet: string;
  timestamp?: string;
}

export interface MatchResult {
  id: string;
  ioc: IOCRecord;
  count: number;
  matchedLines: MatchedLine[];
  triageStatus: 'unreviewed' | 'confirmed' | 'false_positive';
  analystNotes?: string;
}

export interface FeedInfo {
  id: string;
  name: FeedSource;
  type: IOCType[];
  url: string;
  count: number;
  lastUpdated: string;
  enabled: boolean;
  description: string;
  requiresApiKey: boolean;
  freeTierDocs: string;
  status: 'active' | 'updating' | 'error' | 'idle';
}

export interface LogSample {
  id: string;
  name: string;
  format: 'csv' | 'json' | 'syslog' | 'plain';
  description: string;
  content: string;
}

export interface ScanMetrics {
  totalLinesProcessed: number;
  extractedArtifactsCount: number;
  maliciousHitsCount: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  scanDurationMs: number;
}
