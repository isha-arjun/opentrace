export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info' | 'unknown';

export type Finding = {
  id: string;
  title: string;
  category: string;
  severity: Severity;
  status: string;
  confidence: string;
  explanation: string;
  remediation: string;
  documentation: string;
  observed_value: string | null;
  evidence: {
    source: string;
    check_id: string;
    observed_value: string | null;
    observed_at: string | null;
  }[];
};

export type ScanSummary = {
  total: number;
  passed: number;
  failed: number;
  informational: number;
  unavailable: number;
  unknown: number;
};

export type ScanReport = {
  target: string;
  hostname: string;
  scan_timestamp: string;
  data_source: string;
  summary: ScanSummary;
  findings: Finding[];
  scope: string;
  limitations: string;
};

export type ApiError = {
  message: string;
};
