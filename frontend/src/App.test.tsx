import type { Finding, ScanReport } from '../types';

export const severityLabels: Record<string, string> = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
  info: 'Info',
  unknown: 'Unknown',
};

export const getSeverityScore = (severity: string): number => {
  const map: Record<string, number> = {
    critical: 5,
    high: 4,
    medium: 3,
    low: 2,
    info: 1,
    unknown: 0,
  };
  return map[severity] ?? 0;
};

export const sortFindings = (findings: Finding[], direction: 'asc' | 'desc' = 'desc') => {
  return [...findings].sort((a, b) => {
    const delta = getSeverityScore(b.severity) - getSeverityScore(a.severity);
    return direction === 'desc' ? delta : -delta;
  });
};

export const filterFindings = (findings: Finding[], severityFilter: string, categoryFilter: string) => {
  return findings.filter((finding) => {
    const matchesSeverity = severityFilter === 'all' || finding.severity === severityFilter;
    const matchesCategory = categoryFilter === 'all' || finding.category === categoryFilter;
    return matchesSeverity && matchesCategory;
  });
};

export const buildMarkdownReport = (report: ScanReport): string => {
  const lines = [
    `# OpenTrace report`,
    '',
    `- Target: ${report.target}`,
    `- Hostname: ${report.hostname}`,
    `- Scan timestamp: ${report.scan_timestamp}`,
    `- Data source: ${report.data_source}`,
    '',
    '## Summary',
    '',
    `- Passed: ${report.summary.passed}`,
    `- Failed: ${report.summary.failed}`,
    `- Informational: ${report.summary.informational}`,
    `- Unavailable: ${report.summary.unavailable}`,
    `- Unknown: ${report.summary.unknown}`,
    '',
    '## Findings',
    '',
  ];

  report.findings.forEach((finding, index) => {
    lines.push(`### ${index + 1}. ${finding.title}`);
    lines.push(`- Severity: ${finding.severity}`);
    lines.push(`- Category: ${finding.category}`);
    lines.push(`- Status: ${finding.status}`);
    lines.push(`- Confidence: ${finding.confidence}`);
    lines.push(`- Observation: ${finding.observed_value ?? 'Not available'}`);
    lines.push(`- Why it matters: ${finding.explanation}`);
    lines.push(`- Remediation: ${finding.remediation}`);
    lines.push(`- Documentation: ${finding.documentation}`);
    lines.push('');
  });

  lines.push('## Scope and limitations');
  lines.push(report.scope);
  lines.push('');
  lines.push(report.limitations);

  return lines.join('\n');
};

export const buildJsonReport = (report: ScanReport): string => JSON.stringify(report, null, 2);

export const compareReports = (current: ScanReport, previous: ScanReport | null) => {
  if (!previous) return [];

  const changes: Array<{ id: string; previous: string | null; current: string | null; title: string }> = [];
  const previousMap = new Map(previous.findings.map((f) => [f.id, f]));
  const currentMap = new Map(current.findings.map((f) => [f.id, f]));

  for (const [id, finding] of currentMap.entries()) {
    const previousFinding = previousMap.get(id);
    if (!previousFinding || previousFinding.status !== finding.status || previousFinding.severity !== finding.severity) {
      changes.push({
        id,
        previous: previousFinding ? previousFinding.status : null,
        current: finding.status,
        title: finding.title,
      });
    }
  }

  return changes;
};
