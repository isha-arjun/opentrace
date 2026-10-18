import type { ScanReport } from '../types';

export const sampleReport: ScanReport = {
  target: 'https://example.com/',
  hostname: 'example.com',
  scan_timestamp: '2026-10-18T10:00:00Z',
  data_source: 'Synthetic example data only — not a real scan',
  summary: {
    total: 5,
    passed: 3,
    failed: 1,
    informational: 1,
    unavailable: 0,
    unknown: 0,
  },
  scope: 'Synthetic example report for demonstration only. It does not represent a live site analysis.',
  limitations: 'Example data is labeled and intentionally not representative of any real target. Missing data is not proof of insecurity.',
  findings: [
    {
      id: 'example-csp',
      title: 'Content-Security-Policy',
      category: 'Headers',
      severity: 'medium',
      status: 'fail',
      confidence: 'confirmed',
      explanation: 'The synthetic example shows a missing CSP header, leaving the browser without a restrictive policy.',
      remediation: 'Define a policy that covers scripts, styles, and third-party content while allowing only required sources.',
      documentation: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP',
      observed_value: 'Header absent',
      evidence: [
        {
          source: 'Synthetic example',
          check_id: 'content-security-policy',
          observed_value: 'Header absent',
          observed_at: '2026-10-18T10:00:00Z',
        },
      ],
    },
    {
      id: 'example-hsts',
      title: 'Strict-Transport-Security',
      category: 'Headers',
      severity: 'low',
      status: 'pass',
      confidence: 'confirmed',
      explanation: 'The synthetic example includes HSTS with a reasonable max-age, which is a positive signal for HTTPS enforcement.',
      remediation: 'Keep this configuration aligned with the site’s certificate and deployment process.',
      documentation: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security',
      observed_value: 'max-age=31536000; includeSubDomains',
      evidence: [
        {
          source: 'Synthetic example',
          check_id: 'strict-transport-security',
          observed_value: 'max-age=31536000; includeSubDomains',
          observed_at: '2026-10-18T10:00:00Z',
        },
      ],
    },
    {
      id: 'example-referrer',
      title: 'Referrer-Policy',
      category: 'Headers',
      severity: 'low',
      status: 'pass',
      confidence: 'confirmed',
      explanation: 'The synthetic example uses a strict referrer policy to limit leakage of URL information.',
      remediation: 'Keep the policy aligned with your site’s navigation and analytics needs.',
      documentation: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy',
      observed_value: 'strict-origin-when-cross-origin',
      evidence: [
        {
          source: 'Synthetic example',
          check_id: 'referrer-policy',
          observed_value: 'strict-origin-when-cross-origin',
          observed_at: '2026-10-18T10:00:00Z',
        },
      ],
    },
    {
      id: 'example-nosniff',
      title: 'X-Content-Type-Options',
      category: 'Headers',
      severity: 'low',
      status: 'pass',
      confidence: 'confirmed',
      explanation: 'The synthetic example includes nosniff to reduce MIME confusion.',
      remediation: 'Keep this header in place for resource serving paths with browser-controlled MIME interpretation.',
      documentation: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options',
      observed_value: 'nosniff',
      evidence: [
        {
          source: 'Synthetic example',
          check_id: 'x-content-type-options',
          observed_value: 'nosniff',
          observed_at: '2026-10-18T10:00:00Z',
        },
      ],
    },
    {
      id: 'example-framing',
      title: 'Framing protection',
      category: 'Headers',
      severity: 'info',
      status: 'info',
      confidence: 'informational',
      explanation: 'The synthetic example does not explicitly report a framing policy, so this is informational rather than a direct security failure.',
      remediation: 'Review whether the site should block embedding or allow selected trusted origins.',
      documentation: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options',
      observed_value: 'No explicit evidence',
      evidence: [
        {
          source: 'Synthetic example',
          check_id: 'x-frame-options',
          observed_value: 'No explicit evidence',
          observed_at: '2026-10-18T10:00:00Z',
        },
      ],
    },
  ],
};

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

export const sortFindings = (findings: ScanReport['findings'], direction: 'asc' | 'desc' = 'desc') => {
  return [...findings].sort((a, b) => {
    const delta = getSeverityScore(b.severity) - getSeverityScore(a.severity);
    return direction === 'desc' ? delta : -delta;
  });
};

export const filterFindings = (findings: ScanReport['findings'], severityFilter: string, categoryFilter: string) => {
  return findings.filter((finding) => {
    const matchesSeverity = severityFilter === 'all' || finding.severity === severityFilter;
    const matchesCategory = categoryFilter === 'all' || finding.category === categoryFilter;
    return matchesSeverity && matchesCategory;
  });
};

export const buildMarkdownReport = (report: ScanReport): string => {
  const lines = [
    '# OpenTrace report',
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
