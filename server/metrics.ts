// Prometheus text exposition, written by hand: a few lines, no client library needed.
const requests = new Map<string, number>();

export function countRequest(method: string, route: string, status: number) {
  const key = `method="${method}",route="${route}",status="${status}"`;
  requests.set(key, (requests.get(key) ?? 0) + 1);
}

export interface Gauges {
  feeds: number;
  /** Active indicators, in total and by type. */
  active: number;
  byType: Record<string, number>;
  allowListed: number;
  /** Values looked up since the process started, and how many of them matched an indicator. */
  lookups: number;
  hits: number;
}

export function renderMetrics(version: string, g: Gauges): string {
  const lines = [
    "# HELP openasy_build_info Build information.",
    "# TYPE openasy_build_info gauge",
    `openasy_build_info{product="threat-intel",version="${version}"} 1`,
    "# HELP openasy_http_requests_total HTTP requests handled.",
    "# TYPE openasy_http_requests_total counter",
    ...[...requests].map(([labels, n]) => `openasy_http_requests_total{${labels}} ${n}`),
    "# HELP openasy_threat_intel_feeds Feeds that indicators come from.",
    "# TYPE openasy_threat_intel_feeds gauge",
    `openasy_threat_intel_feeds ${g.feeds}`,
    "# HELP openasy_threat_intel_indicators Active indicators by type.",
    "# TYPE openasy_threat_intel_indicators gauge",
    ...Object.entries(g.byType).map(([t, n]) => `openasy_threat_intel_indicators{type="${t}"} ${n}`),
    "# HELP openasy_threat_intel_allow_list Active allow-list entries.",
    "# TYPE openasy_threat_intel_allow_list gauge",
    `openasy_threat_intel_allow_list ${g.allowListed}`,
    "# HELP openasy_threat_intel_lookups_total Values looked up since the process started.",
    "# TYPE openasy_threat_intel_lookups_total counter",
    `openasy_threat_intel_lookups_total ${g.lookups}`,
    "# HELP openasy_threat_intel_lookup_hits_total Looked-up values that matched an active indicator.",
    "# TYPE openasy_threat_intel_lookup_hits_total counter",
    `openasy_threat_intel_lookup_hits_total ${g.hits}`,
    "# HELP process_uptime_seconds Seconds since the process started.",
    "# TYPE process_uptime_seconds gauge",
    `process_uptime_seconds ${process.uptime().toFixed(0)}`,
  ];
  return lines.join("\n") + "\n";
}
