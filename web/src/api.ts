// The UI is an ordinary client of the public API (ADR 0014, 0018). Types follow openapi.json.

export const INDICATOR_TYPES = ["ipv4", "ipv6", "cidr", "domain", "url", "email", "sha256", "sha1", "md5"] as const;
export type IndicatorType = (typeof INDICATOR_TYPES)[number];
export type Tlp = "clear" | "green" | "amber" | "red";
export type Severity = "critical" | "high" | "medium" | "low";
export type FeedKind = "stix" | "csv" | "text" | "manual";
export type Verdict = "malicious" | "suspicious" | "unknown" | "allowed";

/** Another OpenAsy product of this install, from OPENASY_PRODUCTS. */
export interface ProductLink {
  id: string;
  url: string;
}

export interface FeedRef {
  id: string;
  name: string;
}

export interface Feed {
  id: string;
  name: string;
  kind: FeedKind;
  defaultTtlDays: number;
  defaultConfidence: number;
  defaultTlp: Tlp;
  defaultSeverity: Severity;
  lastImportAt: string | null;
  indicators: { total: number; active: number };
  /** Where the feed is pulled from on a schedule, or null when it is only sent. */
  pull: FeedPull | null;
  createdAt: string;
}

export interface PullResult {
  received: number;
  created: number;
  updated: number;
  revoked: number;
  leftOut: number;
  more: boolean;
}

export interface FeedPull {
  source: "taxii" | "url";
  url: string;
  auth: "none" | "basic" | "bearer";
  username: string | null;
  everyMinutes: number;
  lastAttemptAt: string | null;
  lastSuccessAt: string | null;
  lastError: string | null;
  lastResult: PullResult | null;
  nextAt: string;
}

export interface Indicator {
  id: string;
  type: IndicatorType;
  value: string;
  feed: FeedRef;
  confidence: number;
  tlp: Tlp;
  severity: Severity;
  labels: string[];
  description: string | null;
  includeSubdomains: boolean;
  validFrom: string;
  validUntil: string;
  revoked: boolean;
  active: boolean;
  createdAt: string;
  updatedAt: string;
}

export interface LookupResult {
  type: IndicatorType;
  value: string;
  verdict: Verdict;
  confidence: number | null;
  severity: Severity | null;
  tlp: Tlp | null;
  feeds: string[];
  matches: Array<{
    id: string;
    type: IndicatorType;
    value: string;
    feed: FeedRef;
    confidence: number;
    severity: Severity;
    tlp: Tlp;
    labels: string[];
    description: string | null;
    validUntil: string;
    via: "exact" | "cidr" | "subdomain";
  }>;
  allowed: { reason: string; expiresAt: string } | null;
}

export interface AllowEntry {
  id: string;
  type: IndicatorType;
  value: string;
  includeSubdomains: boolean;
  reason: string;
  by: string | null;
  createdAt: string;
  expiresAt: string;
  active: boolean;
}

export interface Summary {
  feeds: number;
  indicators: { active: number; inactive: number };
  byType: Record<IndicatorType, number>;
  allowListed: number;
  lookups: { total: number; hits: number };
}

export class Unauthorized extends Error {}
/** The signed-in owner or admin has no second factor yet; the sign-in gate asks for one. */
export class MfaSetupRequired extends Error {}
export class ApiError extends Error {}

// The session is an HttpOnly cookie set by sign-in (@openasy/auth); the browser sends it, nothing is stored here.
export async function api<T>(path: string, init: RequestInit = {}): Promise<T> {
  const res = await fetch(path, {
    ...init,
    credentials: "same-origin",
    headers: { ...(init.body ? { "content-type": "application/json" } : {}), ...init.headers },
  });
  if (!res.ok) {
    const problem = (await res.json().catch(() => ({}))) as { code?: string; detail?: string };
    if (res.status === 401) throw new Unauthorized(problem.detail);
    if (problem.code === "mfa-setup-required") throw new MfaSetupRequired(problem.detail);
    throw new ApiError(problem.detail ?? `${path}: ${res.status}`);
  }
  return (res.status === 204 ? undefined : await res.json()) as T;
}
