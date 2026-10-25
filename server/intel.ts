import { randomUUID } from "node:crypto";
import type { DatabaseSync, SQLInputValue } from "node:sqlite";
import type { Role } from "@openasy/auth";
import { detectType, networksContaining, NormalizeError, normalizeIndicator, TYPES, type IndicatorType } from "./normalize.ts";
import { presentPull } from "./pull.ts";
import { parseStixPattern, StixPatternError } from "./stix.ts";

export type ProblemCode =
  | "invalid-token"
  | "invalid-json"
  | "invalid-body"
  | "invalid-import"
  | "not-found"
  | "conflict"
  | "not-configured"
  | "payload-too-large"
  | "pull-failed"
  | "internal-error";

export class IntelError extends Error {
  readonly status: number;
  readonly code: ProblemCode;
  constructor(status: number, code: ProblemCode, detail: string) {
    super(detail);
    this.status = status;
    this.code = code;
  }
}

export const TLPS = ["clear", "green", "amber", "red"] as const;
export type Tlp = (typeof TLPS)[number];
export const SEVERITIES = ["critical", "high", "medium", "low"] as const;
export type Severity = (typeof SEVERITIES)[number];
export const KINDS = ["stix", "csv", "text", "manual"] as const;
export type Kind = (typeof KINDS)[number];
export type Verdict = "malicious" | "suspicious" | "unknown" | "allowed";

const SEVERITY_RANK: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1 };
const TLP_RANK: Record<Tlp, number> = { clear: 0, green: 1, amber: 2, red: 3 };
/** A match at or above this confidence makes a value malicious; below it, suspicious. */
export const MALICIOUS_CONFIDENCE = 60;
/** TLP:RED is for named recipients: only editors and above, and callers with the ingest token, see it. */
const SEES_RED = (role: Caller["role"]) => role === "editor" || role === "admin" || role === "owner";

/** STIX 2.1 marking definitions for TLP, by id. */
const TLP_MARKINGS: Record<string, Tlp> = {
  "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9": "clear",
  "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da": "green",
  "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82": "amber",
  "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d40e": "red",
};

const FEED_NAME = /^[A-Za-z0-9][A-Za-z0-9._ -]{0,63}$/;
const MAX_ALLOW_DAYS = 366;
/** The most indicators one import may hold. */
export const MAX_IMPORT = 200_000;
/** Problems named in the answer to an import; the rest are counted. */
const MAX_PROBLEMS = 100;
export const MAX_LOOKUP = 1000;

const now = () => new Date().toISOString();
const bad = (detail: string) => new IntelError(422, "invalid-body", detail);
const notFound = (what: string) => new IntelError(404, "not-found", `${what} does not exist.`);

export interface Caller {
  role: Role;
}

export interface Page<T> {
  items: T[];
  /** Opaque; pass it back as `cursor` for the next page. Absent on the last page (ADR 0024). */
  nextCursor?: string;
}

const encodeCursor = (offset: number) => Buffer.from(JSON.stringify({ o: offset })).toString("base64url");
function decodeCursor(cursor: string | undefined): number {
  if (!cursor) return 0;
  try {
    const o = (JSON.parse(Buffer.from(cursor, "base64url").toString("utf8")) as { o?: unknown }).o;
    if (typeof o === "number" && Number.isSafeInteger(o) && o >= 0) return o;
  } catch {
    // fall through
  }
  throw bad("cursor is not one this API returned.");
}

export function parseLimit(value: string | null, max = 500, fallback = 100): number {
  if (value === null) return fallback;
  const n = Number(value);
  if (!Number.isInteger(n) || n < 1 || n > max) throw bad(`limit must be between 1 and ${max}.`);
  return n;
}

const oneOf = <T extends string>(list: readonly T[], value: unknown, name: string): T => {
  if (typeof value !== "string" || !list.includes(value as T)) throw bad(`${name} must be one of ${list.join(", ")}.`);
  return value as T;
};
const int = (value: unknown, min: number, max: number, name: string) => {
  if (typeof value !== "number" || !Number.isInteger(value) || value < min || value > max) throw bad(`${name} must be a whole number from ${min} to ${max}.`);
  return value;
};
const date = (value: unknown, name: string) => {
  const t = typeof value === "string" ? Date.parse(value) : NaN;
  if (Number.isNaN(t)) throw bad(`${name} must be a date and time such as 2026-10-22T12:00:00Z.`);
  return new Date(t).toISOString();
};
const labelsOf = (value: unknown): string[] => {
  if (!Array.isArray(value) || value.length > 20 || value.some((l) => typeof l !== "string" || !l.trim() || l.length > 64))
    throw bad("labels must be up to 20 short strings.");
  return [...new Set(value.map((l: string) => l.trim()))];
};
const noExtra = (rest: object, expected: string) => {
  if (Object.keys(rest).length) throw bad(`Expected ${expected}.`);
};

interface IndicatorRow {
  id: string;
  type: IndicatorType;
  value: string;
  feed_id: string;
  feed_name: string;
  confidence: number;
  tlp: Tlp;
  severity: Severity;
  labels: string;
  description: string | null;
  include_subdomains: number;
  valid_from: string;
  valid_until: string;
  revoked: number;
  created_at: string;
  updated_at: string;
}

/** What goes into the store for one indicator, before defaults are filled in. */
interface Candidate {
  type: IndicatorType;
  value: string;
  confidence?: number;
  tlp?: Tlp;
  severity?: Severity;
  labels?: string[];
  description?: string | null;
  includeSubdomains?: boolean;
  validFrom?: string;
  validUntil?: string;
  revoked?: boolean;
}

export interface IntelOptions {
  /** Indicators that ended, and allow-list entries that expired, more than this long ago are deleted (ADR 0015). */
  retentionDays?: number;
}

export function createIntel(db: DatabaseSync, { retentionDays = 365 }: IntelOptions = {}) {
  let lookups = 0;
  let hits = 0;

  const feedRow = (id: string) => {
    const r = db.prepare("SELECT * FROM feeds WHERE id = ?").get(id) as Record<string, any> | undefined;
    if (!r) throw notFound("The feed");
    return r;
  };

  const upsert = db.prepare(
    `INSERT INTO indicators (id, type, value, feed_id, confidence, tlp, severity, labels, description, include_subdomains, valid_from, valid_until, revoked, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
     ON CONFLICT (type, value, feed_id) DO UPDATE SET confidence = excluded.confidence, tlp = excluded.tlp, severity = excluded.severity, labels = excluded.labels,
       description = excluded.description, include_subdomains = excluded.include_subdomains, valid_from = excluded.valid_from, valid_until = excluded.valid_until,
       revoked = excluded.revoked, updated_at = excluded.updated_at`,
  );
  const exists = db.prepare("SELECT 1 FROM indicators WHERE type = ? AND value = ? AND feed_id = ?");

  /** Stores one indicator with the feed's defaults for whatever it does not say. Returns whether it is new. */
  function store(feed: Record<string, any>, c: Candidate, at: string): boolean {
    const isNew = !exists.get(c.type, c.value, feed.id);
    const validFrom = c.validFrom ?? at;
    const validUntil = c.validUntil ?? new Date(Date.parse(at) + feed.default_ttl_days * 86_400_000).toISOString();
    upsert.run(
      randomUUID(),
      c.type,
      c.value,
      feed.id,
      c.confidence ?? feed.default_confidence,
      c.tlp ?? feed.default_tlp,
      c.severity ?? feed.default_severity,
      JSON.stringify(c.labels ?? []),
      c.description ?? null,
      c.type === "domain" && c.includeSubdomains ? 1 : 0,
      validFrom,
      validUntil,
      c.revoked ? 1 : 0,
      at,
      at,
    );
    return isNew;
  }

  function presentFeed(f: Record<string, any>) {
    const at = now();
    const total = (db.prepare("SELECT COUNT(*) AS n FROM indicators WHERE feed_id = ?").get(f.id) as { n: number }).n;
    const active = (
      db.prepare("SELECT COUNT(*) AS n FROM indicators WHERE feed_id = ? AND revoked = 0 AND valid_from <= ? AND valid_until > ?").get(f.id, at, at) as {
        n: number;
      }
    ).n;
    return {
      id: f.id as string,
      name: f.name as string,
      kind: f.kind as Kind,
      defaultTtlDays: f.default_ttl_days as number,
      defaultConfidence: f.default_confidence as number,
      defaultTlp: f.default_tlp as Tlp,
      defaultSeverity: f.default_severity as Severity,
      lastImportAt: (f.last_import_at as string | null) ?? null,
      indicators: { total, active },
      pull: presentPull(db, f.id as string),
      createdAt: f.created_at as string,
    };
  }

  function presentIndicator(r: IndicatorRow) {
    const at = now();
    return {
      id: r.id,
      type: r.type,
      value: r.value,
      feed: { id: r.feed_id, name: r.feed_name },
      confidence: r.confidence,
      tlp: r.tlp,
      severity: r.severity,
      labels: JSON.parse(r.labels) as string[],
      description: r.description,
      includeSubdomains: r.include_subdomains === 1,
      validFrom: r.valid_from,
      validUntil: r.valid_until,
      revoked: r.revoked === 1,
      active: r.revoked === 0 && r.valid_from <= at && r.valid_until > at,
      createdAt: r.created_at,
      updatedAt: r.updated_at,
    };
  }

  const indicatorRow = (id: string) => {
    const r = db.prepare("SELECT i.*, f.name AS feed_name FROM indicators i JOIN feeds f ON f.id = i.feed_id WHERE i.id = ?").get(id) as
      IndicatorRow | undefined;
    if (!r) throw notFound("The indicator");
    return r;
  };

  const feedFields = (body: Record<string, unknown>, base: { ttl: number; confidence: number; tlp: Tlp; severity: Severity }) => ({
    ttl: body.defaultTtlDays === undefined ? base.ttl : int(body.defaultTtlDays, 1, 3650, "defaultTtlDays"),
    confidence: body.defaultConfidence === undefined ? base.confidence : int(body.defaultConfidence, 0, 100, "defaultConfidence"),
    tlp: body.defaultTlp === undefined ? base.tlp : oneOf(TLPS, body.defaultTlp, "defaultTlp"),
    severity: body.defaultSeverity === undefined ? base.severity : oneOf(SEVERITIES, body.defaultSeverity, "defaultSeverity"),
  });

  const inList = new Map<number, ReturnType<DatabaseSync["prepare"]>>();
  const placeholders = (n: number) => Array<string>(n).fill("?").join(",");
  /** A statement with an IN list of n values, prepared once per n. */
  const withList = (sql: (marks: string) => string, n: number) => {
    const key = n + sql("").length;
    let s = inList.get(key);
    if (!s) inList.set(key, (s = db.prepare(sql(placeholders(n)))));
    return s;
  };

  function lookupOne(n: { type: IndicatorType; value: string }, at: string, red: boolean) {
    const active = "i.revoked = 0 AND i.valid_from <= ? AND i.valid_until > ? AND (? = 1 OR i.tlp <> 'red')";
    const base = (extra: string) => `SELECT i.*, f.name AS feed_name FROM indicators i JOIN feeds f ON f.id = i.feed_id WHERE ${active} AND ${extra}`;
    const common: SQLInputValue[] = [at, at, red ? 1 : 0];
    const found: Array<{ row: IndicatorRow; via: "exact" | "cidr" | "subdomain" }> = [];
    const isIp = n.type === "ipv4" || n.type === "ipv6";
    let allowRows: Array<Record<string, any>>;
    const allowBase = (extra: string) => `SELECT a.* FROM allow_list a WHERE a.expires_at > ? AND ${extra}`;

    if (n.type === "domain") {
      const labels = n.value.split(".");
      const parents = labels.map((_, i) => labels.slice(i).join(".")).filter((d) => d.includes("."));
      const rows = withList((m) => base(`i.type = 'domain' AND i.value IN (${m}) AND (i.value = ? OR i.include_subdomains = 1)`), parents.length).all(
        ...common,
        ...parents,
        n.value,
      ) as unknown as IndicatorRow[];
      for (const row of rows) found.push({ row, via: row.value === n.value ? "exact" : "subdomain" });
      allowRows = withList((m) => allowBase(`a.type = 'domain' AND a.value IN (${m}) AND (a.value = ? OR a.include_subdomains = 1)`), parents.length).all(
        at,
        ...parents,
        n.value,
      ) as Array<Record<string, any>>;
    } else {
      for (const row of db.prepare(base("i.type = ? AND i.value = ?")).all(...common, n.type, n.value) as unknown as IndicatorRow[])
        found.push({ row, via: "exact" });
      allowRows = db.prepare(allowBase("a.type = ? AND a.value = ?")).all(at, n.type, n.value) as Array<Record<string, any>>;
      if (isIp) {
        const nets = networksContaining(n.value);
        for (const row of withList((m) => base(`i.type = 'cidr' AND i.value IN (${m})`), nets.length).all(...common, ...nets) as unknown as IndicatorRow[])
          found.push({ row, via: "cidr" });
        allowRows.push(...(withList((m) => allowBase(`a.type = 'cidr' AND a.value IN (${m})`), nets.length).all(at, ...nets) as Array<Record<string, any>>));
      }
    }

    const best = <T>(list: T[], rank: (x: T) => number) => list.reduce<T | undefined>((a, x) => (a === undefined || rank(x) > rank(a) ? x : a), undefined);
    const confidence = found.length ? Math.max(...found.map((m) => m.row.confidence)) : null;
    const allow = allowRows[0];
    const verdict: Verdict = allow ? "allowed" : !found.length ? "unknown" : confidence! >= MALICIOUS_CONFIDENCE ? "malicious" : "suspicious";
    return {
      type: n.type,
      value: n.value,
      verdict,
      confidence,
      severity: best(found, (m) => SEVERITY_RANK[m.row.severity])?.row.severity ?? null,
      tlp: best(found, (m) => TLP_RANK[m.row.tlp])?.row.tlp ?? null,
      feeds: [...new Set(found.map((m) => m.row.feed_name))].sort(),
      matches: found
        .sort((a, b) => b.row.confidence - a.row.confidence)
        .map(({ row, via }) => ({
          id: row.id,
          type: row.type,
          value: row.value,
          feed: { id: row.feed_id, name: row.feed_name },
          confidence: row.confidence,
          severity: row.severity,
          tlp: row.tlp,
          labels: JSON.parse(row.labels) as string[],
          description: row.description,
          validUntil: row.valid_until,
          via,
        })),
      allowed: allow ? { reason: allow.reason as string, expiresAt: allow.expires_at as string } : null,
    };
  }

  const allowPresent = (a: Record<string, any>) => ({
    id: a.id as string,
    type: a.type as IndicatorType,
    value: a.value as string,
    includeSubdomains: a.include_subdomains === 1,
    reason: a.reason as string,
    by: (a.created_by as string | null) ?? null,
    createdAt: a.created_at as string,
    expiresAt: a.expires_at as string,
    active: (a.expires_at as string) > now(),
  });

  return {
    createFeed(body: Record<string, unknown>) {
      const { name, kind, defaultTtlDays, defaultConfidence, defaultTlp, defaultSeverity, ...rest } = body;
      noExtra(rest, "{ name, kind, defaultTtlDays?, defaultConfidence?, defaultTlp?, defaultSeverity? }");
      if (typeof name !== "string" || !FEED_NAME.test(name)) throw bad("name is up to 64 letters, digits, spaces and . _ -.");
      const d = feedFields({ defaultTtlDays, defaultConfidence, defaultTlp, defaultSeverity }, { ttl: 30, confidence: 50, tlp: "amber", severity: "medium" });
      if (db.prepare("SELECT 1 FROM feeds WHERE name = ?").get(name)) throw new IntelError(409, "conflict", "A feed with this name exists.");
      const id = randomUUID();
      db.prepare(
        "INSERT INTO feeds (id, name, kind, default_ttl_days, default_confidence, default_tlp, default_severity, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
      ).run(id, name, oneOf(KINDS, kind, "kind"), d.ttl, d.confidence, d.tlp, d.severity, now());
      return presentFeed(feedRow(id));
    },

    listFeeds(cursor: string | undefined, limit: number): Page<ReturnType<typeof presentFeed>> {
      const offset = decodeCursor(cursor);
      const rows = db.prepare("SELECT * FROM feeds ORDER BY name LIMIT ? OFFSET ?").all(limit + 1, offset) as Array<Record<string, any>>;
      return { items: rows.slice(0, limit).map(presentFeed), ...(rows.length > limit && { nextCursor: encodeCursor(offset + limit) }) };
    },

    feed: (id: string) => presentFeed(feedRow(id)),

    updateFeed(id: string, body: Record<string, unknown>) {
      const f = feedRow(id);
      const { name, defaultTtlDays, defaultConfidence, defaultTlp, defaultSeverity, ...rest } = body;
      noExtra(rest, "{ name?, defaultTtlDays?, defaultConfidence?, defaultTlp?, defaultSeverity? }");
      if (name === undefined && defaultTtlDays === undefined && defaultConfidence === undefined && defaultTlp === undefined && defaultSeverity === undefined)
        throw bad("Send at least one field to change.");
      if (name !== undefined) {
        if (typeof name !== "string" || !FEED_NAME.test(name)) throw bad("name is up to 64 letters, digits, spaces and . _ -.");
        if (db.prepare("SELECT 1 FROM feeds WHERE name = ? AND id <> ?").get(name, id)) throw new IntelError(409, "conflict", "A feed with this name exists.");
      }
      const d = feedFields(
        { defaultTtlDays, defaultConfidence, defaultTlp, defaultSeverity },
        { ttl: f.default_ttl_days, confidence: f.default_confidence, tlp: f.default_tlp, severity: f.default_severity },
      );
      db.prepare("UPDATE feeds SET name = ?, default_ttl_days = ?, default_confidence = ?, default_tlp = ?, default_severity = ? WHERE id = ?").run(
        name ?? f.name,
        d.ttl,
        d.confidence,
        d.tlp,
        d.severity,
        id,
      );
      return presentFeed(feedRow(id));
    },

    deleteFeed(id: string) {
      if (db.prepare("DELETE FROM feeds WHERE id = ?").run(id).changes === 0) throw notFound("The feed");
    },

    /** Reads an import by the feed's kind and stores what it holds. Nothing it cannot read is dropped without a word. */
    importFeed(feedId: string, raw: Buffer) {
      const feed = feedRow(feedId);
      if (feed.kind === "manual")
        throw new IntelError(409, "conflict", "A manual feed takes indicators one at a time; create a feed of kind stix, csv or text to import.");
      const at = now();
      const skipped: Array<{ ref: string; reason: string }> = [];
      const unparsed: Array<{ id: string; pattern: string; reason: string }> = [];
      let skippedCount = 0;
      let unparsedCount = 0;
      let received = 0;
      const candidates: Candidate[] = [];
      const skip = (ref: string, reason: string) => {
        skippedCount++;
        if (skipped.length < MAX_PROBLEMS) skipped.push({ ref, reason });
      };
      const cannot = (id: string, pattern: string, reason: string) => {
        unparsedCount++;
        if (unparsed.length < MAX_PROBLEMS) unparsed.push({ id, pattern: pattern.slice(0, 300), reason });
      };
      const text = raw.toString("utf8");

      if (feed.kind === "text") {
        text.split(/\r?\n/).forEach((line, i) => {
          const v = line.trim();
          if (!v || v.startsWith("#")) return;
          received++;
          try {
            candidates.push(normalizeIndicator(undefined, v));
          } catch (err) {
            skip(`line ${i + 1}`, (err as Error).message);
          }
        });
      } else if (feed.kind === "csv") {
        const rows = parseCsv(text);
        const header = (rows[0] ?? []).map((h) => h.trim().toLowerCase());
        const col = (row: string[], name: string) => {
          const i = header.indexOf(name);
          return i < 0 ? "" : (row[i] ?? "").trim();
        };
        if (!header.includes("value"))
          throw new IntelError(
            422,
            "invalid-import",
            "The first row must name the columns, and one of them must be value (optional: type, confidence, tlp, severity, tags, description, valid_from, valid_until, include_subdomains).",
          );
        rows.slice(1).forEach((row, i) => {
          received++;
          const ref = `row ${i + 2}`;
          try {
            const n = normalizeIndicator(col(row, "type") || undefined, col(row, "value"));
            const c: Candidate = { ...n };
            if (col(row, "confidence")) c.confidence = int(Number(col(row, "confidence")), 0, 100, "confidence");
            if (col(row, "tlp")) c.tlp = oneOf(TLPS, col(row, "tlp").toLowerCase(), "tlp");
            if (col(row, "severity")) c.severity = oneOf(SEVERITIES, col(row, "severity").toLowerCase(), "severity");
            const tags = col(row, "tags") || col(row, "labels");
            if (tags)
              c.labels = labelsOf(
                tags
                  .split(/[;|]/)
                  .map((t) => t.trim())
                  .filter(Boolean),
              );
            if (col(row, "description")) c.description = col(row, "description").slice(0, 1000);
            if (col(row, "valid_from")) c.validFrom = date(col(row, "valid_from"), "valid_from");
            if (col(row, "valid_until")) c.validUntil = date(col(row, "valid_until"), "valid_until");
            c.includeSubdomains = ["true", "1", "yes"].includes(col(row, "include_subdomains").toLowerCase());
            candidates.push(c);
          } catch (err) {
            skip(ref, (err as Error).message);
          }
        });
      } else {
        let body: any;
        try {
          body = JSON.parse(text);
        } catch {
          throw new IntelError(422, "invalid-import", "The body is not JSON; a stix feed takes a STIX 2.1 bundle.");
        }
        const objects: unknown[] | null = Array.isArray(body)
          ? body
          : body && typeof body === "object" && body.type === "bundle" && Array.isArray(body.objects)
            ? body.objects
            : null;
        if (!objects) throw new IntelError(422, "invalid-import", "Send a STIX 2.1 bundle: a JSON object with type bundle and an objects array.");
        for (const obj of objects as Array<Record<string, any>>) {
          if (!obj || typeof obj !== "object" || obj.type !== "indicator") continue;
          received++;
          const id = typeof obj.id === "string" ? obj.id : `indicator ${received}`;
          const pattern = typeof obj.pattern === "string" ? obj.pattern : "";
          if (obj.pattern_type !== undefined && obj.pattern_type !== "stix") {
            cannot(id, pattern, `pattern_type ${String(obj.pattern_type).slice(0, 30)} is not supported; only stix`);
            continue;
          }
          let values: ReturnType<typeof parseStixPattern>;
          try {
            values = parseStixPattern(pattern);
          } catch (err) {
            if (!(err instanceof StixPatternError)) throw err;
            cannot(id, pattern, err.message);
            continue;
          }
          try {
            const c: Omit<Candidate, "type" | "value"> = { revoked: obj.revoked === true };
            if (Number.isInteger(obj.confidence) && obj.confidence >= 0 && obj.confidence <= 100) c.confidence = obj.confidence;
            if (obj.valid_from !== undefined) c.validFrom = date(obj.valid_from, "valid_from");
            if (obj.valid_until !== undefined) c.validUntil = date(obj.valid_until, "valid_until");
            const marking = (Array.isArray(obj.object_marking_refs) ? obj.object_marking_refs : []).map((r: unknown) => TLP_MARKINGS[String(r)]).find(Boolean);
            if (marking) c.tlp = marking;
            const labels = [...(Array.isArray(obj.labels) ? obj.labels : []), ...(Array.isArray(obj.indicator_types) ? obj.indicator_types : [])].filter(
              (l): l is string => typeof l === "string" && !!l.trim() && l.length <= 64,
            );
            c.labels = [...new Set(labels)].slice(0, 20);
            const description = typeof obj.description === "string" ? obj.description : typeof obj.name === "string" ? obj.name : undefined;
            if (description) c.description = description.slice(0, 1000);
            for (const v of values) candidates.push({ ...c, ...v });
          } catch (err) {
            skip(id, (err as Error).message);
          }
        }
      }

      if (candidates.length > MAX_IMPORT) throw new IntelError(422, "invalid-import", `An import holds at most ${MAX_IMPORT} indicators.`);
      let created = 0;
      let updated = 0;
      db.exec("BEGIN IMMEDIATE");
      try {
        for (const c of candidates) store(feed, c, at) ? created++ : updated++;
        db.prepare("UPDATE feeds SET last_import_at = ? WHERE id = ?").run(at, feed.id);
        db.exec("COMMIT");
      } catch (err) {
        db.exec("ROLLBACK");
        throw err;
      }
      return {
        feed: { id: feed.id as string, name: feed.name as string },
        received,
        created,
        updated,
        revoked: candidates.filter((c) => c.revoked).length,
        skippedCount,
        skipped,
        unparsedCount,
        unparsed,
      };
    },

    createIndicator(body: Record<string, unknown>) {
      const { feed: feedRef, type, value, confidence, tlp, severity, labels, description, includeSubdomains, validFrom, validUntil, ...rest } = body;
      noExtra(rest, "{ feed, value, type?, confidence?, tlp?, severity?, labels?, description?, includeSubdomains?, validFrom?, validUntil? }");
      if (typeof feedRef !== "string") throw bad("feed is the id of a manual feed.");
      const f = db.prepare("SELECT * FROM feeds WHERE id = ? OR name = ?").get(feedRef, feedRef) as Record<string, any> | undefined;
      if (!f) throw notFound("The feed");
      if (f.kind !== "manual") throw new IntelError(409, "conflict", "Only a manual feed takes indicators one at a time.");
      if (typeof value !== "string") throw bad("value is the indicator, such as 198.51.100.7 or bad.example.com.");
      if (type !== undefined && typeof type !== "string") throw bad(`type must be one of ${TYPES.join(", ")}.`);
      if (includeSubdomains !== undefined && typeof includeSubdomains !== "boolean") throw bad("includeSubdomains must be true or false.");
      let n: { type: IndicatorType; value: string };
      try {
        n = normalizeIndicator(type, value);
      } catch (err) {
        if (err instanceof NormalizeError) throw bad(`value: ${err.message}.`);
        throw err;
      }
      const c: Candidate = { ...n, includeSubdomains: includeSubdomains === true };
      if (confidence !== undefined) c.confidence = int(confidence, 0, 100, "confidence");
      if (tlp !== undefined) c.tlp = oneOf(TLPS, tlp, "tlp");
      if (severity !== undefined) c.severity = oneOf(SEVERITIES, severity, "severity");
      if (labels !== undefined) c.labels = labelsOf(labels);
      if (description !== undefined) {
        if (typeof description !== "string" || description.length > 1000) throw bad("description is up to 1000 characters.");
        c.description = description;
      }
      if (validFrom !== undefined) c.validFrom = date(validFrom, "validFrom");
      if (validUntil !== undefined) c.validUntil = date(validUntil, "validUntil");
      if (c.validFrom && c.validUntil && c.validUntil <= c.validFrom) throw bad("validUntil must be after validFrom.");
      store(f, c, now());
      const row = db
        .prepare("SELECT i.*, fe.name AS feed_name FROM indicators i JOIN feeds fe ON fe.id = i.feed_id WHERE i.type = ? AND i.value = ? AND i.feed_id = ?")
        .get(n.type, n.value, f.id) as unknown as IndicatorRow;
      return presentIndicator(row);
    },

    listIndicators(
      q: { type?: string; feed?: string; q?: string; tlp?: string; severity?: string; status: string },
      cursor: string | undefined,
      limit: number,
      caller: Caller,
    ) {
      const where: string[] = [];
      const args: SQLInputValue[] = [];
      const at = now();
      if (q.type) (where.push("i.type = ?"), args.push(oneOf(TYPES, q.type, "type")));
      if (q.feed) (where.push("i.feed_id = ?"), args.push(q.feed));
      if (q.tlp) (where.push("i.tlp = ?"), args.push(oneOf(TLPS, q.tlp, "tlp")));
      if (q.severity) (where.push("i.severity = ?"), args.push(oneOf(SEVERITIES, q.severity, "severity")));
      if (q.q) (where.push("i.value LIKE ? ESCAPE '\\'"), args.push(`%${q.q.replace(/[\\%_]/g, "\\$&")}%`));
      if (q.status === "active") (where.push("i.revoked = 0 AND i.valid_from <= ? AND i.valid_until > ?"), args.push(at, at));
      else if (q.status === "inactive") (where.push("(i.revoked = 1 OR i.valid_from > ? OR i.valid_until <= ?)"), args.push(at, at));
      else if (q.status !== "all") throw bad("status must be active, inactive or all.");
      if (!SEES_RED(caller.role)) where.push("i.tlp <> 'red'");
      const offset = decodeCursor(cursor);
      const rows = db
        .prepare(
          `SELECT i.*, f.name AS feed_name FROM indicators i JOIN feeds f ON f.id = i.feed_id ${where.length ? "WHERE " + where.join(" AND ") : ""} ORDER BY i.updated_at DESC, i.id LIMIT ? OFFSET ?`,
        )
        .all(...args, limit + 1, offset) as unknown as IndicatorRow[];
      return {
        items: rows.slice(0, limit).map(presentIndicator),
        ...(rows.length > limit && { nextCursor: encodeCursor(offset + limit) }),
      } satisfies Page<unknown>;
    },

    indicator(id: string, caller: Caller) {
      const r = indicatorRow(id);
      if (r.tlp === "red" && !SEES_RED(caller.role)) throw notFound("The indicator");
      return presentIndicator(r);
    },

    deleteIndicator(id: string) {
      if (db.prepare("DELETE FROM indicators WHERE id = ?").run(id).changes === 0) throw notFound("The indicator");
    },

    /** Looks values up in the active indicators. TLP:RED is left out for callers who may not see it, as if it were not there. */
    lookup(items: unknown, caller: Caller) {
      if (!Array.isArray(items) || items.length === 0 || items.length > MAX_LOOKUP) throw bad(`items is a list of 1 to ${MAX_LOOKUP} values.`);
      const at = now();
      const red = SEES_RED(caller.role);
      const results = items.map((it: unknown, i) => {
        const item = it as { type?: unknown; value?: unknown } | null;
        if (!item || typeof item !== "object" || typeof item.value !== "string" || (item.type !== undefined && typeof item.type !== "string"))
          throw bad(`items[${i}] must be { value, type? }.`);
        if (item.type === "cidr") throw bad(`items[${i}]: look up an address, not a block; blocks that contain it are found for you.`);
        try {
          return lookupOne(normalizeIndicator(item.type, item.value), at, red);
        } catch (err) {
          if (err instanceof NormalizeError) throw bad(`items[${i}]: ${err.message}.`);
          throw err;
        }
      });
      lookups += results.length;
      hits += results.filter((r) => r.verdict === "malicious" || r.verdict === "suspicious").length;
      return results;
    },

    createAllow(body: Record<string, unknown>, by: string) {
      const { type, value, includeSubdomains, reason, expiresAt, ...rest } = body;
      noExtra(rest, "{ value, reason, expiresAt, type?, includeSubdomains? }");
      if (typeof value !== "string") throw bad("value is what is known to be fine, such as 203.0.113.0/24 or example.com.");
      if (type !== undefined && typeof type !== "string") throw bad(`type must be one of ${TYPES.join(", ")}.`);
      if (includeSubdomains !== undefined && typeof includeSubdomains !== "boolean") throw bad("includeSubdomains must be true or false.");
      let n: { type: IndicatorType; value: string };
      try {
        n = normalizeIndicator(type, value);
      } catch (err) {
        if (err instanceof NormalizeError) throw bad(`value: ${err.message}.`);
        throw err;
      }
      // A decision without a reason is lost the day its author leaves (ADR 0050).
      if (typeof reason !== "string" || reason.trim().length < 3 || reason.length > 500) throw bad("reason is required: 3 to 500 characters.");
      const end = date(expiresAt, "expiresAt");
      if (Date.parse(end) <= Date.now()) throw bad("expiresAt must be in the future.");
      if (Date.parse(end) > Date.now() + MAX_ALLOW_DAYS * 86_400_000) throw bad(`expiresAt must be within ${MAX_ALLOW_DAYS} days.`);
      if (db.prepare("SELECT 1 FROM allow_list WHERE type = ? AND value = ?").get(n.type, n.value))
        throw new IntelError(409, "conflict", "This value is already on the allow list.");
      const id = randomUUID();
      db.prepare(
        "INSERT INTO allow_list (id, type, value, include_subdomains, reason, created_by, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
      ).run(id, n.type, n.value, n.type === "domain" && includeSubdomains === true ? 1 : 0, reason.trim(), by, now(), end);
      return allowPresent(db.prepare("SELECT * FROM allow_list WHERE id = ?").get(id) as Record<string, any>);
    },

    listAllow(cursor: string | undefined, limit: number): Page<ReturnType<typeof allowPresent>> {
      const offset = decodeCursor(cursor);
      const rows = db.prepare("SELECT * FROM allow_list ORDER BY expires_at, id LIMIT ? OFFSET ?").all(limit + 1, offset) as Array<Record<string, any>>;
      return { items: rows.slice(0, limit).map(allowPresent), ...(rows.length > limit && { nextCursor: encodeCursor(offset + limit) }) };
    },

    deleteAllow(id: string) {
      if (db.prepare("DELETE FROM allow_list WHERE id = ?").run(id).changes === 0) throw notFound("The allow-list entry");
    },

    summary() {
      const at = now();
      const byType = Object.fromEntries(TYPES.map((t) => [t, 0])) as Record<IndicatorType, number>;
      for (const r of db
        .prepare("SELECT type, COUNT(*) AS n FROM indicators WHERE revoked = 0 AND valid_from <= ? AND valid_until > ? GROUP BY type")
        .all(at, at) as Array<{ type: IndicatorType; n: number }>)
        byType[r.type] = r.n;
      const total = (db.prepare("SELECT COUNT(*) AS n FROM indicators").get() as { n: number }).n;
      const active = Object.values(byType).reduce((a, b) => a + b, 0);
      return {
        feeds: (db.prepare("SELECT COUNT(*) AS n FROM feeds").get() as { n: number }).n,
        indicators: { active, inactive: total - active },
        byType,
        allowListed: (db.prepare("SELECT COUNT(*) AS n FROM allow_list WHERE expires_at > ?").get(at) as { n: number }).n,
        lookups: { total: lookups, hits },
        // Feeds pulled on a schedule whose last pull worked, and those whose last pull failed.
        pulls: db
          .prepare("SELECT COUNT(*) FILTER (WHERE last_error IS NULL) AS ok, COUNT(*) FILTER (WHERE last_error IS NOT NULL) AS failing FROM feed_pulls")
          .get() as { ok: number; failing: number },
      };
    },

    stats: () => ({ lookups, hits }),

    purge() {
      const before = new Date(Date.now() - retentionDays * 86_400_000).toISOString();
      db.prepare("DELETE FROM indicators WHERE valid_until < ?").run(before);
      db.prepare("DELETE FROM allow_list WHERE expires_at < ?").run(before);
    },
  };
}

export type Intel = ReturnType<typeof createIntel>;

/** Comma-separated values with "quoted, cells" and "" for a quote; CRLF or LF. */
export function parseCsv(text: string): string[][] {
  const rows: string[][] = [];
  let row: string[] = [];
  let cell = "";
  let quoted = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i]!;
    if (quoted) {
      if (c === '"') {
        if (text[i + 1] === '"') ((cell += '"'), i++);
        else quoted = false;
      } else cell += c;
    } else if (c === '"' && cell === "") quoted = true;
    else if (c === ",") (row.push(cell), (cell = ""));
    else if (c === "\n") (row.push(cell), rows.push(row), (row = []), (cell = ""));
    else if (c !== "\r") cell += c;
  }
  if (cell !== "" || row.length) (row.push(cell), rows.push(row));
  return rows.filter((r) => r.some((c) => c.trim()));
}

export { detectType };
