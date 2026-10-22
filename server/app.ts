import { timingSafeEqual } from "node:crypto";
import { readFile } from "node:fs/promises";
import type { IncomingMessage, ServerResponse } from "node:http";
import { extname, join, normalize } from "node:path";
import type { DatabaseSync } from "node:sqlite";
import { createGunzip } from "node:zlib";
import { AuthError, mergeOpenApi, sendProblem, type Auth, type Role } from "@openasy/auth";
import { log } from "./log.ts";
import { countRequest, renderMetrics } from "./metrics.ts";
import type { ProductLink } from "./products.ts";
import { IntelError, parseLimit, type Caller, type Intel, type ProblemCode } from "./intel.ts";

export interface AppOptions {
  db: DatabaseSync;
  intel: Intel;
  version: string;
  /** Sign-in, sessions, members and API tokens (ADR 0002, 0003). */
  auth: Auth;
  /** Token for imports and lookups, and nothing else (ADR 0003). An API token with the editor role works too. */
  ingestToken?: string;
  /** For tests and local scripts: one shared token with the admin role. main.ts never sets it. */
  adminToken?: string;
  /** Built web UI; omit to run headless (ADR 0018). */
  webDir?: string;
  /** Built API reference (Swagger UI), served at /api/docs. */
  docsDir?: string;
  /** The OpenAPI description, served at /api/openapi.json with this release's version. */
  openapi?: Record<string, unknown>;
  /** false when /metrics is served on its own port instead (ADR 0026). */
  serveMetrics?: boolean;
  /** The install's OpenAsy products and their addresses, from OPENASY_PRODUCTS, for the product switcher. */
  products?: ProductLink[];
}

function metricsText(intel: Intel, version: string) {
  const s = intel.summary();
  return renderMetrics(version, { feeds: s.feeds, active: s.indicators.active, byType: s.byType, allowListed: s.allowListed, lookups: s.lookups.total, hits: s.lookups.hits });
}

/** Serves only /metrics, for a port that is not exposed with the rest (THREAT_INTEL_METRICS_PORT). */
export function createMetricsHandler(intel: Intel, version: string) {
  return (req: IncomingMessage, res: ServerResponse) => {
    if (new URL(req.url ?? "/", "http://localhost").pathname !== "/metrics") return problem(res, 404, "not-found");
    send(res, 200, metricsText(intel, version), "text/plain; version=0.0.4");
  };
}

const TYPES: Record<string, string> = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript",
  ".json": "application/json",
  ".css": "text/css",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".ico": "image/x-icon",
  ".woff2": "font/woff2",
};

const SECURITY_HEADERS = {
  "x-content-type-options": "nosniff",
  "referrer-policy": "no-referrer",
  "x-frame-options": "DENY",
  "content-security-policy": "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'",
};

/** Largest import accepted, after decompression. */
const IMPORT_LIMIT = 32 * 1024 * 1024;

function send(res: ServerResponse, status: number, body: string | Buffer, type = "application/json", headers: Record<string, string> = {}) {
  res.writeHead(status, { ...SECURITY_HEADERS, ...headers, "content-type": type, "content-length": Buffer.byteLength(body) });
  res.end(body);
}

const json = (res: ServerResponse, status: number, data: unknown, headers?: Record<string, string>) => send(res, status, JSON.stringify(data), "application/json", headers);

const TITLES: Record<ProblemCode, string> = {
  "invalid-token": "Invalid token",
  "invalid-json": "Invalid JSON",
  "invalid-body": "Invalid request body",
  "invalid-import": "Invalid import",
  "not-found": "Not found",
  conflict: "Conflict",
  "not-configured": "Not configured",
  "payload-too-large": "Payload too large",
  "internal-error": "Internal error",
};

/** RFC 9457 Problem Details (ADR 0024). `code` is the stable part clients match on. */
function problem(res: ServerResponse, status: number, code: ProblemCode, detail?: string) {
  const body = { type: `https://openasy.github.io/problems/${code}`, title: TITLES[code], status, code, ...(detail && { detail }) };
  send(res, status, JSON.stringify(body), "application/problem+json");
}

/** Serves a file from dir, or returns false when the path is outside it or missing. */
async function serveFile(res: ServerResponse, dir: string, relative: string): Promise<boolean> {
  const file = normalize(join(dir, relative));
  if (!file.startsWith(normalize(dir)) || !extname(file)) return false;
  try {
    send(res, 200, await readFile(file), TYPES[extname(file)] ?? "application/octet-stream");
    return true;
  } catch {
    return false;
  }
}

/** Reads the whole body, gunzipping it when sent with `Content-Encoding: gzip`, up to limit bytes. */
async function readBody(req: IncomingMessage, limit: number): Promise<Buffer> {
  const encoding = req.headers["content-encoding"];
  if (encoding && encoding !== "gzip" && encoding !== "identity") throw new IntelError(400, "invalid-body", "Content-Encoding must be gzip or absent.");
  const source = encoding === "gzip" ? req.pipe(createGunzip()) : req;
  const chunks: Buffer[] = [];
  let size = 0;
  try {
    for await (const chunk of source as AsyncIterable<Buffer>) {
      size += chunk.length;
      if (size > limit) throw new IntelError(413, "payload-too-large", `The body must be at most ${Math.round(limit / 1024 / 1024)} MiB.`);
      chunks.push(chunk);
    }
  } catch (err) {
    if (err instanceof IntelError) throw err;
    throw new IntelError(400, "invalid-body", "The gzip body could not be read.");
  }
  return Buffer.concat(chunks);
}

async function readJson(req: IncomingMessage, limit = 64 * 1024): Promise<Record<string, unknown>> {
  const raw = await readBody(req, limit).catch((err: unknown) => {
    if (err instanceof IntelError && err.code === "payload-too-large") throw new IntelError(400, "invalid-json", `The body must be JSON, at most ${Math.round(limit / 1024)} KiB.`);
    throw err;
  });
  try {
    const body = JSON.parse(raw.toString("utf8")) as unknown;
    if (body === null || typeof body !== "object" || Array.isArray(body)) throw new Error("not an object");
    return body as Record<string, unknown>;
  } catch {
    throw new IntelError(400, "invalid-json", "The body must be a JSON object.");
  }
}

function tokenMatches(header: string | undefined, expected: string | undefined): boolean {
  if (!expected || !header?.startsWith("Bearer ")) return false;
  const a = Buffer.from(header.slice(7));
  const b = Buffer.from(expected);
  return a.length === b.length && timingSafeEqual(a, b);
}

/** The role a route needs (ADR 0003), "ingest" for imports and "lookup" for lookups, which the ingest token may also do. */
type Access = "none" | "ingest" | "lookup" | Role;
interface Ctx {
  req: IncomingMessage;
  res: ServerResponse;
  url: URL;
  params: string[];
  body: () => Promise<Record<string, unknown>>;
  /** Who made the request, for the audit trail of a decision, and the role it acted with. */
  caller: Caller & { actor: string };
}
interface Route {
  method: string;
  /** Path pattern; each `:name` matches one segment. */
  path: string;
  auth: Access;
  handle: (ctx: Ctx) => unknown;
}

const query = (url: URL, name: string, max = 128) => {
  const v = url.searchParams.get(name)?.trim();
  if (v && v.length > max) throw new IntelError(422, "invalid-body", `${name} must be at most ${max} characters.`);
  return v || undefined;
};

export function createApp({ db, intel, version, auth, adminToken, ingestToken, webDir, docsDir, openapi, serveMetrics = true, products = [] }: AppOptions) {
  // The served description includes /api/v1/auth from @openasy/auth, so the API reference documents sign-in too.
  const spec = openapi && JSON.stringify({ ...mergeOpenApi(openapi), info: { ...(openapi.info as object), version } });
  const noContent = (res: ServerResponse) => {
    res.writeHead(204, SECURITY_HEADERS).end();
  };
  const cursor = (url: URL) => url.searchParams.get("cursor") ?? undefined;
  const limit = (url: URL) => parseLimit(url.searchParams.get("limit"));
  const page = <K extends string, T>(key: K, p: { items: T[]; nextCursor?: string }) => ({ [key]: p.items, ...(p.nextCursor && { nextCursor: p.nextCursor }) }) as Record<K, T[]> & { nextCursor?: string };

  const routes: Route[] = [
    { method: "GET", path: "/api/v1/version", auth: "none", handle: () => ({ product: "threat-intel", version }) },
    { method: "GET", path: "/api/v1/products", auth: "viewer", handle: () => ({ products }) },
    { method: "GET", path: "/api/v1/summary", auth: "viewer", handle: () => intel.summary() },

    // Feeds: where indicators come from.
    { method: "GET", path: "/api/v1/feeds", auth: "viewer", handle: ({ url }) => page("feeds", intel.listFeeds(cursor(url), limit(url))) },
    { method: "POST", path: "/api/v1/feeds", auth: "admin", handle: async ({ res, body }) => json(res, 201, intel.createFeed(await body())) },
    { method: "GET", path: "/api/v1/feeds/:id", auth: "viewer", handle: ({ params }) => intel.feed(params[0]!) },
    { method: "PATCH", path: "/api/v1/feeds/:id", auth: "admin", handle: async ({ params, body }) => intel.updateFeed(params[0]!, await body()) },
    { method: "DELETE", path: "/api/v1/feeds/:id", auth: "admin", handle: ({ res, params }) => (intel.deleteFeed(params[0]!), noContent(res)) },
    {
      // A STIX bundle, a CSV or a list of values, by the feed's kind. The answer names what was left out and why.
      method: "POST",
      path: "/api/v1/feeds/:id/import",
      auth: "ingest",
      handle: async ({ req, params }) => intel.importFeed(params[0]!, await readBody(req, IMPORT_LIMIT)),
    },

    // Indicators.
    {
      method: "GET",
      path: "/api/v1/indicators",
      auth: "viewer",
      handle: ({ url, caller }) =>
        page(
          "indicators",
          intel.listIndicators(
            { type: query(url, "type"), feed: query(url, "feed"), q: query(url, "q"), tlp: query(url, "tlp"), severity: query(url, "severity"), status: url.searchParams.get("status") ?? "active" },
            cursor(url),
            limit(url),
            caller,
          ),
        ),
    },
    { method: "POST", path: "/api/v1/indicators", auth: "editor", handle: async ({ res, body }) => json(res, 201, intel.createIndicator(await body())) },
    { method: "GET", path: "/api/v1/indicators/:id", auth: "viewer", handle: ({ params, caller }) => intel.indicator(params[0]!, caller) },
    { method: "DELETE", path: "/api/v1/indicators/:id", auth: "editor", handle: ({ res, params }) => (intel.deleteIndicator(params[0]!), noContent(res)) },

    // Lookup: the hot path other products call. TLP:RED is only for editors and the ingest token.
    {
      method: "GET",
      path: "/api/v1/lookup",
      auth: "lookup",
      handle: ({ url, caller }) => {
        const value = url.searchParams.get("value");
        if (value === null) throw new IntelError(422, "invalid-body", "value is required.");
        return intel.lookup([{ value, ...(url.searchParams.has("type") && { type: url.searchParams.get("type")! }) }], caller)[0];
      },
    },
    {
      method: "POST",
      path: "/api/v1/lookup",
      auth: "lookup",
      handle: async ({ body, caller }) => {
        const { items, ...rest } = await body();
        if (Object.keys(rest).length) throw new IntelError(422, "invalid-body", "Expected { items: [{ value, type? }] }.");
        return { results: intel.lookup(items, caller) };
      },
    },

    // The allow list: what is known to be fine, with a reason and an end date.
    { method: "GET", path: "/api/v1/allow-list", auth: "viewer", handle: ({ url }) => page("entries", intel.listAllow(cursor(url), limit(url))) },
    { method: "POST", path: "/api/v1/allow-list", auth: "editor", handle: async ({ res, body, caller }) => json(res, 201, intel.createAllow(await body(), caller.actor)) },
    { method: "DELETE", path: "/api/v1/allow-list/:id", auth: "editor", handle: ({ res, params }) => (intel.deleteAllow(params[0]!), noContent(res)) },
  ];

  const compiled = routes.map((r) => ({ ...r, re: new RegExp(`^${r.path.replace(/:[A-Za-z]+/g, "([^/]+)")}$`) }));

  /** Who is calling and with which role. The ingest token acts as an editor: it sends imports and looks values up. */
  function authorize(req: IncomingMessage, access: Access): Caller & { actor: string } {
    if (access === "none") return { role: "viewer", actor: "unknown" };
    const header = req.headers.authorization;
    if ((access === "ingest" || access === "lookup") && tokenMatches(header, ingestToken)) return { role: "editor", actor: "ingest token" };
    if (tokenMatches(header, adminToken)) return { role: "admin", actor: "admin token" };
    if (access === "ingest") {
      // An API token or a session with the editor role can import too, for scripts set up from Settings.
      if (!ingestToken && !header?.startsWith("Bearer oa_")) throw new IntelError(503, "not-configured", "Set THREAT_INTEL_INGEST_TOKEN on threat-intel, or send an API token with the editor role.");
      if (!header?.startsWith("Bearer oa_")) throw new IntelError(401, "invalid-token", "Send THREAT_INTEL_INGEST_TOKEN or an API token as a bearer token.");
    }
    const p = auth.authorize(req, access === "ingest" ? "editor" : access === "lookup" ? "viewer" : access);
    return { role: p.role, actor: p.kind === "session" ? p.user.name : `API token ${p.name}` };
  }

  async function route(req: IncomingMessage, res: ServerResponse): Promise<string> {
    const url = new URL(req.url ?? "/", "http://localhost");
    const path = url.pathname;

    if (path === "/healthz") return (json(res, 200, { status: "ok" }), "/healthz");

    if (path === "/readyz") {
      // Ready to take imports and lookups as long as the database answers.
      try {
        db.prepare("SELECT 1").get();
        json(res, 200, { status: "ready" });
      } catch {
        json(res, 503, { status: "database unavailable" });
      }
      return "/readyz";
    }

    if (path === "/metrics") {
      // Not even the web UI's fallback answers here when metrics have their own port.
      if (serveMetrics) send(res, 200, metricsText(intel, version), "text/plain; version=0.0.4");
      else problem(res, 404, "not-found");
      return "/metrics";
    }

    if (path === "/api/openapi.json" && spec) return (send(res, 200, spec), "/api/openapi.json");

    if (docsDir && (path === "/api/docs" || path.startsWith("/api/docs/"))) {
      if (path === "/api/docs") {
        res.writeHead(301, { ...SECURITY_HEADERS, location: "/api/docs/" }).end();
        return "/api/docs";
      }
      const relative = path.slice("/api/docs/".length) || "index.html";
      if (!(await serveFile(res, docsDir, relative))) problem(res, 404, "not-found");
      return "/api/docs";
    }

    if (await auth.handle(req, res)) return auth.routeName(req) ?? "/api/v1/auth/*";

    for (const r of compiled) {
      const m = path.match(r.re);
      if (!m || r.method !== req.method) continue;
      try {
        const caller = authorize(req, r.auth);
        const params = m.slice(1).map(decodeURIComponent);
        const result = await r.handle({ req, res, url, params, body: () => readJson(req), caller });
        if (!res.headersSent && result !== undefined) json(res, 200, result);
      } catch (err) {
        if (err instanceof AuthError) {
          sendProblem(res, err);
          if (!req.complete) req.resume();
          return r.path;
        }
        if (!(err instanceof IntelError)) throw err;
        problem(res, err.status, err.code, err.message);
        // Unread request bodies would otherwise hold the connection.
        if (!req.complete) req.resume();
      }
      return r.path;
    }

    if (path.startsWith("/api/")) return (problem(res, 404, "not-found"), "/api/*");

    if (webDir && (req.method === "GET" || req.method === "HEAD")) {
      // Unknown paths fall back to the single-page app.
      if (!(await serveFile(res, webDir, path === "/" ? "index.html" : path))) send(res, 200, await readFile(join(webDir, "index.html")), TYPES[".html"]);
      return "/web";
    }

    problem(res, 404, "not-found");
    return "unmatched";
  }

  return async (req: IncomingMessage, res: ServerResponse) => {
    const started = performance.now();
    let routeName = "error";
    try {
      routeName = await route(req, res);
    } catch (err) {
      log("error", "request failed", { error: String(err), path: req.url });
      if (!res.headersSent) problem(res, 500, "internal-error");
    }
    countRequest(req.method ?? "GET", routeName, res.statusCode);
    if (routeName !== "/healthz" && routeName !== "/metrics") {
      log("info", "request", { method: req.method, path: url(req), status: res.statusCode, ms: Math.round(performance.now() - started) });
    }
  };
}

/** The path without the query string, which may name hosts and images. */
const url = (req: IncomingMessage) => (req.url ?? "/").split("?")[0];
