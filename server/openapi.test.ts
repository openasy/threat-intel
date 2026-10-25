import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { gzipSync } from "node:zlib";
import { Ajv2020 } from "ajv/dist/2020.js";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { ADMIN_TOKEN, bundle, INGEST_TOKEN, startApp } from "./test-app.ts";

// Contract tests (ADR 0024): every response the API sends must match openapi.json.

type Spec = {
  info: { version: string };
  paths: Record<string, Record<string, { responses: Record<string, { $ref?: string; content?: Record<string, { schema: object }> }> }>>;
  components: { responses: Record<string, { content: Record<string, { schema: object }> }> };
};

const spec = JSON.parse(readFileSync(new URL("../openapi.json", import.meta.url), "utf8")) as Spec;
const { version } = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")) as { version: string };

const ajv = new Ajv2020({ strict: false, validateFormats: false });
ajv.addSchema(spec, "openapi");

const docsDir = mkdtempSync(join(tmpdir(), "threat-intel-docs-"));
writeFileSync(join(docsDir, "index.html"), "<!doctype html><title>API</title>");

let app: Awaited<ReturnType<typeof startApp>>;
let base: string;
const covered = new Set<string>();

beforeAll(async () => {
  // Feeds are pulled from here: one answers with a list, the other is down.
  const pullFetch = (async (url: string | URL) =>
    String(url).endsWith("/down") ? new Response("down", { status: 503 }) : new Response("198.51.100.50\n")) as typeof fetch;
  app = await startApp({ version, openapi: spec, docsDir, pullFetch });
  base = app.base;
});

afterAll(() => app.close());

/** Calls the API and checks status, content type and body against the description. */
async function call(method: string, path: string, init: RequestInit = {}, concrete = path) {
  const res = await fetch(base + concrete, { ...init, method });
  const operation = spec.paths[path]?.[method.toLowerCase()];
  expect(operation, `${method} ${path} is not in openapi.json`).toBeDefined();
  covered.add(`${method} ${path}`);

  const declared = operation!.responses[String(res.status)];
  expect(declared, `${method} ${concrete} answered ${res.status}, which openapi.json does not list`).toBeDefined();
  // A response is either inline or a $ref to components/responses; build the JSON pointer to its schema either way.
  const shared = declared!.$ref?.split("/").pop();
  const response = shared ? spec.components.responses[shared]! : declared!;
  const at = shared
    ? `openapi#/components/responses/${shared}`
    : `openapi#/paths/${path.replaceAll("/", "~1")}/${method.toLowerCase()}/responses/${res.status}`;

  if (!response.content) {
    expect(res.headers.get("content-length") ?? "0", `${method} ${path} ${res.status} should have no body`).toBe("0");
    return { res, body: undefined };
  }
  const type = res.headers.get("content-type")!.split(";")[0]!;
  expect(response.content?.[type], `${method} ${path} ${res.status} sent ${type}, which openapi.json does not list`).toBeDefined();

  const body = type.endsWith("json") ? await res.json() : await res.text();
  const schema = `${at}/content/${type.replace("/", "~1")}/schema`;
  const validate = ajv.getSchema(schema)!;
  expect(validate(body), JSON.stringify(validate.errors)).toBe(true);
  return { res, body };
}

const auth = (token: string, body?: string | Buffer, type = "application/json", extra: Record<string, string> = {}) => ({
  headers: { authorization: `Bearer ${token}`, "content-type": type, ...extra },
  ...(body !== undefined && { body }),
});
const admin = (body?: unknown) => auth(ADMIN_TOKEN, body === undefined ? undefined : typeof body === "string" ? body : JSON.stringify(body));
const idOf = (r: { body: unknown }) => (r.body as { id: string }).id;
const inDays = (d: number) => new Date(Date.now() + d * 86_400_000).toISOString();

describe("openapi.json", () => {
  it("has the version of this release", () => {
    expect(spec.info.version).toBe(version);
  });

  it("is served with the running version", async () => {
    const served = (await (await fetch(`${base}/api/openapi.json`)).json()) as Spec;
    expect(served.info.version).toBe(version);
    // threat-intel's own operations, then sign-in from @openasy/auth (tested against its description in that package).
    expect(Object.keys(served.paths).filter((p) => !p.startsWith("/api/v1/auth/"))).toEqual(Object.keys(spec.paths));
    expect(served.paths["/api/v1/auth/login"]).toBeDefined();
  });

  it("serves the API reference at /api/docs/", async () => {
    expect((await fetch(`${base}/api/docs`, { redirect: "manual" })).headers.get("location")).toBe("/api/docs/");
    const res = await fetch(`${base}/api/docs/`);
    expect(res.headers.get("content-type")).toContain("text/html");
    expect((await fetch(`${base}/api/docs/../../package.json`)).status).not.toBe(200);
  });
});

describe("responses match openapi.json", () => {
  let stix = "";
  let manual = "";
  let indicator = "";
  let entry = "";

  it("product and health", async () => {
    await call("GET", "/api/v1/version");
    await call("GET", "/api/v1/products", admin());
    await call("GET", "/api/v1/products");
    await call("GET", "/healthz");
    await call("GET", "/readyz");
    await call("GET", "/metrics");
  });

  it("feeds: add, read, change and every refusal", async () => {
    stix = idOf(await call("POST", "/api/v1/feeds", admin({ name: "OpenCTI", kind: "stix", defaultConfidence: 70 })));
    manual = idOf(await call("POST", "/api/v1/feeds", admin({ name: "Analysts", kind: "manual" })));
    await call("POST", "/api/v1/feeds", admin({ name: "OpenCTI", kind: "stix" }));
    await call("POST", "/api/v1/feeds", admin({ name: "x", kind: "rss" }));
    await call("POST", "/api/v1/feeds", admin("{"));
    await call("POST", "/api/v1/feeds", auth(INGEST_TOKEN, JSON.stringify({ name: "y", kind: "csv" })));
    await call("GET", "/api/v1/feeds", admin());
    await call("GET", "/api/v1/feeds", admin(), "/api/v1/feeds?limit=1");
    await call("GET", "/api/v1/feeds", admin(), "/api/v1/feeds?cursor=nope");
    await call("GET", "/api/v1/feeds/{id}", admin(), `/api/v1/feeds/${stix}`);
    await call("GET", "/api/v1/feeds/{id}", admin(), "/api/v1/feeds/missing");
    await call("PATCH", "/api/v1/feeds/{id}", { ...admin({ defaultTlp: "green" }) }, `/api/v1/feeds/${stix}`);
    await call("PATCH", "/api/v1/feeds/{id}", admin({}), `/api/v1/feeds/${stix}`);
    await call("PATCH", "/api/v1/feeds/{id}", admin({ name: "Analysts" }), `/api/v1/feeds/${stix}`);
    await call("PATCH", "/api/v1/feeds/{id}", admin("["), `/api/v1/feeds/${stix}`);
    await call("PATCH", "/api/v1/feeds/{id}", admin({ name: "z" }), "/api/v1/feeds/missing");
  });

  it("imports, and every refusal", async () => {
    const body = bundle(
      { pattern: "[ipv4-addr:value = '198.51.100.40']", confidence: 90 },
      { pattern: "[network-traffic:dst_port = 443]" },
      { pattern: "[domain-name:value = 'c2.example.org']", tlp: "red" },
    );
    await call(
      "POST",
      "/api/v1/feeds/{id}/import",
      auth(INGEST_TOKEN, gzipSync(body), "application/json", { "content-encoding": "gzip" }),
      `/api/v1/feeds/${stix}/import`,
    );
    await call("POST", "/api/v1/feeds/{id}/import", auth(INGEST_TOKEN, "not json"), `/api/v1/feeds/${stix}/import`);
    await call("POST", "/api/v1/feeds/{id}/import", auth(INGEST_TOKEN, body), `/api/v1/feeds/${manual}/import`);
    await call("POST", "/api/v1/feeds/{id}/import", auth(INGEST_TOKEN, body), "/api/v1/feeds/missing/import");
    await call("POST", "/api/v1/feeds/{id}/import", auth("wrong", body), `/api/v1/feeds/${stix}/import`);
  });

  it("pulls, and every refusal", async () => {
    const text = idOf(await call("POST", "/api/v1/feeds", admin({ name: "Blocklist", kind: "text" })));
    const at = `/api/v1/feeds/${text}/pull`;
    await call("PUT", "/api/v1/feeds/{id}/pull", admin({ url: "https://feeds.example.com/list.txt", everyMinutes: 60 }), at);
    await call("PUT", "/api/v1/feeds/{id}/pull", admin({ url: "https://feeds.example.com/list.txt", auth: "bearer", secret: "t0ken" }), at);
    await call("PUT", "/api/v1/feeds/{id}/pull", admin({ url: "nope" }), at);
    await call("PUT", "/api/v1/feeds/{id}/pull", admin("{"), at);
    await call("PUT", "/api/v1/feeds/{id}/pull", admin({ url: "https://feeds.example.com/x" }), `/api/v1/feeds/${manual}/pull`);
    await call("PUT", "/api/v1/feeds/{id}/pull", admin({ url: "https://feeds.example.com/x" }), "/api/v1/feeds/missing/pull");
    await call("POST", "/api/v1/feeds/{id}/pull/run", admin(), `${at}/run`);
    await call("GET", "/api/v1/feeds/{id}", admin(), `/api/v1/feeds/${text}`);
    await call("PUT", "/api/v1/feeds/{id}/pull", admin({ url: "https://feeds.example.com/down" }), at);
    await call("POST", "/api/v1/feeds/{id}/pull/run", admin(), `${at}/run`);
    await call("GET", "/api/v1/feeds", admin());
    await call("POST", "/api/v1/feeds/{id}/pull/run", admin(), `/api/v1/feeds/${manual}/pull/run`);
    await call("DELETE", "/api/v1/feeds/{id}/pull", admin(), at);
    await call("DELETE", "/api/v1/feeds/{id}/pull", admin(), at);
    await call("DELETE", "/api/v1/feeds/{id}/pull", { method: "DELETE" }, at);
  });

  it("indicators", async () => {
    indicator = idOf(
      await call("POST", "/api/v1/indicators", admin({ feed: manual, value: "hxxps://phish[.]example.net/login", severity: "high", labels: ["phishing"] })),
    );
    await call("POST", "/api/v1/indicators", admin({ feed: manual, value: "1.2.3.4", type: "domain" }));
    await call("POST", "/api/v1/indicators", admin({ feed: stix, value: "198.51.100.41" }));
    await call("POST", "/api/v1/indicators", admin({ feed: "missing", value: "198.51.100.41" }));
    await call("POST", "/api/v1/indicators", admin("{"));
    await call("GET", "/api/v1/indicators", admin());
    await call("GET", "/api/v1/indicators", admin(), "/api/v1/indicators?status=all&type=domain&tlp=red&q=example&limit=1");
    await call("GET", "/api/v1/indicators", admin(), "/api/v1/indicators?status=gone");
    await call("GET", "/api/v1/indicators/{id}", admin(), `/api/v1/indicators/${indicator}`);
    await call("GET", "/api/v1/indicators/{id}", admin(), "/api/v1/indicators/missing");
  });

  it("lookups, one and many, with the ingest token and without", async () => {
    await call("GET", "/api/v1/lookup", auth(INGEST_TOKEN), "/api/v1/lookup?value=198.51.100.40");
    await call("GET", "/api/v1/lookup", admin(), "/api/v1/lookup?value=c2.example.org&type=domain");
    await call("GET", "/api/v1/lookup", admin(), "/api/v1/lookup?value=nothing.example.com");
    await call("GET", "/api/v1/lookup", admin(), "/api/v1/lookup");
    await call("GET", "/api/v1/lookup", admin(), "/api/v1/lookup?value=what");
    await call("GET", "/api/v1/lookup", {}, "/api/v1/lookup?value=198.51.100.40");
    await call(
      "POST",
      "/api/v1/lookup",
      auth(INGEST_TOKEN, JSON.stringify({ items: [{ value: "198.51.100.40" }, { value: "https://phish.example.net/login", type: "url" }] })),
    );
    await call("POST", "/api/v1/lookup", admin({ items: [] }));
    await call("POST", "/api/v1/lookup", admin({ items: [{ value: "198.51.100.0/24", type: "cidr" }] }));
    await call("POST", "/api/v1/lookup", admin("{"));
  });

  it("the allow list", async () => {
    entry = idOf(await call("POST", "/api/v1/allow-list", admin({ value: "198.51.100.40", reason: "Our own scanner", expiresAt: inDays(30) })));
    await call("GET", "/api/v1/lookup", admin(), "/api/v1/lookup?value=198.51.100.40");
    await call("POST", "/api/v1/allow-list", admin({ value: "198.51.100.40", reason: "Again", expiresAt: inDays(30) }));
    await call("POST", "/api/v1/allow-list", admin({ value: "198.51.100.42", reason: "x", expiresAt: inDays(30) }));
    await call("POST", "/api/v1/allow-list", admin("{"));
    await call("GET", "/api/v1/allow-list", admin());
    await call("GET", "/api/v1/allow-list", admin(), "/api/v1/allow-list?limit=0");
    await call("GET", "/api/v1/summary", admin());
    await call("GET", "/api/v1/overview", admin());
  });

  it("deletes", async () => {
    await call("DELETE", "/api/v1/allow-list/{id}", admin(), `/api/v1/allow-list/${entry}`);
    await call("DELETE", "/api/v1/allow-list/{id}", admin(), `/api/v1/allow-list/${entry}`);
    await call("DELETE", "/api/v1/indicators/{id}", admin(), `/api/v1/indicators/${indicator}`);
    await call("DELETE", "/api/v1/indicators/{id}", admin(), `/api/v1/indicators/${indicator}`);
    await call("DELETE", "/api/v1/feeds/{id}", admin(), `/api/v1/feeds/${stix}`);
    await call("DELETE", "/api/v1/feeds/{id}", admin(), `/api/v1/feeds/${stix}`);
    await call("DELETE", "/api/v1/feeds/{id}", { method: "DELETE" }, "/api/v1/feeds/x");
  });

  it("covers every operation in openapi.json", () => {
    const all = Object.entries(spec.paths).flatMap(([path, ops]) => Object.keys(ops).map((m) => `${m.toUpperCase()} ${path}`));
    expect([...covered].sort()).toEqual(all.sort());
  });
});
