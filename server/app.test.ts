import { gzipSync } from "node:zlib";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { bundle, startApp } from "./test-app.ts";

let app: Awaited<ReturnType<typeof startApp>>;
beforeAll(async () => {
  app = await startApp({ version: "0.1.0" });
});
afterAll(() => app.close());

const json = async (res: Response) => (await res.json()) as any;
const inDays = (d: number) => new Date(Date.now() + d * 86_400_000).toISOString();
const lookup = async (...values: string[]) =>
  (await json(await app.ingest("/api/v1/lookup", { method: "POST", body: JSON.stringify({ items: values.map((value) => ({ value })) }) }))).results as any[];

describe("feeds", () => {
  it("creates feeds with defaults and refuses what is wrong", async () => {
    const res = await app.post("/api/v1/feeds", { name: "Abuse list", kind: "text" });
    expect(res.status).toBe(201);
    expect(await json(res)).toMatchObject({
      name: "Abuse list",
      kind: "text",
      defaultTtlDays: 30,
      defaultConfidence: 50,
      defaultTlp: "amber",
      defaultSeverity: "medium",
      indicators: { total: 0, active: 0 },
      lastImportAt: null,
    });
    expect((await app.post("/api/v1/feeds", { name: "Abuse list", kind: "csv" })).status).toBe(409);
    for (const bad of [
      { name: "x", kind: "rss" },
      { name: "-x", kind: "csv" },
      { name: "x", kind: "csv", defaultTtlDays: 0 },
      { name: "x", kind: "csv", defaultConfidence: 101 },
      { name: "x", kind: "csv", defaultTlp: "blue" },
      { name: "x", kind: "csv", extra: 1 },
    ]) {
      expect((await app.post("/api/v1/feeds", bad)).status, JSON.stringify(bad)).toBe(422);
    }
  });

  it("changes and deletes a feed", async () => {
    const id = await app.feed("Changing", "csv");
    const patch = (body: unknown) => app.admin(`/api/v1/feeds/${id}`, { method: "PATCH", body: JSON.stringify(body) });
    expect(await json(await patch({ defaultTlp: "green", name: "Changed" }))).toMatchObject({ name: "Changed", defaultTlp: "green", kind: "csv" });
    expect((await patch({})).status).toBe(422);
    expect((await patch({ kind: "text" })).status).toBe(422);
    expect((await patch({ name: "Abuse list" })).status).toBe(409);
    expect((await app.admin(`/api/v1/feeds/${id}`, { method: "DELETE" })).status).toBe(204);
    expect((await app.admin(`/api/v1/feeds/${id}`)).status).toBe(404);
  });
});

describe("importing", () => {
  it("imports a STIX bundle with the ingest token, gzipped, and reports what it could not read", async () => {
    const id = await app.feed("OpenCTI", "stix", { defaultConfidence: 40 });
    const body = bundle(
      { pattern: "[ipv4-addr:value = '198.51.100.40']", confidence: 90, tlp: "amber" },
      { pattern: "[domain-name:value = 'c2.example.org' OR url:value = 'https://c2.example.org/gate.php']", labels: ["c2"] },
      { pattern: "[network-traffic:dst_port = 443]" },
    );
    const res = await app.ingest(`/api/v1/feeds/${id}/import`, { method: "POST", body: gzipSync(body), headers: { "content-encoding": "gzip" } });
    expect(res.status).toBe(200);
    const r = await json(res);
    expect(r).toMatchObject({
      feed: { name: "OpenCTI" },
      received: 3,
      created: 3,
      updated: 0,
      unparsedCount: 1,
      unparsed: [{ reason: expect.stringContaining("network-traffic") }],
    });
    const [hit, c2, gate] = await lookup("198.51.100.40", "c2.example.org", "https://c2.example.org/gate.php");
    expect(hit).toMatchObject({ verdict: "malicious", confidence: 90, tlp: "amber" });
    expect(c2).toMatchObject({ verdict: "suspicious", confidence: 40 });
    expect(gate.verdict).toBe("suspicious");
  });

  it("imports a text list and a CSV, and refuses what is not importable", async () => {
    const text = await app.feed("Plain", "text");
    expect(
      await json(
        await app.ingest(`/api/v1/feeds/${text}/import`, {
          method: "POST",
          body: "# list\n198.51.100.50\nbad-line\n",
          headers: { "content-type": "text/plain" },
        }),
      ),
    ).toMatchObject({ created: 1, skippedCount: 1 });
    const csv = await app.feed("Sheet", "csv");
    expect(await json(await app.ingest(`/api/v1/feeds/${csv}/import`, { method: "POST", body: "value,confidence\n198.51.100.51,75\n" }))).toMatchObject({
      created: 1,
    });
    expect((await lookup("198.51.100.51"))[0]).toMatchObject({ verdict: "malicious", confidence: 75 });
    const manual = await app.feed("By hand", "manual");
    expect((await app.ingest(`/api/v1/feeds/${manual}/import`, { method: "POST", body: "198.51.100.52" })).status).toBe(409);
    expect((await app.ingest(`/api/v1/feeds/${csv}/import`, { method: "POST", body: "ip\n1.2.3.4\n" })).status).toBe(422);
    expect((await app.ingest("/api/v1/feeds/missing/import", { method: "POST", body: "x" })).status).toBe(404);
    expect((await app.ingest(`/api/v1/feeds/${text}/import`, { method: "POST", body: "x", headers: { "content-encoding": "br" } })).status).toBe(400);
  });
});

describe("indicators", () => {
  it("adds one by hand, finds it, lists it with filters and deletes it", async () => {
    const feed = await app.feed("Analysts", "manual", { defaultConfidence: 65 });
    const res = await app.post("/api/v1/indicators", {
      feed,
      value: "hxxp://phish[.]example.com/login",
      labels: ["phishing"],
      description: "Seen in a ticket",
      validUntil: inDays(10),
    });
    expect(res.status).toBe(201);
    const ind = await json(res);
    expect(ind).toMatchObject({
      type: "url",
      value: "http://phish.example.com/login",
      confidence: 65,
      active: true,
      labels: ["phishing"],
      feed: { name: "Analysts" },
    });
    expect((await lookup("http://phish.example.com/login"))[0].verdict).toBe("malicious");
    expect((await json(await app.admin(`/api/v1/indicators/${ind.id}`))).value).toBe(ind.value);
    const list = (q: string) => app.admin(`/api/v1/indicators?${q}`).then(json);
    expect((await list("type=url")).indicators.map((i: { id: string }) => i.id)).toContain(ind.id);
    expect((await list(`feed=${feed}&q=phish`)).indicators).toHaveLength(1);
    expect((await list("q=%25")).indicators).toEqual([]);
    expect((await list("limit=1")).nextCursor).toBeDefined();
    for (const q of ["type=nope", "tlp=blue", "severity=urgent", "status=gone", "limit=0", "cursor=junk"])
      expect((await app.admin(`/api/v1/indicators?${q}`)).status, q).toBe(422);
    expect((await app.admin(`/api/v1/indicators/${ind.id}`, { method: "DELETE" })).status).toBe(204);
    expect((await app.admin(`/api/v1/indicators/${ind.id}`)).status).toBe(404);
  });

  it("refuses what it cannot store", async () => {
    const manual = await app.feed("Strict", "manual");
    const csv = await app.feed("Not manual", "csv");
    for (const [body, status] of [
      [{ feed: manual, value: "what is this" }, 422],
      [{ feed: manual, value: "1.2.3.4", type: "domain" }, 422],
      [{ feed: manual, value: "198.51.100.60", confidence: 101 }, 422],
      [{ feed: manual, value: "198.51.100.60", tlp: "pink" }, 422],
      [{ feed: manual, value: "198.51.100.60", validFrom: inDays(2), validUntil: inDays(1) }, 422],
      [{ feed: manual, value: "198.51.100.60", extra: 1 }, 422],
      [{ feed: csv, value: "198.51.100.60" }, 409],
      [{ feed: "missing", value: "198.51.100.60" }, 404],
      [{ value: "198.51.100.60" }, 422],
    ] as const) {
      expect((await app.post("/api/v1/indicators", body)).status, JSON.stringify(body)).toBe(status);
    }
  });
});

describe("lookup", () => {
  it("answers one value over GET and many over POST", async () => {
    const f = await app.feed("Lookups", "manual");
    await app.post("/api/v1/indicators", { feed: f, value: "198.51.100.0/24", confidence: 80, severity: "high" });
    const one = await json(await app.ingest("/api/v1/lookup?value=198.51.100.99"));
    expect(one).toMatchObject({
      type: "ipv4",
      value: "198.51.100.99",
      verdict: "malicious",
      severity: "high",
      matches: [{ via: "cidr", value: "198.51.100.0/24" }],
    });
    expect((await json(await app.ingest("/api/v1/lookup?value=203.0.113.1&type=ipv4"))).verdict).toBe("unknown");
    const many = await lookup("198.51.100.1", "203.0.113.2", "Example.COM.");
    expect(many.map((r) => r.verdict)).toEqual(["malicious", "unknown", "unknown"]);
    expect(many[2].value).toBe("example.com");
  });

  it("refuses bad requests", async () => {
    const post = (body: unknown) => app.ingest("/api/v1/lookup", { method: "POST", body: JSON.stringify(body) });
    expect((await app.ingest("/api/v1/lookup")).status).toBe(422);
    expect((await app.ingest("/api/v1/lookup?value=zzz")).status).toBe(422);
    expect((await app.ingest("/api/v1/lookup?value=198.51.100.0/24&type=cidr")).status).toBe(422);
    expect((await post({ items: [] })).status).toBe(422);
    expect((await post({ items: Array.from({ length: 1001 }, () => ({ value: "198.51.100.1" })) })).status).toBe(422);
    expect((await post({ items: [{ value: 5 }] })).status).toBe(422);
    expect((await post({ items: [{ value: "198.51.100.1" }], extra: 1 })).status).toBe(422);
    expect((await post({ items: [{ value: "198.51.100.1" }, { value: "nope" }] })).status).toBe(422);
  });

  it("counts lookups and hits in the metrics", async () => {
    const metrics = await (await fetch(`${app.base}/metrics`)).text();
    expect(metrics).toMatch(/openasy_threat_intel_lookups_total [1-9]/);
    expect(metrics).toMatch(/openasy_threat_intel_lookup_hits_total [1-9]/);
    expect(metrics).toContain('openasy_threat_intel_indicators{type="ipv4"}');
    expect(metrics).toContain('openasy_build_info{product="threat-intel",version="0.1.0"} 1');
  });
});

describe("allow list", () => {
  it("overrides indicators, records who and why, and can be removed", async () => {
    const res = await app.post("/api/v1/allow-list", { value: "198.51.100.0/25", reason: "Our own egress addresses", expiresAt: inDays(90) });
    expect(res.status).toBe(201);
    const entry = await json(res);
    expect(entry).toMatchObject({ type: "cidr", value: "198.51.100.0/25", by: "admin token", active: true });
    expect((await lookup("198.51.100.1"))[0]).toMatchObject({ verdict: "allowed", allowed: { reason: "Our own egress addresses" } });
    expect((await lookup("198.51.100.200"))[0].verdict).toBe("malicious");
    expect((await json(await app.admin("/api/v1/allow-list"))).entries).toHaveLength(1);
    for (const bad of [
      { value: "198.51.100.0/25", reason: "again", expiresAt: inDays(5) },
      { value: "198.51.100.9", reason: "", expiresAt: inDays(5) },
      { value: "198.51.100.9", reason: "fine", expiresAt: inDays(-1) },
      { value: "198.51.100.9", reason: "fine" },
    ]) {
      expect((await app.post("/api/v1/allow-list", bad)).status, JSON.stringify(bad)).toBeGreaterThanOrEqual(409);
    }
    expect((await app.admin(`/api/v1/allow-list/${entry.id}`, { method: "DELETE" })).status).toBe(204);
    expect((await app.admin(`/api/v1/allow-list/${entry.id}`, { method: "DELETE" })).status).toBe(404);
    expect((await lookup("198.51.100.1"))[0].verdict).toBe("malicious");
  });
});

describe("access", () => {
  it("lets the ingest token import and look up, and nothing else", async () => {
    for (const [method, path] of [
      ["GET", "/api/v1/feeds"],
      ["GET", "/api/v1/indicators"],
      ["GET", "/api/v1/allow-list"],
      ["GET", "/api/v1/summary"],
      ["POST", "/api/v1/feeds"],
      ["POST", "/api/v1/indicators"],
      ["POST", "/api/v1/allow-list"],
    ] as const) {
      expect((await app.ingest(path, { method, body: method === "POST" ? "{}" : undefined })).status, `${method} ${path}`).toBe(401);
    }
    const anon = (path: string, init: RequestInit = {}) => fetch(app.base + path, init);
    expect((await anon("/api/v1/lookup?value=198.51.100.1")).status).toBe(401);
    expect((await anon("/api/v1/feeds/x/import", { method: "POST", body: "x" })).status).toBe(401);
    expect((await anon("/api/v1/lookup?value=198.51.100.1", { headers: { authorization: "Bearer nope" } })).status).toBe(401);
    const closed = await startApp({ version: "0.1.0", ingestToken: undefined, adminToken: undefined });
    expect((await fetch(`${closed.base}/api/v1/feeds/x/import`, { method: "POST", body: "x" })).status).toBe(503);
    await closed.close();
  });

  it("shows the overview and answers health and version", async () => {
    expect(await json(await app.admin("/api/v1/summary"))).toMatchObject({
      feeds: expect.any(Number),
      indicators: { active: expect.any(Number) },
      lookups: { total: expect.any(Number) },
    });
    expect(await json(await fetch(`${app.base}/api/v1/version`))).toEqual({ product: "threat-intel", version: "0.1.0" });
    expect((await fetch(`${app.base}/healthz`)).status).toBe(200);
    expect((await fetch(`${app.base}/readyz`)).status).toBe(200);
  });
});
