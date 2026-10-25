import { randomBytes } from "node:crypto";
import { createServer, type IncomingMessage, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { afterEach, describe, expect, it } from "vitest";
import { openDb } from "./db.ts";
import { createIntel, IntelError } from "./intel.ts";
import { createKeyring } from "./kek.ts";
import { createPuller } from "./pull.ts";
import { bundle } from "./test-app.ts";

type Handler = (req: IncomingMessage, url: URL) => { status?: number; headers?: Record<string, string>; body: string };

let server: Server | undefined;
afterEach(() => new Promise<void>((resolve) => (server ? server.close(() => resolve()) : resolve())));

/** A feed server on a random port; every request is kept for the test to read. */
async function serve(handle: Handler) {
  const requests: Array<{ url: URL; headers: IncomingMessage["headers"] }> = [];
  server = createServer((req, res) => {
    const url = new URL(req.url ?? "/", "http://localhost");
    requests.push({ url, headers: req.headers });
    const r = handle(req, url);
    res.writeHead(r.status ?? 200, r.headers ?? {}).end(r.body);
  });
  await new Promise<void>((resolve) => server!.listen(0, resolve));
  return { base: `http://localhost:${(server.address() as AddressInfo).port}`, requests };
}

function setup(opts: { fetch?: typeof fetch; keyring?: boolean } = {}) {
  const db = openDb(":memory:");
  const intel = createIntel(db);
  const logs: Array<{ msg: string; fields?: Record<string, unknown> }> = [];
  const puller = createPuller({
    db,
    intel,
    keyring: opts.keyring === false ? undefined : createKeyring(randomBytes(32)),
    version: "1.2.3",
    log: (_level, msg, fields) => logs.push({ msg, fields }),
    fetch: opts.fetch,
  });
  const feed = (name: string, kind: "stix" | "csv" | "text" | "manual") => intel.createFeed({ name, kind }).id;
  return { db, intel, puller, feed, logs };
}

const verdict = (intel: ReturnType<typeof createIntel>, value: string) => intel.lookup([{ value }], { role: "admin" })[0]!.verdict;

describe("pulling a feed from a URL", () => {
  it("reads the whole feed in its kind and says what it left out", async () => {
    const { base, requests } = await serve(() => ({ headers: { "content-type": "text/plain" }, body: "# a blocklist\n198.51.100.7\nnot an address!\n" }));
    const { intel, puller, feed } = setup();
    const id = feed("Blocklist", "text");
    puller.set(id, { url: `${base}/list.txt`, everyMinutes: 60 });
    expect(await puller.run(id)).toEqual({ received: 2, created: 1, updated: 0, revoked: 0, leftOut: 1, more: false });
    expect(verdict(intel, "198.51.100.7")).toBe("suspicious");
    expect(requests[0]!.headers["user-agent"]).toBe("OpenAsy-Threat-Intel/1.2.3");
    expect(requests[0]!.headers.authorization).toBeUndefined();
    const pull = intel.feed(id).pull!;
    expect(pull).toMatchObject({ source: "url", auth: "none", everyMinutes: 60, lastError: null, lastResult: { created: 1, leftOut: 1 } });
    expect(Date.parse(pull.nextAt) - Date.parse(pull.lastAttemptAt!)).toBe(60 * 60_000);
    expect(intel.feed(id).lastImportAt).not.toBeNull();
  });

  it("keeps why a pull failed, and the indicators it had", async () => {
    let up = true;
    const { base } = await serve(() => (up ? { body: "198.51.100.8\n" } : { status: 500, body: "down" }));
    const { intel, puller, feed } = setup();
    const id = feed("Blocklist", "text");
    puller.set(id, { url: `${base}/list.txt` });
    await puller.run(id);
    up = false;
    const err = await puller.run(id).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(IntelError);
    expect(err).toMatchObject({ status: 502, code: "pull-failed", message: `${base}/list.txt answered 500` });
    expect(intel.feed(id).pull).toMatchObject({ lastError: `${base}/list.txt answered 500` });
    expect(intel.summary().pulls).toEqual({ ok: 0, failing: 1 });
    expect(verdict(intel, "198.51.100.8")).toBe("suspicious");
  });
});

describe("pulling a STIX feed from a TAXII 2.1 collection", () => {
  it("reads page by page, and starts the next pull where the last one stopped", async () => {
    const { base, requests } = await serve((_req, url) => {
      const objects = (b: string) => (JSON.parse(b) as { objects: unknown[] }).objects;
      if (url.searchParams.get("added_after") === "2026-10-20T10:00:00.000Z") return { body: JSON.stringify({ more: false }) };
      if (url.searchParams.get("next") === "page-2")
        return {
          headers: { "content-type": "application/taxii+json;version=2.1", "x-taxii-date-added-last": "2026-10-20T10:00:00.000Z" },
          body: JSON.stringify({ more: false, objects: objects(bundle({ pattern: "[domain-name:value = 'c2.example.org']", confidence: 80 })) }),
        };
      return {
        headers: { "content-type": "application/taxii+json;version=2.1", "x-taxii-date-added-last": "2026-10-20T09:00:00.000Z" },
        body: JSON.stringify({
          more: true,
          next: "page-2",
          objects: objects(bundle({ pattern: "[ipv4-addr:value = '198.51.100.9']", confidence: 90 }, { pattern: "[network-traffic:dst_port = 443]" })),
        }),
      };
    });
    const { intel, puller, feed } = setup();
    const id = feed("OpenCTI", "stix");
    puller.set(id, { url: `${base}/api1/collections/91a7b528`, everyMinutes: 15 });
    expect(intel.feed(id).pull).toMatchObject({ source: "taxii", url: `${base}/api1/collections/91a7b528` });
    expect(await puller.run(id)).toEqual({ received: 3, created: 2, updated: 0, revoked: 0, leftOut: 1, more: false });
    expect(verdict(intel, "198.51.100.9")).toBe("malicious");
    expect(verdict(intel, "c2.example.org")).toBe("malicious");
    expect(requests[0]!.url.pathname).toBe("/api1/collections/91a7b528/objects/");
    expect(requests[0]!.headers.accept).toBe("application/taxii+json;version=2.1");
    // The second page repeats the first one's filter, with next.
    expect(requests[1]!.url.searchParams.has("added_after")).toBe(false);
    expect(requests[1]!.url.searchParams.get("next")).toBe("page-2");

    expect(await puller.run(id)).toMatchObject({ received: 0 });
    expect(requests[2]!.url.searchParams.get("added_after")).toBe("2026-10-20T10:00:00.000Z");
    expect(requests[2]!.url.searchParams.has("next")).toBe(false);
  });

  it("names the server's own reason when it refuses", async () => {
    const { base } = await serve(() => ({ status: 403, body: JSON.stringify({ title: "Forbidden", description: "No read access to this collection" }) }));
    const { puller, feed } = setup();
    const id = feed("OpenCTI", "stix");
    puller.set(id, { url: `${base}/api1/collections/x/` });
    await expect(puller.run(id)).rejects.toThrow(`${base}/api1/collections/x/objects/ answered 403 (Forbidden: No read access to this collection)`);
  });

  it("carries on at the next minute when a collection has more than one pull reads", async () => {
    let page = 0;
    const { base } = await serve(() => ({
      headers: { "x-taxii-date-added-last": new Date(Date.UTC(2026, 9, 20, 0, page)).toISOString() },
      body: JSON.stringify({ more: true, next: `p${++page}`, objects: JSON.parse(bundle({ pattern: `[ipv4-addr:value = '198.51.100.${page}']` })).objects }),
    }));
    const { intel, puller, feed } = setup();
    const id = feed("Big", "stix");
    puller.set(id, { url: `${base}/c/` });
    expect(await puller.run(id)).toMatchObject({ more: true, created: 20 });
    expect(Date.parse(intel.feed(id).pull!.nextAt)).toBeLessThanOrEqual(Date.now());
  });
});

describe("where a feed is pulled from", () => {
  it("refuses what cannot be pulled, or would send a secret in clear", () => {
    const { puller, feed } = setup();
    const manual = feed("Analysts", "manual");
    const text = feed("Blocklist", "text");
    expect(() => puller.set(manual, { url: "https://feeds.example.com/x" })).toThrow(/manual feed/);
    expect(() => puller.set(text, { source: "taxii", url: "https://taxii.example.com/c/" })).toThrow(/Only a STIX feed/);
    expect(() => puller.set(text, { url: "ftp://feeds.example.com/x" })).toThrow(/https/);
    expect(() => puller.set(text, { url: "https://user:pw@feeds.example.com/x" })).toThrow(/username and secret/);
    expect(() => puller.set(text, { url: "http://feeds.example.com/x", auth: "bearer", secret: "t" })).toThrow(/only sent over https/);
    expect(() => puller.set(text, { url: "https://feeds.example.com/x", everyMinutes: 5 })).toThrow(/everyMinutes/);
    expect(() => puller.set(text, { url: "https://feeds.example.com/x", auth: "basic", secret: "pw" })).toThrow(/username/);
    expect(() => puller.set(text, { url: "https://feeds.example.com/x", auth: "bearer" })).toThrow(/secret is the token/);
    expect(() => puller.set(text, { url: "https://feeds.example.com/x", extra: 1 })).toThrow(/Expected/);
  });

  it("keeps no password or token without openasy-kek", () => {
    const { puller, feed } = setup({ keyring: false });
    const id = feed("Blocklist", "text");
    expect(() => puller.set(id, { url: "https://feeds.example.com/x", auth: "bearer", secret: "t" })).toThrow(/openasy-kek/);
    expect(puller.set(id, { url: "https://feeds.example.com/x" }).auth).toBe("none");
  });

  it("sends the credentials, keeps them sealed, and asks for them again when the address moves", async () => {
    const seen: Array<{ url: string; authorization?: string }> = [];
    const fake = (async (url: string | URL, init: RequestInit) => {
      seen.push({ url: String(url), authorization: (init.headers as Record<string, string>).authorization });
      return new Response("198.51.100.10\n");
    }) as typeof fetch;
    const { db, puller, feed, intel } = setup({ fetch: fake });
    const id = feed("Paid", "text");
    puller.set(id, { url: "https://feeds.example.com/x", auth: "basic", username: "openasy", secret: "s3cret" });
    await puller.run(id);
    expect(seen[0]!.authorization).toBe(`Basic ${Buffer.from("openasy:s3cret").toString("base64")}`);
    expect(JSON.stringify(intel.feed(id))).not.toContain("s3cret");
    expect(JSON.stringify(db.prepare("SELECT * FROM feed_pulls").all())).not.toContain("s3cret");

    // Changing how often keeps the password; another origin needs it again.
    expect(puller.set(id, { url: "https://feeds.example.com/x", auth: "basic", username: "openasy", everyMinutes: 1440 }).everyMinutes).toBe(1440);
    await puller.run(id);
    expect(seen[1]!.authorization).toBe(seen[0]!.authorization);
    expect(() => puller.set(id, { url: "https://elsewhere.example.net/x", auth: "basic", username: "openasy" })).toThrow(/secret is the password/);

    puller.set(id, { url: "https://feeds.example.com/x", auth: "bearer", secret: "tok" });
    await puller.run(id);
    expect(seen[2]!.authorization).toBe("Bearer tok");
  });

  it("is removed with its feed, and on its own", () => {
    const { db, intel, puller, feed } = setup();
    const id = feed("Blocklist", "text");
    puller.set(id, { url: "https://feeds.example.com/x" });
    puller.remove(id);
    expect(intel.feed(id).pull).toBeNull();
    expect(() => puller.remove(id)).toThrow(/not pulled/);
    puller.set(id, { url: "https://feeds.example.com/x" });
    intel.deleteFeed(id);
    expect(db.prepare("SELECT COUNT(*) AS n FROM feed_pulls").get()).toEqual({ n: 0 });
  });
});

describe("the schedule", () => {
  it("pulls the feeds that are due, and leaves the others until they are", async () => {
    const pulled: string[] = [];
    const fake = (async (url: string | URL) => (pulled.push(String(url)), new Response("198.51.100.11\n"))) as typeof fetch;
    const { db, puller, feed } = setup({ fetch: fake });
    const a = feed("A", "text");
    const b = feed("B", "text");
    puller.set(a, { url: "https://feeds.example.com/a", everyMinutes: 15 });
    puller.set(b, { url: "https://feeds.example.com/b", everyMinutes: 60 });
    await puller.tick();
    expect(pulled).toEqual(["https://feeds.example.com/a", "https://feeds.example.com/b"]);
    await puller.tick();
    expect(pulled).toHaveLength(2);
    // A was last tried 20 minutes ago: due again. B is not.
    db.prepare("UPDATE feed_pulls SET last_attempt_at = ?").run(new Date(Date.now() - 20 * 60_000).toISOString());
    await puller.tick();
    expect(pulled.slice(2)).toEqual(["https://feeds.example.com/a"]);
  });
});
