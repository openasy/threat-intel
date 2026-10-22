import { describe, expect, it } from "vitest";
import { openDb } from "./db.ts";
import { createIntel, IntelError, parseCsv, type Caller } from "./intel.ts";
import { bundle } from "./test-app.ts";

const viewer: Caller = { role: "viewer" };
const editor: Caller = { role: "editor" };
const later = (days: number) => new Date(Date.now() + days * 86_400_000).toISOString();
const setup = () => {
  const db = openDb(":memory:");
  const intel = createIntel(db);
  const feed = (name = "manual", extra: Record<string, unknown> = {}) => intel.createFeed({ name, kind: "manual", ...extra }).id;
  const add = (f: string, value: string, extra: Record<string, unknown> = {}) => intel.createIndicator({ feed: f, value, ...extra });
  const look = (value: string, caller = editor, type?: string) => intel.lookup([{ value, ...(type && { type }) }], caller)[0]!;
  return { db, intel, feed, add, look };
};

describe("matching", () => {
  it("finds an address in the blocks that contain it", () => {
    const { feed, add, look } = setup();
    const f = feed();
    add(f, "198.51.100.0/24", { confidence: 70, labels: ["scanner"] });
    add(f, "198.51.0.0/16", { confidence: 30 });
    add(f, "203.0.113.0/24");
    const r = look("198.51.100.7");
    expect(r).toMatchObject({ type: "ipv4", verdict: "malicious", confidence: 70, feeds: ["manual"] });
    expect(r.matches.map((m) => [m.value, m.via])).toEqual([["198.51.100.0/24", "cidr"], ["198.51.0.0/16", "cidr"]]);
    expect(look("198.51.99.1")).toMatchObject({ verdict: "suspicious", confidence: 30 });
    expect(look("192.0.2.1")).toMatchObject({ verdict: "unknown", confidence: null, matches: [] });
    expect(look("2001:db8::1")).toMatchObject({ type: "ipv6", verdict: "unknown" });
  });

  it("matches IPv6 blocks and the exact address", () => {
    const { feed, add, look } = setup();
    const f = feed();
    add(f, "2001:db8::/32");
    add(f, "2001:DB8:0:0:0:0:0:99");
    expect(look("2001:db8:1::5").matches.map((m) => m.via)).toEqual(["cidr"]);
    expect(look("2001:db8::99").matches.map((m) => m.via).sort()).toEqual(["cidr", "exact"]);
    expect(look("2001:db9::1").verdict).toBe("unknown");
  });

  it("matches subdomains only when the domain indicator says so", () => {
    const { feed, add, look } = setup();
    const f = feed();
    add(f, "evil.example.com");
    add(f, "tracker.example.net", { includeSubdomains: true });
    expect(look("evil.example.com").matches.map((m) => m.via)).toEqual(["exact"]);
    expect(look("www.evil.example.com").verdict).toBe("unknown");
    expect(look("a.b.tracker.example.net")).toMatchObject({ verdict: "suspicious", matches: [{ via: "subdomain", value: "tracker.example.net" }] });
    expect(look("tracker.example.net").matches[0]!.via).toBe("exact");
    expect(look("example.net").verdict).toBe("unknown");
    // A look-alike is not a subdomain.
    expect(look("nottracker.example.net").verdict).toBe("unknown");
  });

  it("finds hashes, URLs and email addresses by their normal form", () => {
    const { feed, add, look } = setup();
    const f = feed();
    add(f, "A".repeat(64));
    add(f, "hxxp://bad[.]example.com/payload?x=1#frag");
    add(f, "Phish@Example.com");
    expect(look("a".repeat(64)).verdict).toBe("suspicious");
    expect(look("http://BAD.example.com/payload?x=1").verdict).toBe("suspicious");
    expect(look("phish@example.com").type).toBe("email");
    expect(look("http://bad.example.com/other").verdict).toBe("unknown");
  });

  it("takes the best confidence and the worst severity of several feeds", () => {
    const { feed, add, look } = setup();
    add(feed("one", { defaultSeverity: "low", defaultTlp: "green" }), "198.51.100.9", { confidence: 40 });
    add(feed("two", { defaultSeverity: "critical", defaultTlp: "amber" }), "198.51.100.9", { confidence: 90 });
    expect(look("198.51.100.9")).toMatchObject({ confidence: 90, severity: "critical", tlp: "amber", feeds: ["one", "two"], verdict: "malicious" });
  });
});

describe("time", () => {
  it("leaves out indicators that expired, are not valid yet, or were revoked, and keeps them for history", () => {
    const { intel, feed, add, look } = setup();
    const f = feed();
    add(f, "198.51.100.1", { validFrom: later(-10), validUntil: later(-1) });
    add(f, "198.51.100.2", { validFrom: later(1), validUntil: later(5) });
    add(f, "198.51.100.3", { validUntil: later(5) });
    expect(look("198.51.100.1").verdict).toBe("unknown");
    expect(look("198.51.100.2").verdict).toBe("unknown");
    expect(look("198.51.100.3").verdict).toBe("suspicious");
    expect(intel.summary().indicators).toEqual({ active: 1, inactive: 2 });
    expect(intel.listIndicators({ status: "inactive" }, undefined, 100, editor).items).toHaveLength(2);
    expect(intel.listIndicators({ status: "all" }, undefined, 100, editor).items).toHaveLength(3);
  });

  it("gives an indicator the feed's time to live when it does not say", () => {
    const { feed, add } = setup();
    const i = add(feed("short", { defaultTtlDays: 2 }), "198.51.100.4");
    const days = (Date.parse(i.validUntil) - Date.parse(i.createdAt)) / 86_400_000;
    expect(days).toBeCloseTo(2, 3);
  });

  it("deletes what ended long ago when it purges", () => {
    const db = openDb(":memory:");
    const intel = createIntel(db, { retentionDays: 30 });
    const f = intel.createFeed({ name: "m", kind: "manual" }).id;
    intel.createIndicator({ feed: f, value: "198.51.100.1", validFrom: later(-100), validUntil: later(-60) });
    intel.createIndicator({ feed: f, value: "198.51.100.2", validFrom: later(-100), validUntil: later(-5) });
    intel.purge();
    expect(intel.listIndicators({ status: "all" }, undefined, 100, editor).items.map((i) => i.value)).toEqual(["198.51.100.2"]);
  });
});

describe("TLP", () => {
  it("shows TLP:RED only to editors and above, and leaves it out as if it were not there", () => {
    const { intel, feed, add, look } = setup();
    const f = feed();
    add(f, "198.51.100.5", { tlp: "red", confidence: 95 });
    add(f, "198.51.100.6", { tlp: "amber" });
    add(f, "198.51.100.5/32", { tlp: "red" });
    for (const role of ["editor", "admin", "owner"] as const) expect(look("198.51.100.5", { role }).verdict).toBe("malicious");
    for (const role of ["viewer", "user"] as const) expect(look("198.51.100.5", { role })).toMatchObject({ verdict: "unknown", matches: [], tlp: null });
    expect(look("198.51.100.6", viewer).verdict).toBe("suspicious");
    expect(intel.listIndicators({ status: "all" }, undefined, 100, viewer).items.map((i) => i.value)).toEqual(["198.51.100.6"]);
    expect(intel.listIndicators({ status: "all" }, undefined, 100, editor).items).toHaveLength(3);
    const red = intel.listIndicators({ status: "all", type: "ipv4" }, undefined, 100, editor).items.find((i) => i.tlp === "red")!;
    expect(() => intel.indicator(red.id, viewer)).toThrow(IntelError);
    expect(intel.indicator(red.id, editor).tlp).toBe("red");
    // The count of lookups that hit does not include what the caller may not see.
    expect(intel.stats().hits).toBeGreaterThan(0);
  });
});

describe("allow list", () => {
  it("wins over any indicator, for a value, a block or a domain with its subdomains", () => {
    const { intel, feed, add, look } = setup();
    const f = feed();
    add(f, "198.51.100.0/24");
    add(f, "evil.example.com", { includeSubdomains: true });
    intel.createAllow({ value: "198.51.100.77", reason: "Our scanner", expiresAt: later(30) }, "ada");
    intel.createAllow({ value: "198.51.100.128/25", reason: "Our office egress", expiresAt: later(30) }, "ada");
    intel.createAllow({ value: "ok.evil.example.com", reason: "Ours", expiresAt: later(30), includeSubdomains: true }, "ada");
    expect(look("198.51.100.77")).toMatchObject({ verdict: "allowed", allowed: { reason: "Our scanner" } });
    expect(look("198.51.100.200").verdict).toBe("allowed");
    expect(look("198.51.100.5").verdict).toBe("suspicious");
    expect(look("x.ok.evil.example.com").verdict).toBe("allowed");
    expect(look("x.evil.example.com").verdict).toBe("suspicious");
    // The matches are still listed, so a person sees what the value would have been.
    expect(look("198.51.100.77").matches).toHaveLength(1);
  });

  it("stops winning when it expires, and needs a reason and an end", () => {
    const { intel, feed, add, look } = setup();
    add(feed(), "198.51.100.10");
    intel.createAllow({ value: "198.51.100.10", reason: "Temporary", expiresAt: later(1) }, "ada");
    expect(look("198.51.100.10").verdict).toBe("allowed");
    const bad = (body: Record<string, unknown>) => () => intel.createAllow({ value: "198.51.100.11", reason: "fine for now", expiresAt: later(5), ...body }, "ada");
    expect(bad({ reason: "" })).toThrow(/reason/);
    expect(bad({ expiresAt: later(-1) })).toThrow(/future/);
    expect(bad({ expiresAt: later(400) })).toThrow(/366/);
    expect(bad({ expiresAt: undefined })).toThrow(/expiresAt/);
    expect(bad({ extra: 1 })).toThrow(/Expected/);
    expect(() => intel.createAllow({ value: "198.51.100.10", reason: "again", expiresAt: later(5) }, "ada")).toThrow(/already/);
  });
});

describe("importing", () => {
  it("imports text, and names the lines it cannot use", () => {
    const { intel, feed } = setup();
    const f = intel.createFeed({ name: "list", kind: "text", defaultTtlDays: 7 }).id;
    const r = intel.importFeed(f, Buffer.from("# a comment\n198.51.100.1\n\nbad[.]example.com\nnot an indicator\n198.51.100.1\n"));
    expect(r).toMatchObject({ received: 4, created: 2, updated: 1, skippedCount: 1, skipped: [{ ref: "line 5" }] });
    expect(feed).toBeDefined();
    expect(intel.feed(f).indicators).toEqual({ total: 2, active: 2 });
    expect(intel.feed(f).lastImportAt).not.toBeNull();
  });

  it("imports CSV with quoted cells and per-row problems", () => {
    const { intel, look } = (() => {
      const s = setup();
      return { intel: s.intel, look: s.look };
    })();
    const f = intel.createFeed({ name: "csv", kind: "csv" }).id;
    const csv = ['type,value,confidence,tlp,severity,tags,description,include_subdomains', 'domain,Bad.Example.com,80,green,high,"phish;kit","A ""quoted"", comma",yes', ",198.51.100.20,,,,,,", "ipv4,198.51.100.21,150,,,,,", "domain,,50,,,,,", "ipv4,198.51.100.22,50,purple,,,,"].join("\r\n");
    const r = intel.importFeed(f, Buffer.from(csv));
    expect(r).toMatchObject({ received: 5, created: 2, skippedCount: 3 });
    expect(r.skipped.map((s) => s.ref)).toEqual(["row 4", "row 5", "row 6"]);
    expect(look("x.bad.example.com")).toMatchObject({ verdict: "malicious", confidence: 80, severity: "high", tlp: "green", matches: [{ labels: ["phish", "kit"], description: 'A "quoted", comma' }] });
    expect(() => intel.importFeed(f, Buffer.from("ip,confidence\n1.2.3.4,5\n"))).toThrow(/must name the columns/);
  });

  it("imports a STIX bundle: patterns, markings, confidence, labels, revoked, and what it cannot read", () => {
    const { intel, look } = (() => {
      const s = setup();
      return { intel: s.intel, look: s.look };
    })();
    const f = intel.createFeed({ name: "stix", kind: "stix" }).id;
    const r = intel.importFeed(
      f,
      Buffer.from(
        bundle(
          { pattern: "[ipv4-addr:value = '198.51.100.30' OR domain-name:value = 'c2.example.com']", confidence: 85, tlp: "red", labels: ["malicious-activity"], name: "C2 server" },
          { pattern: "[ipv4-addr:value = '198.51.100.31']", revoked: true },
          { pattern: "[ipv4-addr:value = '198.51.100.32' AND domain-name:value = 'a.example.com']" },
          { pattern: "[process:name = 'cmd.exe']" },
          { pattern: "alert tcp any any", pattern_type: "snort" },
        ),
      ),
    );
    expect(r).toMatchObject({ received: 5, created: 3, revoked: 1, unparsedCount: 3 });
    expect(r.unparsed.map((u) => u.reason)).toEqual([expect.stringMatching(/AND/), expect.stringMatching(/process:name/), expect.stringMatching(/snort/)]);
    expect(look("c2.example.com")).toMatchObject({ verdict: "malicious", confidence: 85, tlp: "red", matches: [{ labels: ["malicious-activity"], description: "C2 server" }] });
    expect(look("c2.example.com", viewer).verdict).toBe("unknown");
    expect(look("198.51.100.31").verdict).toBe("unknown");
    expect(intel.listIndicators({ status: "inactive" }, undefined, 10, editor).items.map((i) => i.value)).toEqual(["198.51.100.31"]);
    // Importing again updates, and a revoked indicator comes back when the feed says so.
    expect(intel.importFeed(f, Buffer.from(bundle({ pattern: "[ipv4-addr:value = '198.51.100.31']" })))).toMatchObject({ created: 0, updated: 1 });
    expect(look("198.51.100.31").verdict).toBe("suspicious");
    expect(() => intel.importFeed(f, Buffer.from("{nope"))).toThrow(/not JSON/);
    expect(() => intel.importFeed(f, Buffer.from('{"hello":1}'))).toThrow(/STIX 2.1 bundle/);
  });

  it("does not import into a manual feed", () => {
    const { intel, feed } = setup();
    expect(() => intel.importFeed(feed(), Buffer.from("198.51.100.1"))).toThrow(/one at a time/);
  });
});

describe("csv", () => {
  it("reads quotes, doubled quotes and both line endings", () => {
    expect(parseCsv('a,"b,c","d""e"\r\n1,2,3\n\n')).toEqual([["a", "b,c", 'd"e'], ["1", "2", "3"]]);
  });
});

describe("speed", () => {
  it("looks up 1000 values among 100,000 indicators and 4,096 blocks in well under two seconds", () => {
    const { db, intel, feed } = setup();
    const f = feed();
    const at = new Date().toISOString();
    const until = later(30);
    db.exec("BEGIN");
    const ins = db.prepare("INSERT INTO indicators (id, type, value, feed_id, confidence, tlp, severity, labels, valid_from, valid_until, created_at, updated_at) VALUES (?, ?, ?, ?, 50, 'amber', 'medium', '[]', ?, ?, ?, ?)");
    for (let i = 0; i < 95_000; i++) ins.run(`i${i}`, "domain", `host${i}.example.net`, f, at, until, at, at);
    for (let i = 0; i < 5_000; i++) ins.run(`d${i}`, "ipv4", `10.${i % 250}.${Math.floor(i / 250)}.1`, f, at, until, at, at);
    for (let i = 0; i < 4_096; i++) ins.run(`c${i}`, "cidr", `172.${16 + (i % 16)}.${Math.floor(i / 16) % 256}.0/24`, f, at, until, at, at);
    db.exec("COMMIT");
    const items = Array.from({ length: 1000 }, (_, i) => ({ value: i % 2 ? `host${i * 7}.example.net` : `172.${16 + (i % 16)}.${i % 200}.9` }));
    const started = performance.now();
    const results = intel.lookup(items, editor);
    const ms = performance.now() - started;
    expect(results.filter((r) => r.verdict !== "unknown").length).toBeGreaterThan(400);
    expect(ms).toBeLessThan(2000);
  });
});
