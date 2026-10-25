// Feeds pulled on a schedule (ADR 0050): a STIX feed from a TAXII 2.1 collection, or any feed but a manual one from a
// URL that answers with what it would be sent, such as a blocklist. What is pulled goes through the same import as a
// feed that is sent, so nothing it cannot read is dropped without a word. Pulling is the one outbound call
// threat-intel makes, and only to the addresses an admin sets.
import type { DatabaseSync } from "node:sqlite";
import { IntelError, type Intel } from "./intel.ts";
import type { Keyring } from "./kek.ts";

export const SOURCES = ["taxii", "url"] as const;
export type Source = (typeof SOURCES)[number];
export type PullAuth = "none" | "basic" | "bearer";

/** The most a pulled document, or one TAXII page, may hold: the same as an import that is sent. */
export const MAX_BYTES = 32 * 1024 * 1024;
/** TAXII pages read in one pull; a collection with more carries on at the next minute. */
const MAX_PAGES = 20;
const PAGE_SIZE = 1000;
const TIMEOUT_MS = 60_000;
const MIN_EVERY = 15;
const MAX_EVERY = 7 * 24 * 60;
const TAXII = "application/taxii+json;version=2.1";

const bad = (detail: string) => new IntelError(422, "invalid-body", detail);
const now = () => new Date().toISOString();

interface PullRow {
  feed_id: string;
  source: Source;
  url: string;
  auth: PullAuth;
  username: string | null;
  secret: string | null;
  every_minutes: number;
  added_after: string | null;
  more: number;
  last_attempt_at: string | null;
  last_success_at: string | null;
  last_error: string | null;
  last_result: string | null;
  created_at: string;
}

export interface PullResult {
  received: number;
  created: number;
  updated: number;
  revoked: number;
  /** Entries left out, with their reasons in the import's answer; counted here. */
  leftOut: number;
  /** A TAXII collection had more than one pull reads: the rest follows at the next minute. */
  more: boolean;
}

/** How a feed's pull is shown; never the password or token. */
export function presentPull(db: DatabaseSync, feedId: string) {
  const p = db.prepare("SELECT * FROM feed_pulls WHERE feed_id = ?").get(feedId) as PullRow | undefined;
  if (!p) return null;
  return {
    source: p.source,
    url: p.url,
    auth: p.auth,
    username: p.username,
    everyMinutes: p.every_minutes,
    lastAttemptAt: p.last_attempt_at,
    lastSuccessAt: p.last_success_at,
    lastError: p.last_error,
    lastResult: p.last_result ? (JSON.parse(p.last_result) as PullResult) : null,
    // Due at once when it was never pulled or a TAXII collection had more; otherwise every everyMinutes from the last try.
    nextAt: p.more || !p.last_attempt_at ? now() : new Date(Date.parse(p.last_attempt_at) + p.every_minutes * 60_000).toISOString(),
  };
}

export type Pull = NonNullable<ReturnType<typeof presentPull>>;

/** The address with its credentials and query left out, for messages and logs. */
const shown = (url: string) => {
  const u = new URL(url);
  return `${u.origin}${u.pathname}`;
};

export interface PullerOptions {
  db: DatabaseSync;
  intel: Intel;
  /** Seals passwords and tokens; without it only feeds that need none can be pulled. */
  keyring?: Keyring;
  version: string;
  log: (level: "info" | "warn" | "error", msg: string, fields?: Record<string, unknown>) => void;
  fetch?: typeof fetch;
}

export function createPuller({ db, intel, keyring, version, log, fetch: get = fetch }: PullerOptions) {
  const running = new Set<string>();
  let ticking = false;

  const feedOf = (id: string) => {
    const f = db.prepare("SELECT id, name, kind FROM feeds WHERE id = ?").get(id) as { id: string; name: string; kind: string } | undefined;
    if (!f) throw new IntelError(404, "not-found", "The feed does not exist.");
    return f;
  };
  const rowOf = (id: string) => db.prepare("SELECT * FROM feed_pulls WHERE feed_id = ?").get(id) as PullRow | undefined;

  /** One GET, with the feed's credentials, read up to MAX_BYTES. */
  async function fetchOne(p: PullRow, url: string, accept: string) {
    const headers: Record<string, string> = { accept, "user-agent": `OpenAsy-Threat-Intel/${version}` };
    if (p.auth !== "none") {
      if (!keyring) throw new Error("the password or token cannot be read without openasy-kek");
      const secret = keyring.open(p.secret!).toString("utf8");
      headers.authorization = p.auth === "basic" ? `Basic ${Buffer.from(`${p.username}:${secret}`).toString("base64")}` : `Bearer ${secret}`;
    }
    // fetch drops the authorization header when a redirect leaves the origin.
    const res = await get(url, { headers, redirect: "follow", signal: AbortSignal.timeout(TIMEOUT_MS) });
    const length = Number(res.headers.get("content-length") ?? 0);
    if (length > MAX_BYTES) throw new Error(`${shown(url)} sent more than ${MAX_BYTES / 1024 / 1024} MiB`);
    const chunks: Buffer[] = [];
    let size = 0;
    for await (const chunk of (res.body ?? []) as AsyncIterable<Uint8Array>) {
      size += chunk.length;
      if (size > MAX_BYTES) throw new Error(`${shown(url)} sent more than ${MAX_BYTES / 1024 / 1024} MiB`);
      chunks.push(Buffer.from(chunk));
    }
    const body = Buffer.concat(chunks);
    if (!res.ok) {
      // TAXII servers say why in an error message: { title, description }.
      let why = "";
      try {
        const e = JSON.parse(body.toString("utf8")) as { title?: unknown; description?: unknown };
        why = [e.title, e.description].filter((x) => typeof x === "string").join(": ");
      } catch {
        // not JSON
      }
      throw new Error(`${shown(url)} answered ${res.status}${why ? ` (${why.slice(0, 200)})` : ""}`);
    }
    return { body, headers: res.headers };
  }

  const add = (total: PullResult, r: ReturnType<Intel["importFeed"]>) => {
    total.received += r.received;
    total.created += r.created;
    total.updated += r.updated;
    total.revoked += r.revoked;
    total.leftOut += r.skippedCount + r.unparsedCount;
  };

  /** Reads a TAXII 2.1 collection's objects added after the last pull, page by page, and imports each page. */
  async function pullTaxii(p: PullRow, total: PullResult) {
    const objects = new URL("objects/", p.url.endsWith("/") ? p.url : `${p.url}/`);
    let next: string | undefined;
    // While the server pages with next, every page repeats the first page's filter (TAXII 2.1, 3.4).
    let addedAfter = p.added_after;
    let latest: string | undefined;
    for (let page = 0; page < MAX_PAGES; page++) {
      const u = new URL(objects);
      u.searchParams.set("limit", String(PAGE_SIZE));
      if (addedAfter) u.searchParams.set("added_after", addedAfter);
      if (next) u.searchParams.set("next", next);
      const { body, headers } = await fetchOne(p, u.toString(), TAXII);
      let envelope: { more?: unknown; next?: unknown; objects?: unknown };
      try {
        envelope = JSON.parse(body.toString("utf8")) as typeof envelope;
      } catch {
        throw new Error(`${shown(u.toString())} did not answer with a TAXII envelope`);
      }
      if (envelope.objects !== undefined && !Array.isArray(envelope.objects)) throw new Error(`${shown(u.toString())} did not answer with a TAXII envelope`);
      const list = (envelope.objects ?? []) as unknown[];
      if (list.length) add(total, intel.importFeed(p.feed_id, Buffer.from(JSON.stringify({ type: "bundle", id: "bundle--taxii", objects: list }))));
      // The server says when the last object of the page was added; the next pull starts there, so none is read twice.
      const last = headers.get("x-taxii-date-added-last");
      if (last && !Number.isNaN(Date.parse(last))) {
        latest = last;
        db.prepare("UPDATE feed_pulls SET added_after = ? WHERE feed_id = ?").run(latest, p.feed_id);
      }
      if (envelope.more !== true) return;
      next = typeof envelope.next === "string" ? envelope.next : undefined;
      // Without next, a server pages by added_after alone; without either, it cannot be read further.
      if (!next) {
        if (!latest || latest === addedAfter) return;
        addedAfter = latest;
      }
    }
    total.more = true;
  }

  async function run(feedId: string): Promise<PullResult> {
    const feed = feedOf(feedId);
    const p = rowOf(feedId);
    if (!p) throw new IntelError(404, "not-found", "The feed is not pulled; set where it is pulled from first.");
    if (running.has(feedId)) throw new IntelError(409, "conflict", "This feed is being pulled now.");
    running.add(feedId);
    const at = now();
    const total: PullResult = { received: 0, created: 0, updated: 0, revoked: 0, leftOut: 0, more: false };
    try {
      if (p.source === "taxii") await pullTaxii(p, total);
      else {
        const accept = feed.kind === "stix" ? "application/json" : feed.kind === "csv" ? "text/csv, text/plain;q=0.9, */*;q=0.1" : "text/plain, */*;q=0.1";
        add(total, intel.importFeed(feedId, (await fetchOne(p, p.url, accept)).body));
      }
      db.prepare("UPDATE feed_pulls SET last_attempt_at = ?, last_success_at = ?, last_error = NULL, last_result = ?, more = ? WHERE feed_id = ?").run(
        at,
        now(),
        JSON.stringify(total),
        total.more ? 1 : 0,
        feedId,
      );
      log("info", "feed pulled", { feed: feed.name, source: p.source, url: shown(p.url), ...total });
      return total;
    } catch (err) {
      const message = (
        err instanceof Error && err.name === "TimeoutError" ? `${shown(p.url)} did not answer in ${TIMEOUT_MS / 1000} seconds` : (err as Error).message
      ).slice(0, 500);
      // A page already imported stays; the result says how far the pull got.
      db.prepare("UPDATE feed_pulls SET last_attempt_at = ?, last_error = ?, last_result = ?, more = 0 WHERE feed_id = ?").run(
        at,
        message,
        JSON.stringify(total),
        feedId,
      );
      log("warn", "feed pull failed", { feed: feed.name, source: p.source, url: shown(p.url), error: message });
      throw new IntelError(502, "pull-failed", message);
    } finally {
      running.delete(feedId);
    }
  }

  return {
    /**
     * Sets where a feed is pulled from. A password or token left out is kept, as long as the kind of sign-in and the
     * address's origin stay the same, so changing how often never needs it again and moving the feed always does.
     */
    set(feedId: string, body: Record<string, unknown>) {
      const feed = feedOf(feedId);
      if (feed.kind === "manual") throw new IntelError(409, "conflict", "A manual feed takes indicators one at a time and is not pulled.");
      const { source = feed.kind === "stix" ? "taxii" : "url", url, everyMinutes = 60, auth = "none", username, secret, ...rest } = body;
      if (Object.keys(rest).length) throw bad("Expected { url, source?, everyMinutes?, auth?, username?, secret? }.");
      if (typeof source !== "string" || !(SOURCES as readonly string[]).includes(source)) throw bad("source must be taxii or url.");
      if (source === "taxii" && feed.kind !== "stix") throw bad("Only a STIX feed is pulled from a TAXII collection; pull this feed from a url.");
      let u: URL;
      try {
        u = new URL(String(url));
      } catch {
        throw bad(
          source === "taxii"
            ? "url is the TAXII 2.1 collection, such as https://taxii.example.com/api1/collections/91a7b528-80eb-42ed-a74d-c6fbd5a26116/."
            : "url is where the feed is, such as https://feeds.example.com/blocklist.txt.",
        );
      }
      if (u.protocol !== "https:" && u.protocol !== "http:") throw bad("url must be https:// (or http:// for a feed that needs no password or token).");
      if (u.username || u.password) throw bad("Put the user name and password in username and secret, not in the url.");
      if (typeof everyMinutes !== "number" || !Number.isInteger(everyMinutes) || everyMinutes < MIN_EVERY || everyMinutes > MAX_EVERY)
        throw bad(`everyMinutes must be a whole number from ${MIN_EVERY} to ${MAX_EVERY} (a week).`);
      if (auth !== "none" && auth !== "basic" && auth !== "bearer") throw bad("auth must be none, basic or bearer.");
      if (auth !== "none" && u.protocol !== "https:") throw bad("A password or token is only sent over https://.");
      if (auth === "basic" && (typeof username !== "string" || !username || username.length > 200 || username.includes(":")))
        throw bad("username is required for basic sign-in, up to 200 characters and no colon.");
      if (secret !== undefined && (typeof secret !== "string" || !secret || secret.length > 4096)) throw bad("secret is up to 4096 characters.");

      const old = rowOf(feedId);
      let sealed: string | null = null;
      if (auth !== "none") {
        if (typeof secret === "string") {
          if (!keyring)
            throw new IntelError(
              409,
              "not-configured",
              "Mount openasy-kek (THREAT_INTEL_SECRETS_KEY_FILE) to keep a password or token; none is kept in clear.",
            );
          sealed = keyring.seal(secret);
        } else if (old?.auth === auth && old.secret && new URL(old.url).origin === u.origin) sealed = old.secret;
        else throw bad(auth === "basic" ? "secret is the password." : "secret is the token.");
      }
      const href = u.toString();
      // A TAXII collection read from somewhere else starts from the beginning again.
      const addedAfter = old && old.source === source && old.url === href ? old.added_after : null;
      db.prepare(
        `INSERT INTO feed_pulls (feed_id, source, url, auth, username, secret, every_minutes, added_after, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT (feed_id) DO UPDATE SET source = excluded.source, url = excluded.url, auth = excluded.auth, username = excluded.username,
           secret = excluded.secret, every_minutes = excluded.every_minutes, added_after = excluded.added_after`,
      ).run(feedId, source, href, auth, auth === "basic" ? (username as string) : null, sealed, everyMinutes, addedAfter, now());
      return presentPull(db, feedId)!;
    },

    remove(feedId: string) {
      feedOf(feedId);
      if (db.prepare("DELETE FROM feed_pulls WHERE feed_id = ?").run(feedId).changes === 0) throw new IntelError(404, "not-found", "The feed is not pulled.");
    },

    run,

    /** Pulls the feeds that are due, one after another; called every minute. */
    async tick() {
      if (ticking) return;
      ticking = true;
      try {
        const at = Date.now();
        const due = (db.prepare("SELECT * FROM feed_pulls ORDER BY last_attempt_at IS NOT NULL, last_attempt_at, rowid").all() as unknown as PullRow[]).filter(
          (p) => p.more || !p.last_attempt_at || Date.parse(p.last_attempt_at) + p.every_minutes * 60_000 <= at,
        );
        for (const p of due) await run(p.feed_id).catch(() => {});
      } finally {
        ticking = false;
      }
    },
  };
}

export type Puller = ReturnType<typeof createPuller>;
