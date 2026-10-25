// Starts the app on a random port for tests.
import { randomBytes } from "node:crypto";
import { createServer, type RequestListener, type Server } from "node:http";
import { createAuth } from "@openasy/auth";
import type { AddressInfo } from "node:net";
import { createApp, type AppOptions } from "./app.ts";
import { openDb } from "./db.ts";
import { createIntel } from "./intel.ts";
import { createKeyring } from "./kek.ts";
import { createPuller } from "./pull.ts";

export const INGEST_TOKEN = "test-ingest-token";
export const ADMIN_TOKEN = "test-admin-token";

// STIX 2.1 marking definitions for TLP.
export const MARKING = {
  clear: "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
  green: "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da",
  amber: "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82",
  red: "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d40e",
} as const;

export interface TestIndicator {
  pattern: string;
  confidence?: number;
  tlp?: keyof typeof MARKING;
  revoked?: boolean;
  valid_until?: string;
  labels?: string[];
  pattern_type?: string;
  name?: string;
}

/** A STIX 2.1 bundle of indicators. Addresses are from the documentation ranges (RFC 5737), names are example.com. */
export function bundle(...indicators: TestIndicator[]) {
  return JSON.stringify({
    type: "bundle",
    id: "bundle--4f4cd2c9-0b0a-4c1e-8f3a-000000000001",
    objects: [
      { type: "identity", spec_version: "2.1", id: "identity--00000000-0000-4000-8000-000000000001", name: "Test feed" },
      ...indicators.map((i, n) => ({
        type: "indicator",
        spec_version: "2.1",
        id: `indicator--00000000-0000-4000-8000-${String(n + 1).padStart(12, "0")}`,
        created: "2026-10-01T00:00:00Z",
        modified: "2026-10-01T00:00:00Z",
        valid_from: "2026-10-01T00:00:00Z",
        pattern_type: i.pattern_type ?? "stix",
        pattern: i.pattern,
        ...(i.confidence !== undefined && { confidence: i.confidence }),
        ...(i.tlp && { object_marking_refs: [MARKING[i.tlp]] }),
        ...(i.revoked && { revoked: true }),
        ...(i.valid_until && { valid_until: i.valid_until }),
        ...(i.labels && { labels: i.labels }),
        ...(i.name && { name: i.name }),
      })),
    ],
  });
}

export async function startApp({ pullFetch, ...opts }: Partial<AppOptions> & { version: string; pullFetch?: typeof fetch }) {
  const db = openDb(":memory:");
  const intel = createIntel(db);
  const puller = createPuller({ db, intel, keyring: createKeyring(randomBytes(32)), version: opts.version, log: () => {}, fetch: pullFetch });
  // The origin is known once the port is, so the handler is set after listening.
  let handler: RequestListener = (_req, res) => res.writeHead(503).end();
  const server: Server = createServer((req, res) => handler(req, res));
  await new Promise<void>((resolve) => server.listen(0, resolve));
  const base = `http://localhost:${(server.address() as AddressInfo).port}`;
  const auth = createAuth({ db, product: "threat-intel", productName: "OpenAsy Threat Intel", origin: base });
  handler = createApp({ db, intel, auth, ingestToken: INGEST_TOKEN, adminToken: ADMIN_TOKEN, puller, ...opts });
  const as =
    (token: string) =>
    (path: string, init: RequestInit = {}) =>
      fetch(base + path, { ...init, headers: { authorization: `Bearer ${token}`, "content-type": "application/json", ...init.headers } });
  const admin = as(ADMIN_TOKEN);
  const ingest = as(INGEST_TOKEN);
  const post = (path: string, body: unknown) => admin(path, { method: "POST", body: typeof body === "string" ? body : JSON.stringify(body) });
  const feed = async (name: string, kind: "stix" | "csv" | "text" | "manual", extra: Record<string, unknown> = {}) =>
    ((await (await post("/api/v1/feeds", { name, kind, ...extra })).json()) as { id: string }).id;
  const close = () => new Promise<void>((resolve) => server.close(() => resolve()));
  return { db, intel, puller, auth, base, admin, ingest, post, feed, close };
}
