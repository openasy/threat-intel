import { mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { DatabaseSync } from "node:sqlite";

// Forward-only migrations (ADR 0010): append new entries, never edit or remove old ones.
const MIGRATIONS = [
  `CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
   -- Where indicators come from. kind says how an import is read; manual feeds take indicators one at a time.
   CREATE TABLE feeds (
     id TEXT PRIMARY KEY,
     name TEXT NOT NULL UNIQUE,
     kind TEXT NOT NULL CHECK (kind IN ('stix', 'csv', 'text', 'manual')),
     default_ttl_days INTEGER NOT NULL,
     default_confidence INTEGER NOT NULL,
     default_tlp TEXT NOT NULL CHECK (default_tlp IN ('clear', 'green', 'amber', 'red')),
     default_severity TEXT NOT NULL CHECK (default_severity IN ('critical', 'high', 'medium', 'low')),
     last_import_at TEXT,
     created_at TEXT NOT NULL
   );
   CREATE TABLE indicators (
     id TEXT PRIMARY KEY,
     type TEXT NOT NULL CHECK (type IN ('ipv4', 'ipv6', 'domain', 'url', 'sha256', 'sha1', 'md5', 'email', 'cidr')),
     value TEXT NOT NULL,
     feed_id TEXT NOT NULL REFERENCES feeds (id) ON DELETE CASCADE,
     confidence INTEGER NOT NULL,
     tlp TEXT NOT NULL CHECK (tlp IN ('clear', 'green', 'amber', 'red')),
     severity TEXT NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low')),
     labels TEXT NOT NULL DEFAULT '[]',
     description TEXT,
     include_subdomains INTEGER NOT NULL DEFAULT 0,
     valid_from TEXT NOT NULL,
     valid_until TEXT NOT NULL,
     revoked INTEGER NOT NULL DEFAULT 0,
     created_at TEXT NOT NULL,
     updated_at TEXT NOT NULL,
     UNIQUE (type, value, feed_id)
   );
   CREATE INDEX indicators_value ON indicators (type, value);
   CREATE INDEX indicators_feed ON indicators (feed_id);
   -- Values that are known to be fine, such as your own addresses, with a reason and an end date. They win over any
   -- indicator.
   CREATE TABLE allow_list (
     id TEXT PRIMARY KEY,
     type TEXT NOT NULL CHECK (type IN ('ipv4', 'ipv6', 'domain', 'url', 'sha256', 'sha1', 'md5', 'email', 'cidr')),
     value TEXT NOT NULL,
     include_subdomains INTEGER NOT NULL DEFAULT 0,
     reason TEXT NOT NULL,
     created_by TEXT,
     created_at TEXT NOT NULL,
     expires_at TEXT NOT NULL,
     UNIQUE (type, value)
   );
   CREATE INDEX allow_value ON allow_list (type, value)`,
  // Where a feed is pulled from on a schedule (ADR 0050): a TAXII 2.1 collection for a STIX feed, or a URL for any kind
  // but manual. The password or token is sealed with openasy-kek. added_after is where the next TAXII pull starts.
  `CREATE TABLE feed_pulls (
     feed_id TEXT PRIMARY KEY REFERENCES feeds (id) ON DELETE CASCADE,
     source TEXT NOT NULL CHECK (source IN ('taxii', 'url')),
     url TEXT NOT NULL,
     auth TEXT NOT NULL CHECK (auth IN ('none', 'basic', 'bearer')),
     username TEXT,
     secret TEXT,
     every_minutes INTEGER NOT NULL,
     added_after TEXT,
     more INTEGER NOT NULL DEFAULT 0,
     last_attempt_at TEXT,
     last_success_at TEXT,
     last_error TEXT,
     last_result TEXT,
     created_at TEXT NOT NULL
   )`,
];

/** Opens the product's single SQLite file in WAL mode (ADR 0011) and migrates it forward. */
export function openDb(path: string): DatabaseSync {
  if (path !== ":memory:") mkdirSync(dirname(path), { recursive: true });
  const db = new DatabaseSync(path);
  db.exec("PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 5000;");
  db.exec("CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)");
  const row = db.prepare("SELECT COALESCE(MAX(version), 0) AS v FROM schema_migrations").get() as { v: number };
  for (let v = row.v; v < MIGRATIONS.length; v++) {
    db.exec("BEGIN");
    try {
      db.exec(MIGRATIONS[v]!);
      db.prepare("INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)").run(v + 1, new Date().toISOString());
      db.exec("COMMIT");
    } catch (err) {
      db.exec("ROLLBACK");
      throw err;
    }
  }
  return db;
}
