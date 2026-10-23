import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { openDb } from "./db.ts";

describe("openDb", () => {
  it("uses WAL and migrates once", () => {
    const path = join(mkdtempSync(join(tmpdir(), "threat-intel-")), "nested", "threat-intel.db");
    const first = openDb(path);
    expect(first.prepare("PRAGMA journal_mode").get()).toEqual({ journal_mode: "wal" });
    first.close();

    const second = openDb(path);
    expect(second.prepare("SELECT COUNT(*) AS n FROM schema_migrations").get()).toEqual({ n: 1 });
    second.close();
  });

  it("deletes a feed's indicators with it, and keeps one indicator per type, value and feed", () => {
    const db = openDb(":memory:");
    db.exec(`INSERT INTO feeds VALUES ('f', 'one', 'manual', 30, 50, 'amber', 'medium', NULL, 'now');
      INSERT INTO indicators (id, type, value, feed_id, confidence, tlp, severity, valid_from, valid_until, created_at, updated_at) VALUES ('i', 'ipv4', '198.51.100.1', 'f', 50, 'amber', 'low', 'a', 'b', 'c', 'd')`);
    expect(() =>
      db.exec(
        "INSERT INTO indicators (id, type, value, feed_id, confidence, tlp, severity, valid_from, valid_until, created_at, updated_at) VALUES ('j', 'ipv4', '198.51.100.1', 'f', 50, 'amber', 'low', 'a', 'b', 'c', 'd')",
      ),
    ).toThrow(/UNIQUE/);
    db.exec("DELETE FROM feeds");
    expect(db.prepare("SELECT COUNT(*) AS n FROM indicators").get()).toEqual({ n: 0 });
  });
});
