import { describe, expect, it } from "vitest";
import { parseStixPattern, StixPatternError } from "./stix.ts";

const ok = (p: string) => parseStixPattern(p);
const refused = (p: string) => {
  try {
    parseStixPattern(p);
  } catch (err) {
    if (err instanceof StixPatternError) return err.message;
    throw err;
  }
  throw new Error(`${p} was accepted`);
};

describe("parseStixPattern", () => {
  it("reads one comparison", () => {
    expect(ok("[ipv4-addr:value = '198.51.100.7']")).toEqual([{ type: "ipv4", value: "198.51.100.7" }]);
    expect(ok("[domain-name:value = 'Bad.Example.com']")).toEqual([{ type: "domain", value: "bad.example.com" }]);
    expect(ok("[url:value = 'http://example.com/a?b=c']")).toEqual([{ type: "url", value: "http://example.com/a?b=c" }]);
    expect(ok("[email-addr:value = 'a@example.com']")).toEqual([{ type: "email", value: "a@example.com" }]);
    expect(ok("[ipv6-addr:value = '2001:db8::1']")).toEqual([{ type: "ipv6", value: "2001:db8::1" }]);
  });

  it("reads blocks, with = or ISSUBSET", () => {
    expect(ok("[ipv4-addr:value ISSUBSET '198.51.100.0/24']")).toEqual([{ type: "cidr", value: "198.51.100.0/24" }]);
    expect(ok("[ipv4-addr:value = '203.0.113.0/24']")).toEqual([{ type: "cidr", value: "203.0.113.0/24" }]);
    expect(ok("[ipv6-addr:value ISSUBSET '2001:db8::/32']")).toEqual([{ type: "cidr", value: "2001:db8::/32" }]);
  });

  it("reads file hashes under any spelling of the algorithm", () => {
    const sha256 = "a".repeat(64);
    expect(ok(`[file:hashes.'SHA-256' = '${sha256}']`)).toEqual([{ type: "sha256", value: sha256 }]);
    expect(ok(`[file:hashes.SHA256 = '${sha256}']`)).toEqual([{ type: "sha256", value: sha256 }]);
    expect(ok(`[file:hashes."SHA-1" = '${"b".repeat(40)}']`)[0]!.type).toBe("sha1");
    expect(ok(`[file:hashes.MD5 = '${"c".repeat(32)}']`)[0]!.type).toBe("md5");
  });

  it("reads lists joined by OR, inside one pair of brackets or in several, and IN", () => {
    expect(ok("[domain-name:value = 'a.example.com' OR domain-name:value = 'b.example.com']").map((x) => x.value)).toEqual(["a.example.com", "b.example.com"]);
    expect(ok("[ipv4-addr:value = '198.51.100.1'] OR [ipv4-addr:value = '198.51.100.2']").map((x) => x.value)).toEqual(["198.51.100.1", "198.51.100.2"]);
    expect(ok("[domain-name:value IN ('a.example.com', 'b.example.com')]")).toHaveLength(2);
    expect(ok("[url:value = 'http://example.com/it\\'s']")[0]!.value).toBe("http://example.com/it's");
  });

  it("says why it refuses everything else", () => {
    expect(refused("[ipv4-addr:value = '198.51.100.1' AND domain-name:value = 'a.example.com']")).toMatch(/AND/);
    expect(refused("[ipv4-addr:value = '198.51.100.1'] AND [domain-name:value = 'a.example.com']")).toMatch(/AND is not supported/);
    expect(refused("[ipv4-addr:value = '198.51.100.1'] FOLLOWEDBY [domain-name:value = 'a.example.com']")).toMatch(/FOLLOWEDBY/);
    expect(refused("[ipv4-addr:value = '198.51.100.1'] WITHIN 5 SECONDS")).toMatch(/WITHIN/);
    expect(refused("[domain-name:value LIKE '%.example.com']")).toMatch(/LIKE/);
    expect(refused("[domain-name:value MATCHES '^a']")).toMatch(/MATCHES/);
    expect(refused("[domain-name:value != 'a.example.com']")).toMatch(/!=/);
    expect(refused("[domain-name:value NOT = 'a.example.com']")).toMatch(/NOT/);
    expect(refused("[process:name = 'cmd.exe']")).toMatch(/process:name is not supported/);
    expect(refused("[windows-registry-key:key = 'HKLM\\\\x']")).toMatch(/not supported/);
    expect(refused("[file:hashes.'SSDEEP' = 'x']")).toMatch(/SSDEEP/);
    expect(refused("[network-traffic:src_ref.value = '198.51.100.1']")).toMatch(/not supported/);
    expect(refused("[network-traffic:dst_port = 443]")).toMatch(/network-traffic:dst_port is not supported/);
    expect(refused("")).toMatch(/empty/);
    expect(refused("[ipv4-addr:value = ")).toMatch(/string value/);
    expect(refused("[ipv4-addr:value = 'oops']")).toMatch(/not an IPv4/);
    expect(refused("[domain-name:value = 'unterminated]")).toMatch(/not closed/);
    expect(refused("ipv4-addr:value = '198.51.100.1'")).toMatch(/expected \[/);
  });
});
