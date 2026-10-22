import { describe, expect, it } from "vitest";
import { detectType, networksContaining, NormalizeError, normalizeIndicator, refang } from "./normalize.ts";

const n = (value: string, type?: string) => normalizeIndicator(type, value);

describe("refang", () => {
  it("undoes the ways indicators are written to be safe to share", () => {
    expect(refang("hxxps://bad[.]example[.]com/a")).toBe("https://bad.example.com/a");
    expect(refang("  198[.]51[.]100[.]7 ")).toBe("198.51.100.7");
    expect(refang("alice[at]example(.)com")).toBe("alice@example.com");
    expect(refang("hxxp[://]example.com")).toBe("http://example.com");
  });
});

describe("normalizeIndicator", () => {
  it("canonicalizes addresses", () => {
    expect(n("198.51.100.7")).toEqual({ type: "ipv4", value: "198.51.100.7" });
    expect(n("2001:DB8:0:0:0:0:0:1")).toEqual({ type: "ipv6", value: "2001:db8::1" });
    expect(n("2001:db8::1", "ipv6").value).toBe("2001:db8::1");
  });

  it("refuses addresses that different software reads differently", () => {
    expect(() => n("010.0.0.1", "ipv4")).toThrow(NormalizeError);
    expect(() => n("256.1.1.1", "ipv4")).toThrow(NormalizeError);
    expect(() => n("1.2.3", "ipv4")).toThrow(NormalizeError);
    expect(() => n("gggg::1", "ipv6")).toThrow(NormalizeError);
  });

  it("masks the host bits of a CIDR block", () => {
    expect(n("198.51.100.77/24")).toEqual({ type: "cidr", value: "198.51.100.0/24" });
    expect(n("2001:db8:abcd:1234::1/32")).toEqual({ type: "cidr", value: "2001:db8::/32" });
    expect(n("0.0.0.0/0").value).toBe("0.0.0.0/0");
    expect(() => n("198.51.100.0/33", "cidr")).toThrow(/at most 32/);
    expect(() => n("198.51.100.0", "cidr")).toThrow(NormalizeError);
    expect(() => n("not/24", "cidr")).toThrow(NormalizeError);
  });

  it("lowercases domains, drops the trailing dot and converts to punycode", () => {
    expect(n("Bad.Example.COM.")).toEqual({ type: "domain", value: "bad.example.com" });
    expect(n("bücher.example", "domain").value).toBe("xn--bcher-kva.example");
    expect(() => n("localhost", "domain")).toThrow(NormalizeError);
    expect(() => n("1.2.3.4", "domain")).toThrow(/IP address/);
    expect(() => n("-bad.example.com", "domain")).toThrow(NormalizeError);
    expect(() => n(`${"a".repeat(64)}.example.com`, "domain")).toThrow(NormalizeError);
  });

  it("keeps a URL's path and query, and drops credentials and the fragment", () => {
    expect(n("HTTP://User:pw@Example.com:80/a/b?x=1#top")).toEqual({ type: "url", value: "http://example.com/a/b?x=1" });
    expect(() => n("javascript:alert(1)", "url")).toThrow(NormalizeError);
    expect(() => n("gopher://example.com/", "url")).toThrow(NormalizeError);
  });

  it("checks hashes and email addresses", () => {
    const sha256 = "a".repeat(64);
    expect(n(sha256.toUpperCase())).toEqual({ type: "sha256", value: sha256 });
    expect(n("b".repeat(40)).type).toBe("sha1");
    expect(n("c".repeat(32)).type).toBe("md5");
    expect(() => n("abc", "sha256")).toThrow(/64 hexadecimal/);
    expect(n("Alice@Example.COM")).toEqual({ type: "email", value: "alice@example.com" });
    expect(() => n("nobody", "email")).toThrow(NormalizeError);
  });

  it("asks for the type when it cannot tell, and refuses a type it does not know", () => {
    expect(() => n("what is this")).toThrow(/give its type/);
    expect(() => n("1.2.3.4", "ip")).toThrow(/type must be one of/);
    expect(() => n("   ")).toThrow(/empty/);
  });
});

describe("detectType", () => {
  it("tells what a value looks like", () => {
    expect(detectType("198.51.100.7")).toBe("ipv4");
    expect(detectType("198.51.100.0/24")).toBe("cidr");
    expect(detectType("2001:db8::/32")).toBe("cidr");
    expect(detectType("2001:db8::1")).toBe("ipv6");
    expect(detectType("hxxp://a[.]example")).toBe("url");
    expect(detectType("bad.example.com")).toBe("domain");
    expect(detectType("a@example.com")).toBe("email");
    expect(detectType("zzz")).toBeNull();
  });
});

describe("networksContaining", () => {
  it("lists every block that could hold an address", () => {
    const v4 = networksContaining("198.51.100.7");
    expect(v4).toHaveLength(33);
    expect(v4[0]).toBe("198.51.100.7/32");
    expect(v4).toContain("198.51.100.0/24");
    expect(v4.at(-1)).toBe("0.0.0.0/0");
    const v6 = networksContaining("2001:db8::1");
    expect(v6).toHaveLength(129);
    expect(v6).toContain("2001:db8::/32");
  });
});
