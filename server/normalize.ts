import { domainToASCII } from "node:url";

export const TYPES = ["ipv4", "ipv6", "domain", "url", "sha256", "sha1", "md5", "email", "cidr"] as const;
export type IndicatorType = (typeof TYPES)[number];

export class NormalizeError extends Error {}

/** Undoes the ways indicators are written to be safe to share: hxxp://evil[.]example, a(t)b, [:] and the like. */
export function refang(value: string): string {
  return value
    .trim()
    .replace(/^hxxp/i, "http")
    .replace(/^fxp/i, "ftp")
    .replace(/\[:\/\/\]/g, "://")
    .replace(/\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)/gi, ".")
    .replace(/\[:\]/g, ":")
    .replace(/\[@\]|\[at\]|\(at\)/gi, "@");
}

const V4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;

/** Dotted quad with no leading zeros: "010.0.0.1" is read differently by different software, so it is refused. */
export function parseV4(value: string): number[] | null {
  const m = V4.exec(value);
  if (!m) return null;
  const parts = m.slice(1).map((p) => (p.length > 1 && p.startsWith("0") ? NaN : Number(p)));
  return parts.every((n) => Number.isInteger(n) && n >= 0 && n <= 255) ? parts : null;
}

/** The canonical (compressed, lowercase) form of an IPv6 address, or null. */
export function canonicalV6(value: string): string | null {
  if (!/^[0-9a-f:.]+$/i.test(value) || !value.includes(":")) return null;
  try {
    return new URL(`http://[${value}]/`).hostname.slice(1, -1);
  } catch {
    return null;
  }
}

/** All 8 groups of a canonical IPv6 address, as a bigint. */
export function v6ToBig(canonical: string): bigint {
  const [head = "", tail] = canonical.split("::");
  const left = head ? head.split(":") : [];
  const right = tail !== undefined && tail ? tail.split(":") : [];
  const groups = tail === undefined ? left : [...left, ...Array<string>(8 - left.length - right.length).fill("0"), ...right];
  return groups.reduce((acc, g) => (acc << 16n) | BigInt(parseInt(g || "0", 16)), 0n);
}

export const v4ToBig = (parts: number[]) => parts.reduce((acc, p) => (acc << 8n) | BigInt(p), 0n);

/** Formats a network address and prefix the way normalizeIndicator stores a CIDR block. */
export function formatCidr(family: 4 | 6, net: bigint, prefix: number): string {
  if (family === 4) return `${[24n, 16n, 8n, 0n].map((s) => Number((net >> s) & 255n)).join(".")}/${prefix}`;
  const groups = Array.from({ length: 8 }, (_, i) => ((net >> BigInt(112 - 16 * i)) & 0xffffn).toString(16)).join(":");
  return `${canonicalV6(groups)}/${prefix}`;
}

/** Every CIDR block, from /0 to the address itself, that could contain this address: what a lookup asks the index for. */
export function networksContaining(ip: string): string[] {
  const v4 = parseV4(ip);
  const family: 4 | 6 = v4 ? 4 : 6;
  const n = v4 ? v4ToBig(v4) : v6ToBig(ip);
  const width = family === 4 ? 32 : 128;
  const out: string[] = [];
  for (let prefix = width; prefix >= 0; prefix--) out.push(formatCidr(family, n & ~((1n << BigInt(width - prefix)) - 1n), prefix));
  return out;
}

function normalizeCidr(value: string): string {
  const [addr = "", bits = "", ...extra] = value.split("/");
  if (extra.length || !/^\d{1,3}$/.test(bits)) throw new NormalizeError("a CIDR block looks like 192.0.2.0/24");
  const v4 = parseV4(addr);
  const v6 = v4 ? null : canonicalV6(addr);
  if (!v4 && !v6) throw new NormalizeError("a CIDR block starts with an IPv4 or IPv6 address");
  const family: 4 | 6 = v4 ? 4 : 6;
  const prefix = Number(bits);
  if (prefix > (family === 4 ? 32 : 128)) throw new NormalizeError(`the prefix of an IPv${family} block is at most ${family === 4 ? 32 : 128}`);
  const width = family === 4 ? 32 : 128;
  const host = (1n << BigInt(width - prefix)) - 1n;
  return formatCidr(family, (v4 ? v4ToBig(v4) : v6ToBig(v6!)) & ~host, prefix);
}

const HOST_LABEL = /^[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?$/;

function normalizeDomain(value: string): string {
  const ascii = domainToASCII(value.replace(/\.$/, "").toLowerCase());
  const labels = ascii.split(".");
  if (!ascii || ascii.length > 253 || labels.length < 2 || !labels.every((l) => HOST_LABEL.test(l))) throw new NormalizeError("not a domain name");
  // No top-level domain is all digits; such a name is an address, and stored as a domain it would never match one.
  if (/^\d+$/.test(labels.at(-1)!)) throw new NormalizeError("an IP address is not a domain name; give it as ipv4");
  return ascii;
}

function normalizeUrl(value: string): string {
  const url = URL.parse(value);
  if (!url || !["http:", "https:", "ftp:"].includes(url.protocol) || !url.hostname) throw new NormalizeError("a URL starts with http://, https:// or ftp://");
  // Credentials in a URL are secrets and add nothing to an indicator; the fragment never reaches a server.
  url.username = "";
  url.password = "";
  url.hash = "";
  if (url.href.length > 2048) throw new NormalizeError("a URL is at most 2048 characters");
  return url.href;
}

const HASH = { sha256: 64, sha1: 40, md5: 32 } as const;

/** The type a value looks like, for feeds that do not say. */
export function detectType(value: string): IndicatorType | null {
  const v = refang(value);
  if (v.includes("/") && !v.includes("://") && (parseV4(v.split("/")[0]!) || canonicalV6(v.split("/")[0]!))) return "cidr";
  if (parseV4(v)) return "ipv4";
  if (canonicalV6(v)) return "ipv6";
  if (v.includes("://")) return "url";
  if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v)) return "email";
  if (/^[0-9a-f]+$/i.test(v)) for (const [type, len] of Object.entries(HASH)) if (v.length === len) return type as IndicatorType;
  return /^[^\s/:]+\.[^\s/:]+$/.test(v) ? "domain" : null;
}

/** One indicator in its stored form. Throws NormalizeError with what is wrong. */
export function normalizeIndicator(type: string | undefined | null, raw: string): { type: IndicatorType; value: string } {
  const value = refang(String(raw));
  if (!value) throw new NormalizeError("the value is empty");
  const t = (type ?? detectType(value)) as IndicatorType | null;
  if (!t || !(TYPES as readonly string[]).includes(t))
    throw new NormalizeError(
      type ? `type must be one of ${TYPES.join(", ")}` : `cannot tell what kind of indicator ${JSON.stringify(value.slice(0, 40))} is; give its type`,
    );
  switch (t) {
    case "ipv4": {
      const parts = parseV4(value);
      if (!parts) throw new NormalizeError("not an IPv4 address");
      return { type: t, value: parts.join(".") };
    }
    case "ipv6": {
      const v6 = canonicalV6(value);
      if (!v6) throw new NormalizeError("not an IPv6 address");
      return { type: t, value: v6 };
    }
    case "cidr":
      return { type: t, value: normalizeCidr(value) };
    case "domain":
      return { type: t, value: normalizeDomain(value) };
    case "url":
      return { type: t, value: normalizeUrl(value) };
    case "email": {
      const email = value.toLowerCase();
      if (email.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) throw new NormalizeError("not an email address");
      return { type: t, value: email };
    }
    default: {
      const h = value.toLowerCase();
      if (!/^[0-9a-f]+$/.test(h) || h.length !== HASH[t]) throw new NormalizeError(`a ${t} hash is ${HASH[t]} hexadecimal characters`);
      return { type: t, value: h };
    }
  }
}
