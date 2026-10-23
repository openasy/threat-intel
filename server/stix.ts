import { normalizeIndicator, NormalizeError, type IndicatorType } from "./normalize.ts";

export class StixPatternError extends Error {}

type Tok = { t: "str" | "word" | "sym"; v: string };

function tokenize(pattern: string): Tok[] {
  const out: Tok[] = [];
  let i = 0;
  while (i < pattern.length) {
    const c = pattern[i]!;
    if (/\s/.test(c)) i++;
    else if (c === "'" || c === '"') {
      let s = "";
      i++;
      for (;;) {
        if (i >= pattern.length) throw new StixPatternError("a string is not closed");
        const d = pattern[i]!;
        if (d === "\\" && i + 1 < pattern.length) ((s += pattern[i + 1]), (i += 2));
        else if (d === c) break;
        else ((s += d), i++);
      }
      i++;
      out.push({ t: "str", v: s });
    } else if ("[]()=,:.".includes(c)) (out.push({ t: "sym", v: c }), i++);
    else if (c === "!" || c === "<" || c === ">") {
      const two = pattern.slice(i, i + 2);
      out.push({ t: "sym", v: two === "!=" || two === "<=" || two === ">=" ? two : c });
      i += two === "!=" || two === "<=" || two === ">=" ? 2 : 1;
    } else {
      const m = /^[A-Za-z0-9_-]+/.exec(pattern.slice(i));
      if (!m) throw new StixPatternError(`unexpected character ${JSON.stringify(c)}`);
      out.push({ t: "word", v: m[0] });
      i += m[0].length;
    }
  }
  return out;
}

const HASHES: Record<string, IndicatorType> = { SHA256: "sha256", SHA1: "sha1", MD5: "md5" };

/** What a comparison on this object path means, or why it is not supported. */
function typeOf(object: string, property: string, key: string | null, value: string): IndicatorType {
  if (property === "value") {
    if (object === "ipv4-addr") return value.includes("/") ? "cidr" : "ipv4";
    if (object === "ipv6-addr") return value.includes("/") ? "cidr" : "ipv6";
    if (object === "domain-name") return "domain";
    if (object === "url") return "url";
    if (object === "email-addr") return "email";
  }
  if (object === "file" && property === "hashes" && key) {
    const type = HASHES[key.replace(/[^A-Za-z0-9]/g, "").toUpperCase()];
    if (type) return type;
    throw new StixPatternError(`the hash algorithm ${key} is not supported`);
  }
  throw new StixPatternError(`${object}:${property} is not supported`);
}

/**
 * The indicators a STIX 2.1 pattern asks for. Supported: one or more comparisons joined by OR, inside one pair of
 * brackets or in several joined by OR, with =, IN and ISSUBSET on addresses, domains, URLs, email addresses and file
 * hashes. Anything else (AND, FOLLOWEDBY, WITHIN, NOT, LIKE, MATCHES, other objects) is refused with its reason, so
 * the caller can say what was left out instead of dropping it silently.
 */
export function parseStixPattern(pattern: string): Array<{ type: IndicatorType; value: string }> {
  const toks = tokenize(pattern);
  let p = 0;
  const peek = () => toks[p];
  const word = (w: string) => peek()?.t === "word" && peek()!.v.toUpperCase() === w;
  const sym = (s: string) => peek()?.t === "sym" && peek()!.v === s;
  const expectSym = (s: string) => {
    if (!sym(s)) throw new StixPatternError(`expected ${s}`);
    p++;
  };
  const found: Array<{ type: IndicatorType; value: string }> = [];

  const addValue = (object: string, property: string, key: string | null, value: string) => {
    const type = typeOf(object, property, key, value);
    try {
      found.push(normalizeIndicator(type, value));
    } catch (err) {
      if (err instanceof NormalizeError) throw new StixPatternError(`${JSON.stringify(value.slice(0, 60))}: ${err.message}`);
      throw err;
    }
  };

  function comparison() {
    const t = peek();
    if (t?.t !== "word") throw new StixPatternError("expected an object path such as ipv4-addr:value");
    if (t.v.toUpperCase() === "NOT") throw new StixPatternError("NOT is not supported");
    const object = t.v.toLowerCase();
    p++;
    expectSym(":");
    const prop = peek();
    if (prop?.t !== "word") throw new StixPatternError("expected a property after the colon");
    p++;
    let key: string | null = null;
    if (sym(".")) {
      p++;
      const k = peek();
      if (!k || (k.t !== "str" && k.t !== "word")) throw new StixPatternError("expected a name after the dot");
      key = k.v;
      p++;
    }
    if (sym("[")) throw new StixPatternError("list indexes are not supported");
    // The path decides whether the comparison can be used at all, so say that before looking at its value.
    typeOf(object, prop.v.toLowerCase(), key, "");
    if (word("NOT")) throw new StixPatternError("NOT is not supported");
    const op = peek();
    if (!op) throw new StixPatternError("expected an operator");
    const name = op.v.toUpperCase();
    if (name === "=" || name === "ISSUBSET") {
      p++;
      const v = peek();
      if (v?.t !== "str") throw new StixPatternError("expected a string value");
      p++;
      addValue(object, prop.v.toLowerCase(), key, v.v);
    } else if (name === "IN") {
      p++;
      expectSym("(");
      for (;;) {
        const v = peek();
        if (v?.t !== "str") throw new StixPatternError("expected a string value");
        p++;
        addValue(object, prop.v.toLowerCase(), key, v.v);
        if (sym(",")) p++;
        else break;
      }
      expectSym(")");
    } else throw new StixPatternError(`the operator ${op.v} is not supported`);
  }

  function group() {
    expectSym("[");
    comparison();
    while (word("OR")) (p++, comparison());
    if (word("AND")) throw new StixPatternError("AND inside one observation needs all the conditions on one object, which an indicator list cannot say");
    expectSym("]");
  }

  if (!toks.length) throw new StixPatternError("the pattern is empty");
  group();
  while (p < toks.length) {
    if (word("OR")) (p++, group());
    else if (peek()) throw new StixPatternError(`${peek()!.v.toUpperCase()} is not supported`);
  }
  return found;
}
