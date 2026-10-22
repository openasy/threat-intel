# threat-intel

[![CI](https://github.com/openasy/threat-intel/actions/workflows/ci.yml/badge.svg)](https://github.com/openasy/threat-intel/actions/workflows/ci.yml)
[![Node.js 26 LTS](https://img.shields.io/badge/node-26%20LTS-339933?logo=nodedotjs&logoColor=white)](./.nvmrc)
[![License: AGPL-3.0](https://img.shields.io/badge/license-AGPL--3.0-blue)](./LICENSE)

The [OpenAsy](https://github.com/openasy) Threat Intel product: **indicators from STIX, CSV and text feeds, one lookup for
the other products, and an allow list with reasons** (ADR 0050). Is this address, domain, URL, email address or file
hash known to be bad, how sure is anyone, and who said so?

```
OpenCTI, MISP, a blocklist ──POST /api/v1/feeds/{id}/import──▶  threat-intel  ◀──GET|POST /api/v1/lookup── SIEM, VPN, WAF, DAST
                                                                  ├── verdict: malicious | suspicious | unknown | allowed
                                                                  └── the matches, their feed, confidence, severity and TLP
```

## Feeds and indicators

A **feed** is where indicators come from, and its kind says how it takes them:

| Kind | Body |
| --- | --- |
| `stix` | A STIX 2.1 bundle. Patterns of `=`, `IN` and `ISSUBSET` on `ipv4-addr`, `ipv6-addr`, `domain-name`, `url`, `email-addr` and `file:hashes` (SHA-256, SHA-1, MD5), joined by OR. Confidence, validity, TLP markings, labels and revocation are kept |
| `csv` | A header row with `value` and optionally `type`, `confidence`, `tlp`, `severity`, `tags`, `description`, `valid_from`, `valid_until`, `include_subdomains` |
| `text` | One value per line; `#` starts a comment |
| `manual` | Indicators added one at a time in the UI or the API |

- Values are stored in one form: defanged values (`hxxp://bad[.]example`) are read, domains lowercased and converted to
  punycode, IPv6 compressed, the host bits of a block cleared, credentials and fragments dropped from URLs. An address
  with leading zeros (`010.0.0.1`), which software reads differently, is refused.
- What a feed does not say comes from its defaults: active for 30 days, confidence 50, TLP:AMBER, medium severity.
- An indicator the feed already has is replaced, so a feed can be sent again whole.
- **Nothing is dropped without a word.** A STIX pattern an indicator list cannot hold (AND, FOLLOWEDBY, other objects
  such as `network-traffic`) is named in the answer with its reason, and so is a row or line with a wrong value.

```bash
curl -sf -X POST -H "Authorization: Bearer $THREAT_INTEL_INGEST_TOKEN" --data-binary @bundle.json \
  https://intel.example.com/api/v1/feeds/<feed id>/import
```

## Lookup

```bash
curl -sf -H "Authorization: Bearer $THREAT_INTEL_INGEST_TOKEN" "https://intel.example.com/api/v1/lookup?value=198.51.100.7"
curl -sf -X POST -H "Authorization: Bearer $THREAT_INTEL_INGEST_TOKEN" -H 'content-type: application/json' \
  -d '{"items":[{"value":"bad.example.com"},{"value":"hxxp://phish[.]example/login"}]}' https://intel.example.com/api/v1/lookup
```

- Only **active** indicators count: not revoked, and now between their valid-from and valid-until.
- An address also matches the **blocks** that hold it, and a domain the parent domains added with their subdomains.
- The **verdict** is `malicious` when a match has confidence 60 or more, `suspicious` below that, `unknown` when nothing
  matches (which is not the same as safe), and `allowed` when the allow list has the value, whatever matched.
- Up to 1000 values in one call.

## The allow list

Values known to be fine, such as your own scanners or a shared host a feed blames, answer `allowed` until they expire.
Each entry needs a reason and ends within a year: a decision without a reason is lost the day its author leaves.

## TLP

TLP:RED is for named recipients. Editors, admins and the ingest token see it; for viewers, it does not exist, in lists,
pages and lookups alike.

## Run

```bash
openssl rand -hex 32 > openasy-kek
export THREAT_INTEL_INGEST_TOKEN=$(openssl rand -hex 32)
docker compose up -d
docker compose logs threat-intel | grep 'no owner yet'
```

Open the link from the log once to create the owner account; there is no default password (ADR 0013). The UI and API
are on http://localhost:8080, the API reference at http://localhost:8080/api/docs/.

`openasy-kek` encrypts sign-in secrets in the database (ADR 0021). Keep it apart from the volume and with your backups.

| Variable | Default | |
| --- | --- | --- |
| `PORT` | `8080` | HTTP port |
| `THREAT_INTEL_PUBLIC_URL` | `http://localhost:8080` | The address people open, with `https://` behind your TLS proxy |
| `OPENASY_PRODUCTS` | | The install's other OpenAsy products, for the product switcher. Give every product the same value |
| `THREAT_INTEL_INGEST_TOKEN` | | Lets jobs import feeds and products look values up, and nothing else. An API token works too: editor to import, viewer to look up |
| `THREAT_INTEL_SECRETS_KEY_FILE` | `/run/secrets/openasy-kek` | 32-byte key-encryption key |
| `THREAT_INTEL_DB` | `/data/threat-intel.db` | SQLite file (WAL), on the `/data` volume |
| `THREAT_INTEL_RETENTION_DAYS` | `365` | Indicators that ended, and allow-list entries that expired, this long ago are deleted |
| `THREAT_INTEL_METRICS_PORT` | | Serve `/metrics` on this port only (ADR 0026) |
| `THREAT_INTEL_HEADLESS` | `false` | `true` serves only the API |
| `THREAT_INTEL_PASSWORD_SIGN_IN`, `THREAT_INTEL_OIDC_*` | | Sign-in, as in every OpenAsy product ([@openasy/auth](https://github.com/openasy/auth)) |

`/metrics` has `openasy_threat_intel_indicators{type}`, `openasy_threat_intel_feeds`, `openasy_threat_intel_allow_list`,
`openasy_threat_intel_lookups_total` and `openasy_threat_intel_lookup_hits_total`.

The container runs as non-root with a read-only root filesystem, no capabilities and `no-new-privileges`.

## Roles

Viewers see everything but TLP:RED and look values up; editors also see TLP:RED, add and delete indicators, import and
keep the allow list; admins also add, change and delete feeds, and manage members and API tokens (ADR 0003).

## Develop

```bash
npm install
npm test        # normalizing values, STIX patterns, imports, lookups through blocks and parent domains, TLP, and every API response against openapi.json
npm run dev     # the UI, with the API on :8080
```

## Licence

AGPL-3.0 (ADR 0008).
