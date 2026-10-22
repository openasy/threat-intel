import {
  AppShell,
  Badge,
  BrandProvider,
  Button,
  Callout,
  DataTable,
  Dialog,
  EmptyState,
  KpiCard,
  KpiGrid,
  navigate,
  PageHeader,
  Panel,
  PRODUCT_IDS,
  SegmentedControl,
  SelectField,
  StatusBadge,
  Switch,
  TextField,
  usePath,
  type Column,
  type ProductId,
  useThemePreference,
} from "@openasy/ui";
import { AccountSettings, AuthGate, MembersSettings, SignInSettings, TokensSettings, useAuth } from "@openasy/auth/react";
import { KeyRound, ListChecks, LogIn, LogOut, Plus, Rss, Search, Settings2, ShieldCheck, Trash2, Upload, UserRound, Users } from "lucide-react";
import { useCallback, useEffect, useState, type FormEvent, type ReactNode } from "react";
import { api, INDICATOR_TYPES, MfaSetupRequired, Unauthorized, type AllowEntry, type Feed, type FeedKind, type Indicator, type IndicatorType, type LookupResult, type ProductLink, type Severity, type Summary, type Tlp, type Verdict } from "./api.ts";

const plural = (n: number, one: string, many = `${one}s`) => `${n.toLocaleString()} ${n === 1 ? one : many}`;

const PAGES = ["indicators", "feeds", "allow-list", "setup", "account", "members", "signin", "tokens"] as const;
type Route = { page: "lookup" | (typeof PAGES)[number] };
/** The first path segments that are pages of this UI, for followLinks. */
export const PATHS = ["lookup", ...PAGES];
function parseRoute(path: string): Route {
  const [page] = path.replace(/^\//, "").split("/");
  if ((PAGES as readonly string[]).includes(page ?? "")) return { page: page as (typeof PAGES)[number] };
  return { page: "lookup" };
}

/** Data loading with the session; when it ends, the sign-in screen comes back. */
function useApi() {
  const { expired, refresh } = useAuth();
  return useCallback(
    async <T,>(path: string, init?: RequestInit): Promise<T> => {
      try {
        return await api<T>(path, init);
      } catch (err) {
        if (err instanceof Unauthorized) expired();
        if (err instanceof MfaSetupRequired) void refresh();
        throw err;
      }
    },
    [expired, refresh],
  );
}
type Call = ReturnType<typeof useApi>;

function ago(iso: string | null | undefined): string {
  if (!iso) return "never";
  const s = Math.round((Date.now() - Date.parse(iso)) / 1000);
  if (s < 60) return "just now";
  if (s < 3600) return `${Math.round(s / 60)} min ago`;
  if (s < 86_400) return `${Math.round(s / 3600)} h ago`;
  return `${Math.round(s / 86_400)} d ago`;
}
const date = (iso: string) => new Date(iso).toLocaleDateString();
const inDays = (d: number) => new Date(Date.now() + d * 86_400_000).toISOString();

const TYPE_LABEL: Record<IndicatorType, string> = { ipv4: "IPv4", ipv6: "IPv6", cidr: "Block", domain: "Domain", url: "URL", email: "Email", sha256: "SHA-256", sha1: "SHA-1", md5: "MD5" };
const TLP_TONE: Record<Tlp, "neutral" | "success" | "warning" | "danger"> = { clear: "neutral", green: "success", amber: "warning", red: "danger" };
const SEVERITY_TONE: Record<Severity, "critical" | "danger" | "warning" | "info"> = { critical: "critical", high: "danger", medium: "warning", low: "info" };
const VERDICT_TONE: Record<Verdict, "danger" | "warning" | "neutral" | "success"> = { malicious: "danger", suspicious: "warning", unknown: "neutral", allowed: "success" };
const VERDICT_LABEL: Record<Verdict, string> = { malicious: "Malicious", suspicious: "Suspicious", unknown: "Not known", allowed: "Allowed" };
const KIND_LABEL: Record<FeedKind, string> = { stix: "STIX 2.1", csv: "CSV", text: "Text list", manual: "Manual" };

const TlpBadge = ({ tlp }: { tlp: Tlp }) => <StatusBadge tone={TLP_TONE[tlp]}>{`TLP:${tlp.toUpperCase()}`}</StatusBadge>;
const SeverityBadge = ({ severity }: { severity: Severity }) => <StatusBadge tone={SEVERITY_TONE[severity]}>{severity}</StatusBadge>;

function Code({ children }: { children: ReactNode }) {
  return <pre className="m-0 overflow-x-auto rounded-md bg-subtle px-2.5 py-2 font-mono text-xs text-fg">{children}</pre>;
}

const TLPS: Array<{ value: Tlp; label: string }> = [
  { value: "clear", label: "TLP:CLEAR" },
  { value: "green", label: "TLP:GREEN" },
  { value: "amber", label: "TLP:AMBER" },
  { value: "red", label: "TLP:RED: editors and admins only" },
];
const SEVERITIES: Array<{ value: Severity; label: string }> = [
  { value: "critical", label: "Critical" },
  { value: "high", label: "High" },
  { value: "medium", label: "Medium" },
  { value: "low", label: "Low" },
];

// ---------------------------------------------------------------- Lookup

function LookupPage({ call, summary }: { call: Call; summary?: Summary }) {
  const [value, setValue] = useState(new URLSearchParams(window.location.search).get("value") ?? "");
  const [result, setResult] = useState<LookupResult>();
  const [error, setError] = useState<string>();

  const look = useCallback(
    async (v: string) => {
      if (!v.trim()) return;
      try {
        setResult(await call<LookupResult>(`/api/v1/lookup?value=${encodeURIComponent(v.trim())}`));
        setError(undefined);
      } catch (err) {
        setResult(undefined);
        setError((err as Error).message);
      }
    },
    [call],
  );
  // A value in the address, as the indicator list links to it, is looked up once.
  const [initial] = useState(value);
  useEffect(() => {
    if (initial) void look(initial);
  }, [initial, look]);

  const submit = (e: FormEvent) => {
    e.preventDefault();
    void look(value);
  };
  const r = result;
  type Match = LookupResult["matches"][number];
  const columns: Column<Match>[] = [
    { id: "value", header: "Indicator", width: "36%", cell: (m) => <span className="threat-intel-wrap font-mono text-xs">{m.value}</span> },
    { id: "via", header: "Matched", cell: (m) => <Badge>{m.via === "exact" ? "the value" : m.via === "cidr" ? "a block" : "a parent domain"}</Badge> },
    { id: "feed", header: "Feed", cell: (m) => m.feed.name },
    { id: "confidence", header: "Confidence", align: "right", cell: (m) => m.confidence },
    { id: "severity", header: "Severity", cell: (m) => <SeverityBadge severity={m.severity} /> },
    { id: "tlp", header: "TLP", cell: (m) => <TlpBadge tlp={m.tlp} /> },
    { id: "until", header: "Until", cell: (m) => <span className="whitespace-nowrap text-xs">{date(m.validUntil)}</span> },
  ];
  return (
    <>
      <PageHeader title="Look up" description="Is an address, domain, URL, email address or file hash known to be bad? Defanged values such as hxxp://bad[.]example are read too." />
      {summary && (
        <KpiGrid minWidth={150}>
          <KpiCard label="Active indicators" value={summary.indicators.active.toLocaleString()} href="/indicators" />
          <KpiCard label="Feeds" value={summary.feeds} href="/feeds" />
          <KpiCard label="Allowed values" value={summary.allowListed} href="/allow-list" />
          <KpiCard label="Lookups" value={summary.lookups.total.toLocaleString()} footer={`${summary.lookups.hits.toLocaleString()} matched, since the last start`} />
        </KpiGrid>
      )}
      <Panel>
        <form className="threat-intel-lookup flex flex-wrap items-end gap-2" onSubmit={submit}>
          <TextField label="Value" value={value} onChange={(e) => setValue(e.target.value)} placeholder="198.51.100.7, bad.example.com, a URL or a hash" mono error={error} />
          <Button type="submit" variant="primary" icon={<Search />} disabled={!value.trim()}>
            Look up
          </Button>
        </form>
      </Panel>
      {r && (
        <Panel
          title={
            <span className="flex flex-wrap items-center gap-2">
              <StatusBadge tone={VERDICT_TONE[r.verdict]}>{VERDICT_LABEL[r.verdict]}</StatusBadge>
              <span className="threat-intel-wrap font-mono">{r.value}</span>
              <Badge>{TYPE_LABEL[r.type]}</Badge>
            </span>
          }
          description={
            r.allowed
              ? `On the allow list until ${date(r.allowed.expiresAt)}: ${r.allowed.reason}`
              : r.verdict === "unknown"
                ? "No active indicator matches. That says nothing good about it, only that no feed has it."
                : `Confidence ${r.confidence}, from ${r.feeds.join(", ")}. Malicious from 60.`
          }
          flush={r.matches.length > 0}
        >
          {r.matches.length > 0 && <DataTable label="Matches" columns={columns} rows={r.matches} getRowId={(m) => m.id} minWidth={820} />}
        </Panel>
      )}
    </>
  );
}

// ---------------------------------------------------------------- Indicators

function IndicatorDialog({ call, feeds, onClose, onSaved }: { call: Call; feeds: Feed[]; onClose: () => void; onSaved: () => void }) {
  const manual = feeds.filter((f) => f.kind === "manual");
  const [feed, setFeed] = useState(manual[0]?.id ?? "");
  const [value, setValue] = useState("");
  const [type, setType] = useState("");
  const [confidence, setConfidence] = useState("");
  const [severity, setSeverity] = useState("");
  const [tlp, setTlp] = useState("");
  const [days, setDays] = useState("");
  const [labels, setLabels] = useState("");
  const [description, setDescription] = useState("");
  const [subdomains, setSubdomains] = useState(false);
  const [error, setError] = useState<string>();
  const save = async (e: FormEvent) => {
    e.preventDefault();
    try {
      await call("/api/v1/indicators", {
        method: "POST",
        body: JSON.stringify({
          feed,
          value,
          ...(type && { type }),
          ...(confidence && { confidence: Number(confidence) }),
          ...(severity && { severity }),
          ...(tlp && { tlp }),
          ...(days && { validUntil: inDays(Number(days)) }),
          ...(labels.trim() && { labels: labels.split(",").map((l) => l.trim()).filter(Boolean) }),
          ...(description.trim() && { description }),
          ...(subdomains && { includeSubdomains: true }),
        }),
      });
      onSaved();
    } catch (err) {
      setError((err as Error).message);
    }
  };
  return (
    <Dialog
      open
      onOpenChange={(o) => !o && onClose()}
      title="Add an indicator"
      description="Into a manual feed. What you leave empty takes the feed's defaults."
      onSubmit={save}
      footer={
        <>
          <Button type="button" onClick={onClose}>
            Cancel
          </Button>
          <Button type="submit" variant="primary" disabled={!feed || !value.trim()}>
            Add indicator
          </Button>
        </>
      }
    >
      {!manual.length ? (
        <Callout tone="info" title="No manual feed">
          An admin adds a feed of kind Manual under <a href="/feeds">Feeds</a> first.
        </Callout>
      ) : (
        <>
          <div className="grid gap-2 sm:grid-cols-2">
            <SelectField label="Feed" value={feed} onChange={(e) => setFeed(e.target.value)} options={manual.map((f) => ({ value: f.id, label: f.name }))} />
            <SelectField label="Type" value={type} onChange={(e) => setType(e.target.value)} options={[{ value: "", label: "As it looks" }, ...INDICATOR_TYPES.map((t) => ({ value: t, label: TYPE_LABEL[t] }))]} />
          </div>
          <TextField label="Value" value={value} onChange={(e) => setValue(e.target.value)} mono hint="Defanged is fine: hxxp://bad[.]example." />
          <div className="grid gap-2 sm:grid-cols-2">
            <TextField label="Confidence (0 to 100)" inputMode="numeric" value={confidence} onChange={(e) => setConfidence(e.target.value)} hint="Malicious from 60." />
            <TextField label="Active for (days)" inputMode="numeric" value={days} onChange={(e) => setDays(e.target.value)} />
            <SelectField label="Severity" value={severity} onChange={(e) => setSeverity(e.target.value)} options={[{ value: "", label: "The feed's default" }, ...SEVERITIES]} />
            <SelectField label="TLP" value={tlp} onChange={(e) => setTlp(e.target.value)} options={[{ value: "", label: "The feed's default" }, ...TLPS]} />
          </div>
          <TextField label="Labels" value={labels} onChange={(e) => setLabels(e.target.value)} hint="Comma-separated, such as phishing, c2." />
          <TextField label="Description" value={description} onChange={(e) => setDescription(e.target.value)} error={error} />
          {(type === "domain" || (!type && /^[^/:@]+\.[a-z]{2,}$/i.test(value.trim()))) && <Switch checked={subdomains} onCheckedChange={setSubdomains} label="Subdomains match too" />}
        </>
      )}
    </Dialog>
  );
}

function IndicatorsPage({ call, reload }: { call: Call; reload: () => void }) {
  const { can } = useAuth();
  const [rows, setRows] = useState<Indicator[]>();
  const [next, setNext] = useState<string>();
  const [feeds, setFeeds] = useState<Feed[]>([]);
  const [status, setStatus] = useState<"active" | "inactive" | "all">("active");
  const [type, setType] = useState("");
  const [feed, setFeed] = useState(new URLSearchParams(window.location.search).get("feed") ?? "");
  const [q, setQ] = useState("");
  const [adding, setAdding] = useState(false);
  const [removing, setRemoving] = useState<Indicator>();

  useEffect(() => void call<{ feeds: Feed[] }>("/api/v1/feeds?limit=500").then((r) => setFeeds(r.feeds), () => {}), [call]);
  const query = new URLSearchParams({ status, limit: "200", ...(type && { type }), ...(feed && { feed }), ...(q.trim() && { q: q.trim() }) }).toString();
  const load = useCallback(() => {
    setRows(undefined);
    void call<{ indicators: Indicator[]; nextCursor?: string }>(`/api/v1/indicators?${query}`).then(
      (r) => (setRows(r.indicators), setNext(r.nextCursor)),
      () => setRows([]),
    );
  }, [call, query]);
  useEffect(load, [load]);
  const more = () => next && void call<{ indicators: Indicator[]; nextCursor?: string }>(`/api/v1/indicators?${query}&cursor=${next}`).then((r) => (setRows((rs) => [...(rs ?? []), ...r.indicators]), setNext(r.nextCursor)));

  const columns: Column<Indicator>[] = [
    { id: "type", header: "Type", width: "90px", cell: (i) => <Badge>{TYPE_LABEL[i.type]}</Badge> },
    {
      id: "value",
      header: "Value",
      width: "34%",
      cell: (i) => (
        <span className="flex min-w-0 flex-col">
          <a href={`/lookup?value=${encodeURIComponent(i.value)}`} className="threat-intel-wrap font-mono text-xs">
            {i.value}
            {i.includeSubdomains ? " and subdomains" : ""}
          </a>
          {(i.labels.length > 0 || i.description) && <span className="threat-intel-clamp text-xs text-fg-muted" title={i.description ?? undefined}>{[i.labels.join(", "), i.description].filter(Boolean).join(" · ")}</span>}
        </span>
      ),
    },
    { id: "feed", header: "Feed", cell: (i) => <span className="text-xs">{i.feed.name}</span> },
    { id: "confidence", header: "Confidence", align: "right", sortValue: (i) => i.confidence, cell: (i) => i.confidence },
    { id: "severity", header: "Severity", cell: (i) => <SeverityBadge severity={i.severity} /> },
    { id: "tlp", header: "TLP", cell: (i) => <TlpBadge tlp={i.tlp} /> },
    { id: "until", header: "Until", sortValue: (i) => i.validUntil, cell: (i) => <span className="whitespace-nowrap text-xs">{i.revoked ? "Revoked" : date(i.validUntil)}</span> },
    ...(can("editor") ? [{ id: "remove", header: "", align: "right" as const, width: "56px", cell: (i: Indicator) => <Button size="sm" icon={<Trash2 />} aria-label={`Delete ${i.value}`} onClick={() => setRemoving(i)} /> }] : []),
  ];
  return (
    <>
      <PageHeader
        title="Indicators"
        description="What the feeds say is bad, for how long, and how sure they are. TLP:RED is shown to editors and admins only."
        actions={
          can("editor") && (
            <Button variant="primary" icon={<Plus />} onClick={() => setAdding(true)}>
              Add indicator
            </Button>
          )
        }
      />
      <div className="flex flex-wrap items-end gap-2">
        <SegmentedControl
          label="Status"
          value={status}
          onChange={setStatus}
          options={[
            { value: "active", label: "Active" },
            { value: "inactive", label: "Ended or revoked" },
            { value: "all", label: "All" },
          ]}
        />
        <SelectField label="Type" value={type} onChange={(e) => setType(e.target.value)} options={[{ value: "", label: "Any type" }, ...INDICATOR_TYPES.map((t) => ({ value: t, label: TYPE_LABEL[t] }))]} />
        <SelectField label="Feed" value={feed} onChange={(e) => setFeed(e.target.value)} options={[{ value: "", label: "Any feed" }, ...feeds.map((f) => ({ value: f.id, label: f.name }))]} />
        <TextField label="Contains" value={q} onChange={(e) => setQ(e.target.value)} />
      </div>
      <Panel flush>
        <DataTable label="Indicators" columns={columns} rows={rows ?? []} loading={!rows} getRowId={(i) => i.id} minWidth={980} pageSize={50} empty={<EmptyState title="No indicators">{status === "active" ? "Import a feed, or add one by hand. See Setup." : "None match."}</EmptyState>} />
      </Panel>
      {next && (
        <div>
          <Button onClick={more}>Load more</Button>
        </div>
      )}
      {adding && (
        <IndicatorDialog
          call={call}
          feeds={feeds}
          onClose={() => setAdding(false)}
          onSaved={() => {
            setAdding(false);
            load();
            reload();
          }}
        />
      )}
      {removing && (
        <Dialog
          open
          onOpenChange={(o) => !o && setRemoving(undefined)}
          title={`Delete ${removing.value}?`}
          description="If its feed sends it again, it comes back. To keep a value from matching, put it on the allow list instead."
          footer={
            <>
              <Button type="button" onClick={() => setRemoving(undefined)}>
                Cancel
              </Button>
              <Button type="button" variant="primary" onClick={() => void call(`/api/v1/indicators/${removing.id}`, { method: "DELETE" }).then(() => (setRemoving(undefined), load(), reload()))}>
                Delete
              </Button>
            </>
          }
        >
          <></>
        </Dialog>
      )}
    </>
  );
}

// ---------------------------------------------------------------- Feeds

function FeedDialog({ call, feed, onClose, onSaved }: { call: Call; feed?: Feed; onClose: () => void; onSaved: () => void }) {
  const [name, setName] = useState(feed?.name ?? "");
  const [kind, setKind] = useState<FeedKind>(feed?.kind ?? "stix");
  const [ttl, setTtl] = useState(String(feed?.defaultTtlDays ?? 30));
  const [confidence, setConfidence] = useState(String(feed?.defaultConfidence ?? 50));
  const [tlp, setTlp] = useState<Tlp>(feed?.defaultTlp ?? "amber");
  const [severity, setSeverity] = useState<Severity>(feed?.defaultSeverity ?? "medium");
  const [error, setError] = useState<string>();
  const save = async (e: FormEvent) => {
    e.preventDefault();
    const fields = { name, defaultTtlDays: Number(ttl), defaultConfidence: Number(confidence), defaultTlp: tlp, defaultSeverity: severity };
    try {
      if (feed) await call(`/api/v1/feeds/${feed.id}`, { method: "PATCH", body: JSON.stringify(fields) });
      else await call("/api/v1/feeds", { method: "POST", body: JSON.stringify({ ...fields, kind }) });
      onSaved();
    } catch (err) {
      setError((err as Error).message);
    }
  };
  return (
    <Dialog
      open
      onOpenChange={(o) => !o && onClose()}
      title={feed ? `Change ${feed.name}` : "Add a feed"}
      description="The defaults fill in what an indicator does not say. New defaults apply to what is stored from now on."
      onSubmit={save}
      footer={
        <>
          <Button type="button" onClick={onClose}>
            Cancel
          </Button>
          <Button type="submit" variant="primary" disabled={!name.trim()}>
            {feed ? "Save" : "Add feed"}
          </Button>
        </>
      }
    >
      <TextField label="Name" value={name} onChange={(e) => setName(e.target.value)} hint="Such as OpenCTI or Abuse.ch URLhaus." />
      {!feed && (
        <SelectField
          label="Kind"
          value={kind}
          onChange={(e) => setKind(e.target.value as FeedKind)}
          options={[
            { value: "stix", label: "STIX 2.1 bundle" },
            { value: "csv", label: "CSV with a value column" },
            { value: "text", label: "Text, one value per line" },
            { value: "manual", label: "Manual: added one at a time" },
          ]}
        />
      )}
      <div className="grid gap-2 sm:grid-cols-2">
        <TextField label="Active for (days)" inputMode="numeric" value={ttl} onChange={(e) => setTtl(e.target.value)} />
        <TextField label="Confidence (0 to 100)" inputMode="numeric" value={confidence} onChange={(e) => setConfidence(e.target.value)} hint="Malicious from 60." />
        <SelectField label="Severity" value={severity} onChange={(e) => setSeverity(e.target.value as Severity)} options={SEVERITIES} />
        <SelectField label="TLP" value={tlp} onChange={(e) => setTlp(e.target.value as Tlp)} options={TLPS} />
      </div>
      {error && <p className="m-0 text-xs text-danger">{error}</p>}
    </Dialog>
  );
}

type ImportResult = { received: number; created: number; updated: number; revoked: number; skippedCount: number; skipped: Array<{ ref: string; reason: string }>; unparsedCount: number; unparsed: Array<{ id: string; pattern: string; reason: string }> };

function ImportDialog({ call, feed, onClose, onDone }: { call: Call; feed: Feed; onClose: () => void; onDone: () => void }) {
  const [file, setFile] = useState<File>();
  const [result, setResult] = useState<ImportResult>();
  const [error, setError] = useState<string>();
  const [busy, setBusy] = useState(false);
  const send = async (e: FormEvent) => {
    e.preventDefault();
    if (!file) return;
    setBusy(true);
    try {
      const type = feed.kind === "stix" ? "application/json" : feed.kind === "csv" ? "text/csv" : "text/plain";
      setResult(await call<ImportResult>(`/api/v1/feeds/${feed.id}/import`, { method: "POST", body: file, headers: { "content-type": type } }));
      setError(undefined);
      onDone();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  };
  const problems = [...(result?.unparsed.map((u) => `${u.id}: ${u.reason}`) ?? []), ...(result?.skipped.map((s) => `${s.ref}: ${s.reason}`) ?? [])];
  return (
    <Dialog
      open
      onOpenChange={(o) => !o && onClose()}
      title={`Import into ${feed.name}`}
      description={`A ${KIND_LABEL[feed.kind]} file. Indicators the feed has are replaced; what cannot be read is listed, never dropped without a word.`}
      onSubmit={send}
      footer={
        <>
          <Button type="button" onClick={onClose}>
            {result ? "Close" : "Cancel"}
          </Button>
          {!result && (
            <Button type="submit" variant="primary" icon={<Upload />} disabled={!file || busy}>
              Import
            </Button>
          )}
        </>
      }
    >
      {!result ? (
        <label className="flex flex-col gap-1 text-sm">
          <span className="font-medium">File</span>
          <input type="file" accept={feed.kind === "stix" ? ".json,application/json" : feed.kind === "csv" ? ".csv,text/csv" : ".txt,text/plain"} onChange={(e) => setFile(e.target.files?.[0])} />
          {error && <span className="text-xs text-danger">{error}</span>}
        </label>
      ) : (
        <>
          <p className="m-0 text-sm">
            {plural(result.received, "entry", "entries")} read: {result.created} new, {result.updated} replaced{result.revoked ? `, ${result.revoked} revoked` : ""}.
          </p>
          {problems.length > 0 && (
            <Callout tone="warning" title={`${result.skippedCount + result.unparsedCount} left out`}>
              <ul className="threat-intel-list flex flex-col gap-0.5 text-xs">
                {problems.slice(0, 10).map((p) => (
                  <li key={p} className="threat-intel-wrap">
                    {p}
                  </li>
                ))}
              </ul>
            </Callout>
          )}
        </>
      )}
    </Dialog>
  );
}

function FeedsPage({ call, reload }: { call: Call; reload: () => void }) {
  const { can } = useAuth();
  const [rows, setRows] = useState<Feed[]>();
  const [adding, setAdding] = useState(false);
  const [editing, setEditing] = useState<Feed>();
  const [importing, setImporting] = useState<Feed>();
  const [removing, setRemoving] = useState<Feed>();
  const load = useCallback(() => void call<{ feeds: Feed[] }>("/api/v1/feeds?limit=500").then((r) => setRows(r.feeds), () => setRows([])), [call]);
  useEffect(load, [load]);

  const columns: Column<Feed>[] = [
    {
      id: "name",
      header: "Feed",
      width: "24%",
      sortValue: (f) => f.name,
      cell: (f) => (
        <span className="flex min-w-0 flex-col">
          <a href={`/indicators?feed=${f.id}`} className="font-medium">
            {f.name}
          </a>
          <span className="font-mono text-xs text-fg-muted">{f.id}</span>
        </span>
      ),
    },
    { id: "kind", header: "Kind", cell: (f) => <Badge>{KIND_LABEL[f.kind]}</Badge> },
    { id: "active", header: "Active", align: "right", sortValue: (f) => f.indicators.active, cell: (f) => `${f.indicators.active.toLocaleString()} of ${f.indicators.total.toLocaleString()}` },
    { id: "defaults", header: "Defaults", cell: (f) => <span className="text-xs">{`${f.defaultConfidence} confidence, ${f.defaultSeverity}, ${f.defaultTtlDays} days`}</span> },
    { id: "tlp", header: "TLP", cell: (f) => <TlpBadge tlp={f.defaultTlp} /> },
    { id: "last", header: "Last import", sortValue: (f) => f.lastImportAt ?? "", cell: (f) => <span className="whitespace-nowrap text-xs">{f.kind === "manual" ? "–" : ago(f.lastImportAt)}</span> },
    {
      id: "actions",
      header: "",
      align: "right",
      width: "200px",
      cell: (f) => (
        <span className="flex justify-end gap-1">
          {can("editor") && f.kind !== "manual" && (
            <Button size="sm" icon={<Upload />} onClick={() => setImporting(f)}>
              Import
            </Button>
          )}
          {can("admin") && (
            <>
              <Button size="sm" onClick={() => setEditing(f)}>
                Change
              </Button>
              <Button size="sm" icon={<Trash2 />} aria-label={`Delete ${f.name}`} onClick={() => setRemoving(f)} />
            </>
          )}
        </span>
      ),
    },
  ];
  return (
    <>
      <PageHeader
        title="Feeds"
        description="Where indicators come from. A job sends each feed with the ingest token; an editor can also import a file here."
        actions={
          can("admin") && (
            <Button variant="primary" icon={<Plus />} onClick={() => setAdding(true)}>
              Add feed
            </Button>
          )
        }
      />
      <Panel flush>
        <DataTable label="Feeds" columns={columns} rows={rows ?? []} loading={!rows} getRowId={(f) => f.id} minWidth={1000} empty={<EmptyState title="No feeds yet">{can("admin") ? "Add the first feed, then import into it. See Setup." : "An admin adds the feeds."}</EmptyState>} />
      </Panel>
      {(adding || editing) && (
        <FeedDialog
          call={call}
          feed={editing}
          onClose={() => (setAdding(false), setEditing(undefined))}
          onSaved={() => {
            setAdding(false);
            setEditing(undefined);
            load();
            reload();
          }}
        />
      )}
      {importing && <ImportDialog call={call} feed={importing} onClose={() => setImporting(undefined)} onDone={() => (load(), reload())} />}
      {removing && (
        <Dialog
          open
          onOpenChange={(o) => !o && setRemoving(undefined)}
          title={`Delete ${removing.name}?`}
          description={`Its ${plural(removing.indicators.total, "indicator")} are deleted with it, and stop matching at once.`}
          footer={
            <>
              <Button type="button" onClick={() => setRemoving(undefined)}>
                Cancel
              </Button>
              <Button type="button" variant="primary" onClick={() => void call(`/api/v1/feeds/${removing.id}`, { method: "DELETE" }).then(() => (setRemoving(undefined), load(), reload()))}>
                Delete
              </Button>
            </>
          }
        >
          <></>
        </Dialog>
      )}
    </>
  );
}

// ---------------------------------------------------------------- Allow list

function AllowDialog({ call, onClose, onSaved }: { call: Call; onClose: () => void; onSaved: () => void }) {
  const [value, setValue] = useState("");
  const [reason, setReason] = useState("");
  const [days, setDays] = useState("90");
  const [subdomains, setSubdomains] = useState(false);
  const [error, setError] = useState<string>();
  const save = async (e: FormEvent) => {
    e.preventDefault();
    try {
      await call("/api/v1/allow-list", { method: "POST", body: JSON.stringify({ value, reason, expiresAt: inDays(Number(days)), ...(subdomains && { includeSubdomains: true }) }) });
      onSaved();
    } catch (err) {
      setError((err as Error).message);
    }
  };
  return (
    <Dialog
      open
      onOpenChange={(o) => !o && onClose()}
      title="Allow a value"
      description="Every lookup answers allowed until it ends, whatever a feed says. A block allows every address in it."
      onSubmit={save}
      footer={
        <>
          <Button type="button" onClick={onClose}>
            Cancel
          </Button>
          <Button type="submit" variant="primary" disabled={!value.trim() || reason.trim().length < 3}>
            Allow
          </Button>
        </>
      }
    >
      <TextField label="Value" value={value} onChange={(e) => setValue(e.target.value)} mono hint="Such as 203.0.113.0/24 or example.com." />
      <TextField label="Reason" value={reason} onChange={(e) => setReason(e.target.value)} hint="Required: why it is fine, for whoever reads it next." />
      <SelectField
        label="For"
        value={days}
        onChange={(e) => setDays(e.target.value)}
        options={[
          { value: "30", label: "30 days" },
          { value: "90", label: "90 days" },
          { value: "180", label: "180 days" },
          { value: "365", label: "1 year" },
        ]}
      />
      <Switch checked={subdomains} onCheckedChange={setSubdomains} label="For a domain: its subdomains too" />
      {error && <p className="m-0 text-xs text-danger">{error}</p>}
    </Dialog>
  );
}

function AllowListPage({ call, reload }: { call: Call; reload: () => void }) {
  const { can } = useAuth();
  const [rows, setRows] = useState<AllowEntry[]>();
  const [adding, setAdding] = useState(false);
  const load = useCallback(() => void call<{ entries: AllowEntry[] }>("/api/v1/allow-list?limit=500").then((r) => setRows(r.entries), () => setRows([])), [call]);
  useEffect(load, [load]);
  const columns: Column<AllowEntry>[] = [
    { id: "type", header: "Type", width: "90px", cell: (a) => <Badge>{TYPE_LABEL[a.type]}</Badge> },
    { id: "value", header: "Value", width: "28%", cell: (a) => <span className="threat-intel-wrap font-mono text-xs">{a.value}{a.includeSubdomains ? " and subdomains" : ""}</span> },
    { id: "reason", header: "Reason", width: "30%", cell: (a) => <span className="threat-intel-clamp text-xs" title={a.reason}>{a.reason}</span> },
    { id: "by", header: "By", cell: (a) => <span className="text-xs">{a.by ?? ""}</span> },
    { id: "expires", header: "Until", sortValue: (a) => a.expiresAt, cell: (a) => (a.active ? <span className="whitespace-nowrap text-xs">{date(a.expiresAt)}</span> : <StatusBadge tone="neutral">Ended</StatusBadge>) },
    ...(can("editor")
      ? [{ id: "remove", header: "", align: "right" as const, width: "56px", cell: (a: AllowEntry) => <Button size="sm" icon={<Trash2 />} aria-label={`Remove ${a.value}`} onClick={() => void call(`/api/v1/allow-list/${a.id}`, { method: "DELETE" }).then(() => (load(), reload()))} /> }]
      : []),
  ];
  return (
    <>
      <PageHeader
        title="Allow list"
        description="Values known to be fine: your own scanners, partners, a shared host a feed blames. Each has a reason and an end."
        actions={
          can("editor") && (
            <Button variant="primary" icon={<Plus />} onClick={() => setAdding(true)}>
              Allow a value
            </Button>
          )
        }
      />
      <Panel flush>
        <DataTable label="Allow list" columns={columns} rows={rows ?? []} loading={!rows} getRowId={(a) => a.id} minWidth={860} empty={<EmptyState title="Nothing allowed">Values a feed gets wrong go here, with a reason and an end date.</EmptyState>} />
      </Panel>
      {adding && (
        <AllowDialog
          call={call}
          onClose={() => setAdding(false)}
          onSaved={() => {
            setAdding(false);
            load();
            reload();
          }}
        />
      )}
    </>
  );
}

// ---------------------------------------------------------------- Setup

function SetupPage() {
  const origin = window.location.origin;
  return (
    <>
      <PageHeader title="Setup" description="Add a feed, then send it from a job as often as its source changes. Other products look values up with the same token." />
      <Panel title="Import a feed" description="The body is the feed's kind: a STIX 2.1 bundle, a CSV with a value column, or one value per line. Gzip is fine. Use THREAT_INTEL_INGEST_TOKEN, set where threat-intel runs, or an API token with the editor role.">
        <Code>{`# a STIX 2.1 bundle, such as an export from OpenCTI or MISP
curl -sf -X POST -H "Authorization: Bearer $THREAT_INTEL_INGEST_TOKEN" \\
  --data-binary @bundle.json "${origin}/api/v1/feeds/<feed id>/import"

# a plain list, such as a blocklist
curl -sf https://feed.example.org/ips.txt | curl -sf -X POST \\
  -H "Authorization: Bearer $THREAT_INTEL_INGEST_TOKEN" -H 'content-type: text/plain' \\
  --data-binary @- "${origin}/api/v1/feeds/<feed id>/import"`}</Code>
      </Panel>
      <Panel title="Look values up" description="What SIEM, VPN, WAF and DAST ask. Up to 1000 values in one call.">
        <Code>{`curl -sf -H "Authorization: Bearer $THREAT_INTEL_INGEST_TOKEN" "${origin}/api/v1/lookup?value=198.51.100.7"

curl -sf -X POST -H "Authorization: Bearer $THREAT_INTEL_INGEST_TOKEN" -H 'content-type: application/json' \\
  -d '{"items":[{"value":"bad.example.com"},{"value":"hxxp://phish[.]example/login"}]}' "${origin}/api/v1/lookup"`}</Code>
      </Panel>
      <Panel title="What to know">
        <ul className="threat-intel-list flex flex-col gap-1 text-sm text-fg-muted">
          <li>A match with confidence 60 or more is malicious; below that, suspicious. A value nobody has is not known, which is not the same as safe.</li>
          <li>An address also matches the blocks that hold it; a domain also matches parents added with their subdomains.</li>
          <li>Indicators end on their valid-until date, or after the feed's default days. STIX patterns an indicator list cannot hold, such as AND, are listed in the import's answer.</li>
          <li>TLP:RED is for named recipients: viewers never see it, and their lookups answer as if it were not there.</li>
        </ul>
      </Panel>
    </>
  );
}

// ---------------------------------------------------------------- Shell

/** Account, Members, Sign-in and API tokens: the screens come from @openasy/auth. */
function SettingsPage({ page }: { page: "account" | "members" | "signin" | "tokens" }) {
  const { signOut, can } = useAuth();
  if (page !== "account" && !can("admin")) return <EmptyState title="Admins only">Ask an admin of this threat-intel for access.</EmptyState>;
  const titles = {
    account: ["Account", "Your profile, password, two-step verification and where you are signed in."],
    members: ["Members", "Who can sign in to this threat-intel, and with which role. Viewers see everything but TLP:RED; editors also see TLP:RED, add indicators, import and keep the allow list; admins also change feeds, and manage members and tokens."],
    signin: ["Sign-in", "Identity providers people can sign in with, such as OpenAsy Identity, Keycloak or Microsoft Entra ID, and which of their groups give which role."],
    tokens: ["API tokens", "For scripts and other products. Each token has one role and an expiry; the secret is shown once."],
  } as const;
  return (
    <>
      <PageHeader
        title={titles[page][0]}
        description={titles[page][1]}
        actions={
          page === "account" && (
            <Button icon={<LogOut />} onClick={() => void signOut()}>
              Sign out
            </Button>
          )
        }
      />
      {page === "account" ? <AccountSettings /> : page === "members" ? <MembersSettings /> : page === "signin" ? <SignInSettings /> : <TokensSettings />}
    </>
  );
}

function Product() {
  const [theme, setTheme] = useThemePreference();
  const { me, can } = useAuth();
  const route = parseRoute(usePath());
  const [summary, setSummary] = useState<Summary>();
  const [products, setProducts] = useState<Array<ProductLink & { id: ProductId }>>([]);
  const call = useApi();

  // The install's other products (OPENASY_PRODUCTS), for the switcher; ids this UI does not know are left out.
  useEffect(() => {
    void call<{ products: ProductLink[] }>("/api/v1/products").then(
      (r) => setProducts(r.products.filter((p): p is ProductLink & { id: ProductId } => p.id !== "threat-intel" && (PRODUCT_IDS as readonly string[]).includes(p.id))),
      () => {},
    );
  }, [call]);

  const reload = useCallback(() => void call<Summary>("/api/v1/summary").then(setSummary, () => {}), [call]);
  useEffect(() => {
    reload();
    const t = setInterval(reload, 30_000);
    return () => clearInterval(t);
  }, [reload]);

  const nav = [
    { id: "lookup", label: "Look up", icon: Search },
    { id: "indicators", label: "Indicators", icon: ListChecks, count: summary?.indicators.active },
    { id: "feeds", label: "Feeds", icon: Rss, count: summary?.feeds },
    { id: "allow-list", label: "Allow list", icon: ShieldCheck, count: summary?.allowListed || undefined },
  ];
  const footerNav = [
    { id: "setup", label: "Setup", icon: Settings2 },
    ...(can("admin")
      ? [
          { id: "members", label: "Members", icon: Users },
          { id: "signin", label: "Sign-in", icon: LogIn },
          { id: "tokens", label: "API tokens", icon: KeyRound },
        ]
      : []),
    { id: "account", label: "Account", icon: UserRound },
  ];
  const roleName = me.user.role.charAt(0).toUpperCase() + me.user.role.slice(1);

  return (
    <AppShell
      product="threat-intel"
      nav={nav}
      activeNav={route.page}
      onNavigate={(id) => navigate(`/${id}`)}
      connectedProducts={products.map((p) => p.id)}
      onSwitchProduct={(id) => {
        const to = products.find((p) => p.id === id);
        if (to) window.location.assign(to.url);
      }}
      footerNav={footerNav}
      user={{ name: me.user.name, role: roleName }}
      theme={theme}
      onThemeChange={setTheme}
    >
      {route.page === "lookup" ? (
        <LookupPage call={call} summary={summary} />
      ) : route.page === "indicators" ? (
        <IndicatorsPage call={call} reload={reload} />
      ) : route.page === "feeds" ? (
        <FeedsPage call={call} reload={reload} />
      ) : route.page === "allow-list" ? (
        <AllowListPage call={call} reload={reload} />
      ) : route.page === "account" || route.page === "members" || route.page === "signin" || route.page === "tokens" ? (
        <SettingsPage page={route.page} />
      ) : (
        <SetupPage />
      )}
    </AppShell>
  );
}

export function App() {
  const [theme] = useThemePreference();
  return (
    // No organization until branding is configurable (ADR 0004); the library's default is a placeholder.
    <BrandProvider theme={theme} brand={{ name: "OpenAsy", organization: undefined }} className="min-h-screen">
      <AuthGate product="OpenAsy Threat Intel">
        <Product />
      </AuthGate>
    </BrandProvider>
  );
}
