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
  useAgo,
} from "@openasy/ui";
import { AccountSettings, AuthGate, MembersSettings, SignInSettings, TokensSettings, useAuth } from "@openasy/auth/react";
import { KeyRound, ListChecks, LogIn, LogOut, Plus, Rss, Search, Settings2, ShieldCheck, Trash2, Upload, UserRound, Users } from "lucide-react";
import { useCallback, useEffect, useState, type FormEvent, type ReactNode } from "react";
import { api, INDICATOR_TYPES, MfaSetupRequired, Unauthorized, type AllowEntry, type Feed, type FeedKind, type Indicator, type IndicatorType, type LookupResult, type ProductLink, type Severity, type Summary, type Tlp, type Verdict } from "./api.ts";
import { useT, type T } from "./i18n.ts";

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
const date = (iso: string) => new Date(iso).toLocaleDateString();
const inDays = (d: number) => new Date(Date.now() + d * 86_400_000).toISOString();

const TYPE_LABEL: Record<IndicatorType, string> = { ipv4: "IPv4", ipv6: "IPv6", cidr: "Block", domain: "Domain", url: "URL", email: "Email", sha256: "SHA-256", sha1: "SHA-1", md5: "MD5" };
const TLP_TONE: Record<Tlp, "neutral" | "success" | "warning" | "danger"> = { clear: "neutral", green: "success", amber: "warning", red: "danger" };
const SEVERITY_TONE: Record<Severity, "critical" | "danger" | "warning" | "info"> = { critical: "critical", high: "danger", medium: "warning", low: "info" };
const VERDICT_TONE: Record<Verdict, "danger" | "warning" | "neutral" | "success"> = { malicious: "danger", suspicious: "warning", unknown: "neutral", allowed: "success" };
const VERDICT_LABEL = (t: T): Record<Verdict, string> => ({ malicious: "Malicious", suspicious: "Suspicious", unknown: t("verdictLabel.notKnown"), allowed: "Allowed" });
const KIND_LABEL = (t: T): Record<FeedKind, string> => ({ stix: "STIX 2.1", csv: "CSV", text: t("kindLabel.textList"), manual: "Manual" });

const TlpBadge = ({ tlp }: { tlp: Tlp }) => {
  const t = useT();
  return <StatusBadge tone={TLP_TONE[tlp]}>{t("tlpBadge.tlp", { value: tlp.toUpperCase() })}</StatusBadge>;
};
const SeverityBadge = ({ severity }: { severity: Severity }) => <StatusBadge tone={SEVERITY_TONE[severity]}>{severity}</StatusBadge>;

function Code({ children }: { children: ReactNode }) {
  return <pre className="m-0 overflow-x-auto rounded-md bg-subtle px-2.5 py-2 font-mono text-xs text-fg">{children}</pre>;
}

const TLPS = (t: T): Array<{ value: Tlp; label: string }> => ([
  { value: "clear", label: t("tlps.tlpClear") },
  { value: "green", label: t("tlps.tlpGreen") },
  { value: "amber", label: t("tlps.tlpAmber") },
  { value: "red", label: t("tlps.tlpRedEditorsAndAdmins") },
]);
const SEVERITIES = (t: T): Array<{ value: Severity; label: string }> => ([
  { value: "critical", label: t("severities.critical") },
  { value: "high", label: t("severities.high") },
  { value: "medium", label: t("severities.medium") },
  { value: "low", label: t("severities.low") },
]);

// ---------------------------------------------------------------- Lookup

function LookupPage({ call, summary }: { call: Call; summary?: Summary }) {
  const t = useT();
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
    { id: "value", header: t("lookupPage.indicator"), width: "36%", cell: (m) => <span className="threat-intel-wrap font-mono text-xs">{m.value}</span> },
    { id: "via", header: t("lookupPage.matched"), cell: (m) => <Badge>{m.via === "exact" ? t("lookupPage.theValue") : m.via === "cidr" ? t("lookupPage.aBlock") : t("lookupPage.aParentDomain")}</Badge> },
    { id: "feed", header: t("lookupPage.feed"), cell: (m) => m.feed.name },
    { id: "confidence", header: t("lookupPage.confidence"), align: "right", cell: (m) => m.confidence },
    { id: "severity", header: t("lookupPage.severity"), cell: (m) => <SeverityBadge severity={m.severity} /> },
    { id: "tlp", header: "TLP", cell: (m) => <TlpBadge tlp={m.tlp} /> },
    { id: "until", header: t("lookupPage.until"), cell: (m) => <span className="whitespace-nowrap text-xs">{date(m.validUntil)}</span> },
  ];
  return (
    <>
      <PageHeader title={t("lookupPage.lookUp")} description="Is an address, domain, URL, email address or file hash known to be bad? Defanged values such as hxxp://bad[.]example are read too." />
      {summary && (
        <KpiGrid minWidth={150}>
          <KpiCard label={t("lookupPage.activeIndicators")} value={summary.indicators.active.toLocaleString()} href="/indicators" />
          <KpiCard label={t("lookupPage.feeds")} value={summary.feeds} href="/feeds" />
          <KpiCard label={t("lookupPage.allowedValues")} value={summary.allowListed} href="/allow-list" />
          <KpiCard label={t("lookupPage.lookups")} value={summary.lookups.total.toLocaleString()} footer={t("lookupPage.matchedSinceTheLastStart", { value: summary.lookups.hits.toLocaleString() })} />
        </KpiGrid>
      )}
      <Panel>
        <form className="threat-intel-lookup flex flex-wrap items-end gap-2" onSubmit={submit}>
          <TextField label={t("lookupPage.value")} value={value} onChange={(e) => setValue(e.target.value)} placeholder={t("lookupPage.n198511007Bad")} mono error={error} />
          <Button type="submit" variant="primary" icon={<Search />} disabled={!value.trim()}>
            {t("lookupPage.lookUp")}
          </Button>
        </form>
      </Panel>
      {r && (
        <Panel
          title={
            <span className="flex flex-wrap items-center gap-2">
              <StatusBadge tone={VERDICT_TONE[r.verdict]}>{VERDICT_LABEL(t)[r.verdict]}</StatusBadge>
              <span className="threat-intel-wrap font-mono">{r.value}</span>
              <Badge>{TYPE_LABEL[r.type]}</Badge>
            </span>
          }
          description={
            r.allowed
              ? t("lookupPage.onTheAllowListUntil", { date: date(r.allowed.expiresAt), reason: r.allowed.reason })
              : r.verdict === "unknown"
                ? t("lookupPage.noActiveIndicatorMatchesThat")
                : t("lookupPage.confidenceFromMaliciousFrom60", { confidence: String(r.confidence), value: r.feeds.join(", ") })
          }
          flush={r.matches.length > 0}
        >
          {r.matches.length > 0 && <DataTable label={t("lookupPage.matches")} columns={columns} rows={r.matches} getRowId={(m) => m.id} minWidth={820} />}
        </Panel>
      )}
    </>
  );
}

// ---------------------------------------------------------------- Indicators

function IndicatorDialog({ call, feeds, onClose, onSaved }: { call: Call; feeds: Feed[]; onClose: () => void; onSaved: () => void }) {
  const msg = useT();
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
      title={msg("indicatorDialog.addAnIndicator")}
      description={msg("indicatorDialog.intoAManualFeedWhat")}
      onSubmit={save}
      footer={
        <>
          <Button type="button" onClick={onClose}>
            {msg("indicatorDialog.cancel")}
          </Button>
          <Button type="submit" variant="primary" disabled={!feed || !value.trim()}>
            {msg("indicatorDialog.addIndicator")}
          </Button>
        </>
      }
    >
      {!manual.length ? (
        <Callout tone="info" title={msg("indicatorDialog.noManualFeed")}>
          {msg("indicatorDialog.anAdminAddsAFeed")}{" "}<a href="/feeds">{msg("indicatorDialog.feeds")}</a> first.
        </Callout>
      ) : (
        <>
          <div className="grid gap-2 sm:grid-cols-2">
            <SelectField label={msg("indicatorDialog.feed")} value={feed} onChange={(e) => setFeed(e.target.value)} options={manual.map((f) => ({ value: f.id, label: f.name }))} />
            <SelectField label={msg("indicatorDialog.type")} value={type} onChange={(e) => setType(e.target.value)} options={[{ value: "", label: msg("indicatorDialog.asItLooks") }, ...INDICATOR_TYPES.map((t) => ({ value: t, label: TYPE_LABEL[t] }))]} />
          </div>
          <TextField label={msg("indicatorDialog.value")} value={value} onChange={(e) => setValue(e.target.value)} mono hint="Defanged is fine: hxxp://bad[.]example." />
          <div className="grid gap-2 sm:grid-cols-2">
            <TextField label={msg("indicatorDialog.confidence0To100")} inputMode="numeric" value={confidence} onChange={(e) => setConfidence(e.target.value)} hint={msg("indicatorDialog.maliciousFrom60")} />
            <TextField label={msg("indicatorDialog.activeForDays")} inputMode="numeric" value={days} onChange={(e) => setDays(e.target.value)} />
            <SelectField label={msg("indicatorDialog.severity")} value={severity} onChange={(e) => setSeverity(e.target.value)} options={[{ value: "", label: msg("indicatorDialog.theFeedSDefault") }, ...SEVERITIES(msg)]} />
            <SelectField label="TLP" value={tlp} onChange={(e) => setTlp(e.target.value)} options={[{ value: "", label: msg("indicatorDialog.theFeedSDefault") }, ...TLPS(msg)]} />
          </div>
          <TextField label={msg("indicatorDialog.labels")} value={labels} onChange={(e) => setLabels(e.target.value)} hint={msg("indicatorDialog.commaSeparatedSuchAsPhishing")} />
          <TextField label={msg("indicatorDialog.description")} value={description} onChange={(e) => setDescription(e.target.value)} error={error} />
          {(type === "domain" || (!type && /^[^/:@]+\.[a-z]{2,}$/i.test(value.trim()))) && <Switch checked={subdomains} onCheckedChange={setSubdomains} label={msg("indicatorDialog.subdomainsMatchToo")} />}
        </>
      )}
    </Dialog>
  );
}

function IndicatorsPage({ call, reload }: { call: Call; reload: () => void }) {
  const msg = useT();
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
    { id: "type", header: msg("indicatorsPage.type"), width: "90px", cell: (i) => <Badge>{TYPE_LABEL[i.type]}</Badge> },
    {
      id: "value",
      header: msg("indicatorsPage.value"),
      width: "34%",
      cell: (i) => (
        <span className="flex min-w-0 flex-col">
          <a href={`/lookup?value=${encodeURIComponent(i.value)}`} className="threat-intel-wrap font-mono text-xs">
            {i.value}
            {i.includeSubdomains ? msg("indicatorsPage.andSubdomains") : ""}
          </a>
          {(i.labels.length > 0 || i.description) && <span className="threat-intel-clamp text-xs text-fg-muted" title={i.description ?? undefined}>{[i.labels.join(", "), i.description].filter(Boolean).join(" · ")}</span>}
        </span>
      ),
    },
    { id: "feed", header: msg("indicatorsPage.feed"), cell: (i) => <span className="text-xs">{i.feed.name}</span> },
    { id: "confidence", header: msg("indicatorsPage.confidence"), align: "right", sortValue: (i) => i.confidence, cell: (i) => i.confidence },
    { id: "severity", header: msg("indicatorsPage.severity"), cell: (i) => <SeverityBadge severity={i.severity} /> },
    { id: "tlp", header: "TLP", cell: (i) => <TlpBadge tlp={i.tlp} /> },
    { id: "until", header: msg("indicatorsPage.until"), sortValue: (i) => i.validUntil, cell: (i) => <span className="whitespace-nowrap text-xs">{i.revoked ? msg("indicatorsPage.revoked") : date(i.validUntil)}</span> },
    ...(can("editor") ? [{ id: "remove", header: "", align: "right" as const, width: "56px", cell: (i: Indicator) => <Button size="sm" icon={<Trash2 />} aria-label={msg("indicatorsPage.delete", { value: i.value })} onClick={() => setRemoving(i)} /> }] : []),
  ];
  return (
    <>
      <PageHeader
        title={msg("indicatorsPage.indicators")}
        description={msg("indicatorsPage.whatTheFeedsSayIs")}
        actions={
          can("editor") && (
            <Button variant="primary" icon={<Plus />} onClick={() => setAdding(true)}>
              {msg("indicatorsPage.addIndicator")}
            </Button>
          )
        }
      />
      <div className="flex flex-wrap items-end gap-2">
        <SegmentedControl
          label={msg("indicatorsPage.status")}
          value={status}
          onChange={setStatus}
          options={[
            { value: "active", label: msg("indicatorsPage.active") },
            { value: "inactive", label: msg("indicatorsPage.endedOrRevoked") },
            { value: "all", label: msg("indicatorsPage.all") },
          ]}
        />
        <SelectField label={msg("indicatorsPage.type")} value={type} onChange={(e) => setType(e.target.value)} options={[{ value: "", label: msg("indicatorsPage.anyType") }, ...INDICATOR_TYPES.map((t) => ({ value: t, label: TYPE_LABEL[t] }))]} />
        <SelectField label={msg("indicatorsPage.feed")} value={feed} onChange={(e) => setFeed(e.target.value)} options={[{ value: "", label: msg("indicatorsPage.anyFeed") }, ...feeds.map((f) => ({ value: f.id, label: f.name }))]} />
        <TextField label={msg("indicatorsPage.contains")} value={q} onChange={(e) => setQ(e.target.value)} />
      </div>
      <Panel flush>
        <DataTable label={msg("indicatorsPage.indicators")} columns={columns} rows={rows ?? []} loading={!rows} getRowId={(i) => i.id} minWidth={980} pageSize={50} empty={<EmptyState title={msg("indicatorsPage.noIndicators")}>{status === "active" ? msg("indicatorsPage.importAFeedOrAdd") : msg("indicatorsPage.noneMatch")}</EmptyState>} />
      </Panel>
      {next && (
        <div>
          <Button onClick={more}>{msg("indicatorsPage.loadMore")}</Button>
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
          title={msg("indicatorsPage.delete2", { value: removing.value })}
          description={msg("indicatorsPage.ifItsFeedSendsIt")}
          footer={
            <>
              <Button type="button" onClick={() => setRemoving(undefined)}>
                {msg("indicatorsPage.cancel")}
              </Button>
              <Button type="button" variant="primary" onClick={() => void call(`/api/v1/indicators/${removing.id}`, { method: "DELETE" }).then(() => (setRemoving(undefined), load(), reload()))}>
                {msg("indicatorsPage.delete3")}
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
  const t = useT();
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
      title={feed ? t("feedDialog.change", { name: feed.name }) : t("feedDialog.addAFeed")}
      description={t("feedDialog.theDefaultsFillInWhat")}
      onSubmit={save}
      footer={
        <>
          <Button type="button" onClick={onClose}>
            {t("feedDialog.cancel")}
          </Button>
          <Button type="submit" variant="primary" disabled={!name.trim()}>
            {feed ? t("feedDialog.save") : t("feedDialog.addFeed")}
          </Button>
        </>
      }
    >
      <TextField label={t("feedDialog.name")} value={name} onChange={(e) => setName(e.target.value)} hint={t("feedDialog.suchAsOpenctiOrAbuse")} />
      {!feed && (
        <SelectField
          label={t("feedDialog.kind")}
          value={kind}
          onChange={(e) => setKind(e.target.value as FeedKind)}
          options={[
            { value: "stix", label: t("feedDialog.stix21Bundle") },
            { value: "csv", label: t("feedDialog.csvWithAValueColumn") },
            { value: "text", label: t("feedDialog.textOneValuePerLine") },
            { value: "manual", label: t("feedDialog.manualAddedOneAtA") },
          ]}
        />
      )}
      <div className="grid gap-2 sm:grid-cols-2">
        <TextField label={t("feedDialog.activeForDays")} inputMode="numeric" value={ttl} onChange={(e) => setTtl(e.target.value)} />
        <TextField label={t("feedDialog.confidence0To100")} inputMode="numeric" value={confidence} onChange={(e) => setConfidence(e.target.value)} hint={t("feedDialog.maliciousFrom60")} />
        <SelectField label={t("feedDialog.severity")} value={severity} onChange={(e) => setSeverity(e.target.value as Severity)} options={SEVERITIES(t)} />
        <SelectField label="TLP" value={tlp} onChange={(e) => setTlp(e.target.value as Tlp)} options={TLPS(t)} />
      </div>
      {error && <p className="m-0 text-xs text-danger">{error}</p>}
    </Dialog>
  );
}

type ImportResult = { received: number; created: number; updated: number; revoked: number; skippedCount: number; skipped: Array<{ ref: string; reason: string }>; unparsedCount: number; unparsed: Array<{ id: string; pattern: string; reason: string }> };

function ImportDialog({ call, feed, onClose, onDone }: { call: Call; feed: Feed; onClose: () => void; onDone: () => void }) {
  const t = useT();
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
      title={t("importDialog.importInto", { name: feed.name })}
      description={t("importDialog.aFileIndicatorsTheFeed", { value: KIND_LABEL(t)[feed.kind] })}
      onSubmit={send}
      footer={
        <>
          <Button type="button" onClick={onClose}>
            {result ? t("importDialog.close") : t("importDialog.cancel")}
          </Button>
          {!result && (
            <Button type="submit" variant="primary" icon={<Upload />} disabled={!file || busy}>
              {t("importDialog.import")}
            </Button>
          )}
        </>
      }
    >
      {!result ? (
        <label className="flex flex-col gap-1 text-sm">
          <span className="font-medium">{t("importDialog.file")}</span>
          <input type="file" accept={feed.kind === "stix" ? ".json,application/json" : feed.kind === "csv" ? ".csv,text/csv" : ".txt,text/plain"} onChange={(e) => setFile(e.target.files?.[0])} />
          {error && <span className="text-xs text-danger">{error}</span>}
        </label>
      ) : (
        <>
          <p className="m-0 text-sm">
            {t("plurals.entry", { count: result.received })} read: {result.created} new, {result.updated} replaced{result.revoked ? t("importDialog.revoked", { revoked: result.revoked }) : ""}.
          </p>
          {problems.length > 0 && (
            <Callout tone="warning" title={t("importDialog.leftOut", { value: result.skippedCount + result.unparsedCount })}>
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
  const ago = useAgo();
  const t = useT();
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
      header: t("feedsPage.feed"),
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
    { id: "kind", header: t("feedsPage.kind"), cell: (f) => <Badge>{KIND_LABEL(t)[f.kind]}</Badge> },
    { id: "active", header: t("feedsPage.active"), align: "right", sortValue: (f) => f.indicators.active, cell: (f) => `${f.indicators.active.toLocaleString()} of ${f.indicators.total.toLocaleString()}` },
    { id: "defaults", header: t("feedsPage.defaults"), cell: (f) => <span className="text-xs">{t("feedsPage.confidenceDays", { defaultConfidence: f.defaultConfidence, defaultSeverity: f.defaultSeverity, defaultTtlDays: f.defaultTtlDays })}</span> },
    { id: "tlp", header: "TLP", cell: (f) => <TlpBadge tlp={f.defaultTlp} /> },
    { id: "last", header: t("feedsPage.lastImport"), sortValue: (f) => f.lastImportAt ?? "", cell: (f) => <span className="whitespace-nowrap text-xs">{f.kind === "manual" ? "–" : ago(f.lastImportAt)}</span> },
    {
      id: "actions",
      header: "",
      align: "right",
      width: "200px",
      cell: (f) => (
        <span className="flex justify-end gap-1">
          {can("editor") && f.kind !== "manual" && (
            <Button size="sm" icon={<Upload />} onClick={() => setImporting(f)}>
              {t("feedsPage.import")}
            </Button>
          )}
          {can("admin") && (
            <>
              <Button size="sm" onClick={() => setEditing(f)}>
                {t("feedsPage.change")}
              </Button>
              <Button size="sm" icon={<Trash2 />} aria-label={t("feedsPage.delete", { name: f.name })} onClick={() => setRemoving(f)} />
            </>
          )}
        </span>
      ),
    },
  ];
  return (
    <>
      <PageHeader
        title={t("feedsPage.feeds")}
        description={t("feedsPage.whereIndicatorsComeFromA")}
        actions={
          can("admin") && (
            <Button variant="primary" icon={<Plus />} onClick={() => setAdding(true)}>
              {t("feedsPage.addFeed")}
            </Button>
          )
        }
      />
      <Panel flush>
        <DataTable label={t("feedsPage.feeds")} columns={columns} rows={rows ?? []} loading={!rows} getRowId={(f) => f.id} minWidth={1000} empty={<EmptyState title={t("feedsPage.noFeedsYet")}>{can("admin") ? t("feedsPage.addTheFirstFeedThen") : t("feedsPage.anAdminAddsTheFeeds")}</EmptyState>} />
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
          title={t("feedsPage.delete2", { name: removing.name })}
          description={t("feedsPage.itsAreDeletedWithIt", { plural: t("plurals.indicator", { count: removing.indicators.total }) })}
          footer={
            <>
              <Button type="button" onClick={() => setRemoving(undefined)}>
                {t("feedsPage.cancel")}
              </Button>
              <Button type="button" variant="primary" onClick={() => void call(`/api/v1/feeds/${removing.id}`, { method: "DELETE" }).then(() => (setRemoving(undefined), load(), reload()))}>
                {t("feedsPage.delete3")}
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
  const t = useT();
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
      title={t("allowDialog.allowAValue")}
      description={t("allowDialog.everyLookupAnswersAllowedUntil")}
      onSubmit={save}
      footer={
        <>
          <Button type="button" onClick={onClose}>
            {t("allowDialog.cancel")}
          </Button>
          <Button type="submit" variant="primary" disabled={!value.trim() || reason.trim().length < 3}>
            {t("allowDialog.allow")}
          </Button>
        </>
      }
    >
      <TextField label={t("allowDialog.value")} value={value} onChange={(e) => setValue(e.target.value)} mono hint={t("allowDialog.suchAs2030113")} />
      <TextField label={t("allowDialog.reason")} value={reason} onChange={(e) => setReason(e.target.value)} hint={t("allowDialog.requiredWhyItIsFine")} />
      <SelectField
        label={t("allowDialog.for")}
        value={days}
        onChange={(e) => setDays(e.target.value)}
        options={[
          { value: "30", label: t("allowDialog.n30Days") },
          { value: "90", label: t("allowDialog.n90Days") },
          { value: "180", label: t("allowDialog.n180Days") },
          { value: "365", label: t("allowDialog.n1Year") },
        ]}
      />
      <Switch checked={subdomains} onCheckedChange={setSubdomains} label={t("allowDialog.forADomainItsSubdomains")} />
      {error && <p className="m-0 text-xs text-danger">{error}</p>}
    </Dialog>
  );
}

function AllowListPage({ call, reload }: { call: Call; reload: () => void }) {
  const t = useT();
  const { can } = useAuth();
  const [rows, setRows] = useState<AllowEntry[]>();
  const [adding, setAdding] = useState(false);
  const load = useCallback(() => void call<{ entries: AllowEntry[] }>("/api/v1/allow-list?limit=500").then((r) => setRows(r.entries), () => setRows([])), [call]);
  useEffect(load, [load]);
  const columns: Column<AllowEntry>[] = [
    { id: "type", header: t("allowListPage.type"), width: "90px", cell: (a) => <Badge>{TYPE_LABEL[a.type]}</Badge> },
    { id: "value", header: t("allowListPage.value"), width: "28%", cell: (a) => <span className="threat-intel-wrap font-mono text-xs">{a.value}{a.includeSubdomains ? t("allowListPage.andSubdomains") : ""}</span> },
    { id: "reason", header: t("allowListPage.reason"), width: "30%", cell: (a) => <span className="threat-intel-clamp text-xs" title={a.reason}>{a.reason}</span> },
    { id: "by", header: t("allowListPage.by"), cell: (a) => <span className="text-xs">{a.by ?? ""}</span> },
    { id: "expires", header: t("allowListPage.until"), sortValue: (a) => a.expiresAt, cell: (a) => (a.active ? <span className="whitespace-nowrap text-xs">{date(a.expiresAt)}</span> : <StatusBadge tone="neutral">{t("allowListPage.ended")}</StatusBadge>) },
    ...(can("editor")
      ? [{ id: "remove", header: "", align: "right" as const, width: "56px", cell: (a: AllowEntry) => <Button size="sm" icon={<Trash2 />} aria-label={t("allowListPage.remove", { value: a.value })} onClick={() => void call(`/api/v1/allow-list/${a.id}`, { method: "DELETE" }).then(() => (load(), reload()))} /> }]
      : []),
  ];
  return (
    <>
      <PageHeader
        title={t("allowListPage.allowList")}
        description={t("allowListPage.valuesKnownToBeFine")}
        actions={
          can("editor") && (
            <Button variant="primary" icon={<Plus />} onClick={() => setAdding(true)}>
              {t("allowListPage.allowAValue")}
            </Button>
          )
        }
      />
      <Panel flush>
        <DataTable label={t("allowListPage.allowList")} columns={columns} rows={rows ?? []} loading={!rows} getRowId={(a) => a.id} minWidth={860} empty={<EmptyState title={t("allowListPage.nothingAllowed")}>{t("allowListPage.valuesAFeedGetsWrong")}</EmptyState>} />
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
  const t = useT();
  const origin = window.location.origin;
  return (
    <>
      <PageHeader title={t("setupPage.setup")} description={t("setupPage.addAFeedThenSend")} />
      <Panel title={t("setupPage.importAFeed")} description={t("setupPage.theBodyIsTheFeed")}>
        <Code>{`# a STIX 2.1 bundle, such as an export from OpenCTI or MISP
curl -sf -X POST -H "Authorization: Bearer $THREAT_INTEL_INGEST_TOKEN" \\
  --data-binary @bundle.json "${origin}/api/v1/feeds/<feed id>/import"

# a plain list, such as a blocklist
curl -sf https://feed.example.org/ips.txt | curl -sf -X POST \\
  -H "Authorization: Bearer $THREAT_INTEL_INGEST_TOKEN" -H 'content-type: text/plain' \\
  --data-binary @- "${origin}/api/v1/feeds/<feed id>/import"`}</Code>
      </Panel>
      <Panel title={t("setupPage.lookValuesUp")} description={t("setupPage.whatSiemVpnWafAnd")}>
        <Code>{`curl -sf -H "Authorization: Bearer $THREAT_INTEL_INGEST_TOKEN" "${origin}/api/v1/lookup?value=198.51.100.7"

curl -sf -X POST -H "Authorization: Bearer $THREAT_INTEL_INGEST_TOKEN" -H 'content-type: application/json' \\
  -d '{"items":[{"value":"bad.example.com"},{"value":"hxxp://phish[.]example/login"}]}' "${origin}/api/v1/lookup"`}</Code>
      </Panel>
      <Panel title={t("setupPage.whatToKnow")}>
        <ul className="threat-intel-list flex flex-col gap-1 text-sm text-fg-muted">
          <li>{t("setupPage.aMatchWithConfidence60")}</li>
          <li>{t("setupPage.anAddressAlsoMatchesThe")}</li>
          <li>{t("setupPage.indicatorsEndOnTheirValid")}</li>
          <li>{t("setupPage.tlpRedIsForNamed")}</li>
        </ul>
      </Panel>
    </>
  );
}

// ---------------------------------------------------------------- Shell

/** Account, Members, Sign-in and API tokens: the screens come from @openasy/auth. */
function SettingsPage({ page }: { page: "account" | "members" | "signin" | "tokens" }) {
  const t = useT();
  const { signOut, can } = useAuth();
  if (page !== "account" && !can("admin")) return <EmptyState title={t("settingsPage.adminsOnly")}>{t("settingsPage.askAnAdminOfThis")}</EmptyState>;
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
              {t("settingsPage.signOut")}
            </Button>
          )
        }
      />
      {page === "account" ? <AccountSettings /> : page === "members" ? <MembersSettings /> : page === "signin" ? <SignInSettings /> : <TokensSettings />}
    </>
  );
}

function Product() {
  const msg = useT();
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
    { id: "lookup", label: msg("product.lookUp"), icon: Search },
    { id: "indicators", label: msg("product.indicators"), icon: ListChecks, count: summary?.indicators.active },
    { id: "feeds", label: msg("product.feeds"), icon: Rss, count: summary?.feeds },
    { id: "allow-list", label: msg("product.allowList"), icon: ShieldCheck, count: summary?.allowListed || undefined },
  ];
  const footerNav = [
    { id: "setup", label: msg("product.setup"), icon: Settings2 },
    ...(can("admin")
      ? [
          { id: "members", label: msg("product.members"), icon: Users },
          { id: "signin", label: msg("product.signIn"), icon: LogIn },
          { id: "tokens", label: msg("product.apiTokens"), icon: KeyRound },
        ]
      : []),
    { id: "account", label: msg("product.account"), icon: UserRound },
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
