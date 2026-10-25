// What the search window (Cmd+K) finds in Threat Intel: indicators by value, label or description, from the API, and
// feeds by name. An indicator opens the lookup with its value.
import type { SearchFn, SearchResult } from "@openasy/ui";
import { Crosshair, Rss } from "lucide-react";
import type { Feed, Indicator } from "./api.ts";
import type { T } from "./i18n.ts";

type Call = <R>(path: string, init?: RequestInit) => Promise<R>;
const query = (q: string) => new URLSearchParams({ q, limit: "8" });

export function search(call: Call, t: T): SearchFn {
  return async (q, signal) => {
    const [found, feeds] = await Promise.all([
      call<{ indicators: Indicator[] }>(`/api/v1/indicators?${query(q)}`, { signal }),
      call<{ feeds: Feed[] }>("/api/v1/feeds?limit=500", { signal }),
    ]);
    const indicators: SearchResult[] = found.indicators.map((i) => ({
      id: `indicator:${i.id}`,
      label: i.value,
      detail: t("search.indicatorDetail", { type: i.type, feed: i.feed.name }),
      kind: t("search.indicator"),
      icon: Crosshair,
      severity: i.severity,
      mono: true,
      href: `/?value=${encodeURIComponent(i.value)}`,
    }));
    const named: SearchResult[] = feeds.feeds
      .filter((f) => f.name.toLowerCase().includes(q))
      .slice(0, 6)
      .map((f) => ({
        id: `feed:${f.id}`,
        label: f.name,
        detail: t("search.feedDetail", { active: f.indicators.active }),
        kind: t("search.feed"),
        icon: Rss,
        href: `/indicators?feed=${encodeURIComponent(f.id)}`,
      }));
    return [...indicators, ...named];
  };
}
