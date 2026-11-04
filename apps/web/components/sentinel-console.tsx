"use client";

import {
  Activity,
  AlertOctagon,
  AlertTriangle,
  Archive,
  BadgeCheck,
  Bell,
  Blocks,
  Box,
  Braces,
  Check,
  ChevronRight,
  CircleUserRound,
  Clock3,
  Code2,
  Database,
  Eye,
  FileKey2,
  FileText,
  Filter,
  Gauge,
  Globe2,
  KeyRound,
  Languages,
  LayoutDashboard,
  ListChecks,
  LockKeyhole,
  Menu,
  Moon,
  Network,
  Play,
  Radar,
  RefreshCcw,
  Search,
  Server,
  Settings,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Sun,
  TerminalSquare,
  TestTube2,
  X,
  Zap,
} from "lucide-react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { api, APIError } from "@/lib/api";
import { copy, type Locale } from "@/lib/i18n";

type Row = Record<string, unknown>;
type Page<T extends Row = Row> = { items: T[]; pagination?: { total: number } };
type User = {
  id: string;
  email: string;
  display_name: string;
  role: string;
  workspace_id: string;
};

const NAV = [
  {
    label: "Monitor",
    items: [
      { key: "dashboard", href: "/dashboard", icon: LayoutDashboard },
      { key: "sessions", href: "/sessions", icon: Activity },
      { key: "approvals", href: "/approvals", icon: ListChecks, badge: true },
    ],
  },
  {
    label: "Control",
    items: [
      { key: "servers", href: "/servers", icon: Server },
      { key: "tools", href: "/tools", icon: Blocks },
      { key: "policies", href: "/policies", icon: ShieldCheck },
      { key: "sandboxes", href: "/sandboxes", icon: Box },
    ],
  },
  {
    label: "Investigate",
    items: [
      { key: "findings", href: "/security/secrets", icon: ShieldAlert },
      { key: "risk", href: "/risk", icon: Gauge },
      { key: "reports", href: "/reports", icon: FileText },
    ],
  },
] as const;

const RISK_COLORS: Record<string, string> = {
  informational: "#7c8aa5",
  low: "#22c993",
  medium: "#eab85e",
  high: "#f28b52",
  critical: "#ef5b6b",
};

function text(value: unknown): string {
  if (value == null) return "—";
  if (typeof value === "string") return value;
  if (typeof value === "number" || typeof value === "boolean")
    return String(value);
  return JSON.stringify(value);
}

function title(value: string): string {
  return value
    .replaceAll("_", " ")
    .replace(/\b\w/g, (match) => match.toUpperCase());
}

function date(value: unknown, locale: Locale = "en"): string {
  if (typeof value !== "string") return "—";
  return new Intl.DateTimeFormat(locale === "ro" ? "ro-RO" : "en-GB", {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(new Date(value));
}

function Badge({ value, tone }: { value: unknown; tone?: string }) {
  const label = text(value);
  const normalized = tone ?? label.toLowerCase();
  return (
    <span className={`badge badge-${normalized.replaceAll(" ", "-")}`}>
      <span aria-hidden="true" className="badge-dot" />
      {title(label)}
    </span>
  );
}

function Empty({ title: heading, detail }: { title: string; detail: string }) {
  return (
    <div className="empty">
      <ShieldCheck aria-hidden="true" />
      <strong>{heading}</strong>
      <p>{detail}</p>
    </div>
  );
}

function ErrorState({ error }: { error: Error }) {
  return (
    <div className="error-state" role="alert">
      <AlertOctagon aria-hidden="true" />
      <div>
        <strong>Couldn’t load this security view</strong>
        <p>{error.message}</p>
      </div>
    </div>
  );
}

function Panel({
  title: heading,
  subtitle,
  action,
  children,
  className = "",
}: {
  title: string;
  subtitle?: string;
  action?: React.ReactNode;
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <section className={`panel ${className}`}>
      <header className="panel-head">
        <div>
          <h2>{heading}</h2>
          {subtitle && <p>{subtitle}</p>}
        </div>
        {action}
      </header>
      {children}
    </section>
  );
}

function DataTable({
  columns,
  rows,
  caption,
}: {
  columns: {
    key: string;
    label: string;
    render?: (row: Row) => React.ReactNode;
  }[];
  rows: Row[];
  caption: string;
}) {
  return (
    <div className="table-scroll">
      <table>
        <caption className="sr-only">{caption}</caption>
        <thead>
          <tr>
            {columns.map((column) => (
              <th key={column.key} scope="col">
                {column.label}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((row, index) => (
            <tr key={text(row.id ?? index)}>
              {columns.map((column) => (
                <td key={column.key}>
                  {column.render ? column.render(row) : text(row[column.key])}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function Login({ onSuccess }: { onSuccess: () => void }) {
  const [email, setEmail] = useState("admin@example.com");
  const [password, setPassword] = useState("SentinelDemo!2026");
  const mutation = useMutation({
    mutationFn: () =>
      api<{ csrf_token: string; user: { display_name: string } }>(
        "/auth/login",
        { method: "POST", body: JSON.stringify({ email, password }) },
      ),
    onSuccess: (data) => {
      window.sessionStorage.setItem("sentinel_csrf", data.csrf_token);
      onSuccess();
    },
  });
  return (
    <main className="login-shell" id="main-content">
      <section className="login-brand">
        <div className="logo logo-large">
          <Shield aria-hidden="true" />
        </div>
        <span className="eyebrow">OPEN-SOURCE MCP SECURITY</span>
        <h1>
          Keep powerful agents
          <br />
          <em>inside the lines.</em>
        </h1>
        <p>
          MCP traffic inspection, deterministic policy enforcement, human
          approvals, secret redaction, and tamper-evident audit trails.
        </p>
        <div className="trust-row">
          <span>
            <ShieldCheck />
            Fail closed
          </span>
          <span>
            <LockKeyhole />
            Local first
          </span>
          <span>
            <Eye />
            Explainable
          </span>
        </div>
      </section>
      <section className="login-card">
        <div>
          <span className="eyebrow">MCP SENTINEL</span>
          <h2>Enter the control room</h2>
          <p>
            Use the seeded local workspace. All visible security events are
            synthetic.
          </p>
        </div>
        <form
          onSubmit={(event) => {
            event.preventDefault();
            mutation.mutate();
          }}
        >
          <label>
            Email address
            <input
              aria-label="Email address"
              autoComplete="username"
              value={email}
              onChange={(event) => setEmail(event.target.value)}
            />
          </label>
          <label>
            Password
            <input
              aria-label="Password"
              autoComplete="current-password"
              type="password"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
            />
          </label>
          {mutation.error && (
            <p className="form-error" role="alert">
              {mutation.error.message}
            </p>
          )}
          <button
            className="button primary wide"
            type="submit"
            disabled={mutation.isPending}
          >
            {mutation.isPending ? "Authenticating…" : "Open security console"}
            <ChevronRight />
          </button>
        </form>
        <div className="demo-note">
          <KeyRound />
          <span>
            <strong>Local demo account</strong>
            <br />
            Credentials are synthetic and may be reset with{" "}
            <code>make seed</code>.
          </span>
        </div>
      </section>
    </main>
  );
}

export function SentinelConsole({ route }: { route: string }) {
  const pathname = usePathname();
  const [locale, setLocale] = useState<Locale>("en");
  const [theme, setTheme] = useState<"dark" | "light">("dark");
  const [mobileNav, setMobileNav] = useState(false);
  useEffect(() => {
    const savedTheme =
      window.localStorage.getItem("sentinel_theme") === "light"
        ? "light"
        : "dark";
    const savedLocale =
      window.localStorage.getItem("sentinel_locale") === "ro" ? "ro" : "en";
    document.documentElement.dataset.theme = savedTheme;
    const timer = window.setTimeout(() => {
      setTheme(savedTheme);
      setLocale(savedLocale);
    }, 0);
    return () => window.clearTimeout(timer);
  }, []);
  const setThemeValue = (value: "dark" | "light") => {
    setTheme(value);
    window.localStorage.setItem("sentinel_theme", value);
    document.documentElement.dataset.theme = value;
  };
  const setLocaleValue = (value: Locale) => {
    setLocale(value);
    window.localStorage.setItem("sentinel_locale", value);
    document.documentElement.lang = value;
  };
  const me = useQuery({
    queryKey: ["me"],
    queryFn: () => api<User>("/auth/me"),
    retry: false,
  });
  if (me.isLoading)
    return (
      <div className="boot">
        <div className="logo">
          <Shield />
        </div>
        <span>Verifying security context…</span>
      </div>
    );
  if (me.error instanceof APIError && me.error.status === 401)
    return <Login onSuccess={() => window.location.reload()} />;
  if (me.error)
    return (
      <main className="fatal">
        <ErrorState error={me.error} />
      </main>
    );
  const c = copy[locale];
  return (
    <div className="app-shell">
      <aside
        className={`sidebar ${mobileNav ? "sidebar-open" : ""}`}
        aria-label="Primary navigation"
      >
        <div className="brand">
          <div className="logo">
            <Shield aria-hidden="true" />
          </div>
          <div>
            <strong>MCP Sentinel</strong>
            <span>Control plane</span>
          </div>
          <button
            className="icon-button close-nav"
            onClick={() => setMobileNav(false)}
            aria-label="Close navigation"
          >
            <X />
          </button>
        </div>
        <nav>
          {NAV.map((group) => (
            <div className="nav-group" key={group.label}>
              <span>{group.label}</span>
              {group.items.map((item) => {
                const active =
                  pathname === item.href ||
                  (item.href !== "/dashboard" &&
                    pathname.startsWith(item.href));
                const Icon = item.icon;
                return (
                  <Link
                    className={active ? "active" : ""}
                    href={item.href}
                    key={item.key}
                    onClick={() => setMobileNav(false)}
                  >
                    <Icon aria-hidden="true" />
                    <span>{c[item.key]}</span>
                    {"badge" in item && item.badge && (
                      <b aria-label="8 pending">8</b>
                    )}
                  </Link>
                );
              })}
            </div>
          ))}
        </nav>
        <div className="sidebar-foot">
          <Link href="/settings">
            <Settings />
            <span>{c.settings}</span>
          </Link>
          <div className="enforcement">
            <span className="pulse" />
            <div>
              <strong>{c.live}</strong>
              <small>Gateway 2025-11-25</small>
            </div>
          </div>
        </div>
      </aside>
      <div className="workspace">
        <header className="topbar">
          <button
            className="icon-button menu-button"
            onClick={() => setMobileNav(true)}
            aria-label="Open navigation"
          >
            <Menu />
          </button>
          <Link className="search-box" aria-label={c.search} href="/sessions">
            <Search />
            <span>{c.search} sessions</span>
            <kbd>OPEN</kbd>
          </Link>
          <div className="top-actions">
            <span className="environment">
              <span />
              PROTECTED · DEVELOPMENT
            </span>
            <Link
              className="icon-button"
              aria-label="Open pending approvals"
              href="/approvals"
            >
              <Bell />
              <i>3</i>
            </Link>
            <button
              className="icon-button"
              onClick={() => setThemeValue(theme === "dark" ? "light" : "dark")}
              aria-label="Toggle color theme"
            >
              {theme === "dark" ? <Sun /> : <Moon />}
            </button>
            <button
              className="locale-button"
              onClick={() => setLocaleValue(locale === "en" ? "ro" : "en")}
              aria-label={c.locale}
            >
              <Languages />
              {locale.toUpperCase()}
            </button>
            <div className="user">
              <span>
                {me.data?.display_name
                  .split(" ")
                  .map((part) => part[0])
                  .join("")
                  .slice(0, 2)}
              </span>
              <div>
                <strong>{me.data?.display_name}</strong>
                <small>{title(me.data?.role ?? "")}</small>
              </div>
            </div>
          </div>
        </header>
        <main id="main-content" className="main">
          <PageView route={route} locale={locale} />
          <footer>
            <span>MCP Sentinel v0.1.0</span>
            <span>
              All demo data is synthetic · <Link href="/api/docs">OpenAPI</Link>{" "}
              ·{" "}
              <a href="https://modelcontextprotocol.io/specification/2025-11-25">
                MCP 2025-11-25
              </a>
            </span>
          </footer>
        </main>
      </div>
    </div>
  );
}

function PageTitle({
  eyebrow,
  title: heading,
  description,
  actions,
}: {
  eyebrow: string;
  title: string;
  description: string;
  actions?: React.ReactNode;
}) {
  return (
    <div className="page-title">
      <div>
        <span className="eyebrow">{eyebrow}</span>
        <h1>{heading}</h1>
        <p>{description}</p>
      </div>
      {actions && <div className="page-actions">{actions}</div>}
    </div>
  );
}

function PageView({ route, locale }: { route: string; locale: Locale }) {
  if (route === "dashboard" || route === "")
    return <Dashboard locale={locale} />;
  if (route === "servers") return <Servers locale={locale} />;
  if (route === "servers/risk") return <ServerRisk />;
  if (route === "tools") return <Tools />;
  if (route === "policies") return <Policies />;
  if (route === "policies/editor") return <PolicyEditor />;
  if (route === "policies/tester") return <PolicyTester />;
  if (route === "sessions") return <Sessions locale={locale} />;
  if (
    [
      "sessions/overview",
      "sessions/timeline",
      "requests/details",
      "replay",
    ].includes(route)
  )
    return <SessionInvestigation mode={route} locale={locale} />;
  if (route === "approvals") return <Approvals locale={locale} />;
  if (route === "approvals/details") return <ApprovalDetail locale={locale} />;
  if (route === "security/secrets") return <Secrets locale={locale} />;
  if (route === "security/injections") return <InjectionWarnings />;
  if (route === "sandboxes") return <Sandboxes locale={locale} />;
  if (route === "risk") return <RiskDashboard />;
  if (route === "reports") return <Reports locale={locale} />;
  if (route === "audit") return <AuditExport />;
  if (route === "settings") return <SettingsPage />;
  return (
    <div>
      <PageTitle
        eyebrow="404"
        title="Security view not found"
        description="This route is not part of the Sentinel console."
      />
      <Empty
        title="No view here"
        detail="Use the navigation to return to an implemented security workflow."
      />
    </div>
  );
}

function Dashboard({ locale }: { locale: Locale }) {
  const query = useQuery({
    queryKey: ["dashboard"],
    queryFn: () => api<Row>("/dashboard"),
  });
  if (query.error) return <ErrorState error={query.error} />;
  const data = query.data;
  const metrics = (data?.metrics ?? {}) as Row;
  const metricCards = [
    [
      "Active sessions",
      metrics.active_sessions,
      Activity,
      "+2 in 20 min",
      "blue",
    ],
    ["Requests · 24h", metrics.requests_24h, Zap, "97.4% allowed", "green"],
    [
      "Blocked actions",
      metrics.blocked_actions,
      ShieldAlert,
      "Hard policy stops",
      "red",
    ],
    [
      "Pending approvals",
      metrics.pending_approvals,
      Clock3,
      "Oldest 6 min",
      "amber",
    ],
    [
      "Secret detections",
      metrics.secret_detections,
      FileKey2,
      "Plaintext discarded",
      "purple",
    ],
    [
      "Critical servers",
      metrics.critical_servers,
      Server,
      "1 quarantined",
      "red",
    ],
  ] as const;
  const volume = (data?.tool_call_volume ?? []) as Row[];
  const recent = (data?.recent_sessions ?? []) as Row[];
  const risky = (data?.highest_risk_servers ?? []) as Row[];
  return (
    <>
      <PageTitle
        eyebrow="SECURITY COMMAND CENTER"
        title="Good evening, Mara."
        description="Your MCP perimeter is enforcing policy. Three items need a human decision."
        actions={
          <>
            <button
              className="button secondary"
              onClick={() => query.refetch()}
              disabled={query.isFetching}
            >
              <RefreshCcw />
              {query.isFetching ? "Refreshing…" : "Refresh"}
            </button>
            <Link className="button primary" href="/approvals">
              <ListChecks />
              Review approvals
            </Link>
          </>
        }
      />
      <div className="posture">
        <div className="posture-score">
          <div className="score-ring">
            <strong>82</strong>
            <span>/100</span>
          </div>
          <div>
            <span className="eyebrow">WORKSPACE POSTURE</span>
            <h2>Protected, with review items</h2>
            <p>
              Controls are operating normally. Risk is concentrated in two
              restricted servers.
            </p>
          </div>
        </div>
        <div className="posture-stats">
          <span>
            <ShieldCheck />
            <b>9</b>
            <small>Active policies</small>
          </span>
          <span>
            <Server />
            <b>8</b>
            <small>Registered servers</small>
          </span>
          <span>
            <Activity />
            <b>1.8 ms</b>
            <small>Policy latency</small>
          </span>
        </div>
      </div>
      <div className="metrics-grid">
        {metricCards.map(([label, value, Icon, note, tone]) => (
          <article className={`metric tone-${tone}`} key={label}>
            <div>
              <span>{label}</span>
              <Icon aria-hidden="true" />
            </div>
            <strong>{text(value)}</strong>
            <small>{note}</small>
          </article>
        ))}
      </div>
      <div className="dashboard-grid">
        <Panel
          title="MCP request volume"
          subtitle="Allowed and blocked tool calls · last 24 hours"
          action={
            <Link className="text-button" href="/sessions">
              <Filter />
              Inspect sessions
            </Link>
          }
        >
          <div className="chart" aria-label="Tool call volume chart">
            <ResponsiveContainer width="100%" height={245}>
              <BarChart data={volume}>
                <CartesianGrid
                  strokeDasharray="3 3"
                  vertical={false}
                  stroke="var(--line)"
                />
                <XAxis
                  dataKey="hour"
                  axisLine={false}
                  tickLine={false}
                  tick={{ fill: "var(--muted)", fontSize: 11 }}
                />
                <YAxis
                  axisLine={false}
                  tickLine={false}
                  tick={{ fill: "var(--muted)", fontSize: 11 }}
                />
                <Tooltip
                  contentStyle={{
                    background: "var(--panel-solid)",
                    border: "1px solid var(--line)",
                    borderRadius: 10,
                  }}
                />
                <Bar dataKey="allowed" fill="#27c9a1" radius={[4, 4, 0, 0]} />
                <Bar dataKey="blocked" fill="#ef5b6b" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
            <div className="chart-summary">
              <span>
                <i className="green" />
                Allowed
              </span>
              <span>
                <i className="red" />
                Blocked
              </span>
            </div>
          </div>
        </Panel>
        <Panel
          title="Highest-risk servers"
          subtitle="Capability-weighted assessment"
        >
          <div className="risk-list">
            {risky.map((server) => (
              <Link href="/servers/risk" key={text(server.id)}>
                <span className="server-icon">
                  <Server />
                </span>
                <div>
                  <strong>{text(server.name)}</strong>
                  <small>
                    {title(text(server.trust_status))} ·{" "}
                    {text(server.transport)}
                  </small>
                </div>
                <div className="risk-meter">
                  <span>
                    <i
                      style={{
                        width: `${text(server.risk_score)}%`,
                        background: RISK_COLORS[text(server.risk_level)],
                      }}
                    />
                  </span>
                  <b>{text(server.risk_score)}</b>
                </div>
                <Badge value={server.risk_level} />
              </Link>
            ))}
          </div>
        </Panel>
      </div>
      <Panel
        title="Recent agent sessions"
        subtitle="Live and recently completed protocol activity"
        action={
          <Link className="text-button" href="/sessions">
            View all <ChevronRight />
          </Link>
        }
      >
        <DataTable
          caption="Recent MCP sessions"
          rows={recent}
          columns={[
            {
              key: "started_at",
              label: "Started",
              render: (row) => date(row.started_at, locale),
            },
            { key: "client", label: "Client" },
            { key: "server", label: "Server" },
            { key: "policy", label: "Policy" },
            { key: "event_count", label: "Events" },
            {
              key: "risk_summary",
              label: "Risk",
              render: (row) => (
                <Badge value={(row.risk_summary as Row)?.level ?? "unknown"} />
              ),
            },
            {
              key: "status",
              label: "Status",
              render: (row) => <Badge value={row.status} />,
            },
          ]}
        />
      </Panel>
    </>
  );
}

function Servers({ locale }: { locale: Locale }) {
  const query = useQuery({
    queryKey: ["servers"],
    queryFn: () => api<Page>("/servers"),
  });
  if (query.error) return <ErrorState error={query.error} />;
  const rows = query.data?.items ?? [];
  return (
    <>
      <PageTitle
        eyebrow="MCP INVENTORY"
        title="Server registry"
        description="Discovered capabilities, trust decisions, health, schema drift, and sandbox state."
        actions={
          <>
            <button
              className="button secondary"
              onClick={() => query.refetch()}
              disabled={query.isFetching}
            >
              <RefreshCcw />
              {query.isFetching ? "Refreshing…" : "Refresh registry"}
            </button>
            <span className="live-pill">
              <Server />
              Config-managed registry
            </span>
          </>
        }
      />
      <div className="summary-strip">
        <span>
          <b>8</b> registered
        </span>
        <span>
          <b>4</b> healthy
        </span>
        <span>
          <b>2</b> restricted
        </span>
        <span>
          <b>1</b> quarantined
        </span>
        <span>
          <b>40</b> discovered tools
        </span>
      </div>
      <Panel
        title="Configured MCP servers"
        subtitle="Credential fields are encrypted and omitted from API responses."
        action={
          <div className="filters">
            <span className="chip active">All records</span>
            <span className="chip">
              Risk and sandbox state shown in columns
            </span>
          </div>
        }
      >
        <DataTable
          caption="MCP server registry"
          rows={rows}
          columns={[
            {
              key: "name",
              label: "Server",
              render: (row) => (
                <Link className="primary-cell" href="/servers/risk">
                  <span className="server-icon">
                    <Server />
                  </span>
                  <span>
                    <strong>{text(row.name)}</strong>
                    <small>{text(row.description).slice(0, 52)}</small>
                  </span>
                </Link>
              ),
            },
            {
              key: "transport",
              label: "Transport",
              render: (row) => <code>{text(row.transport)}</code>,
            },
            {
              key: "trust_status",
              label: "Trust",
              render: (row) => <Badge value={row.trust_status} />,
            },
            {
              key: "risk_score",
              label: "Risk",
              render: (row) => (
                <span className="score-cell">
                  <b>{text(row.risk_score)}</b>
                  <Badge value={row.risk_level} />
                </span>
              ),
            },
            {
              key: "health",
              label: "Health",
              render: (row) => (
                <Badge
                  value={row.health}
                  tone={
                    text(row.health) === "healthy"
                      ? "allowed"
                      : text(row.health)
                  }
                />
              ),
            },
            {
              key: "sandbox_status",
              label: "Sandbox",
              render: (row) => <Badge value={row.sandbox_status} />,
            },
            {
              key: "last_scanned",
              label: "Last scan",
              render: (row) => date(row.last_scanned, locale),
            },
          ]}
        />
      </Panel>
    </>
  );
}

function ServerRisk() {
  const list = useQuery({
    queryKey: ["servers"],
    queryFn: () => api<Page>("/servers"),
  });
  const serverId = list.data?.items[0]?.id;
  const detail = useQuery({
    queryKey: ["server", serverId],
    queryFn: () => api<Row>(`/servers/${serverId}`),
    enabled: Boolean(serverId),
  });
  const queryClient = useQueryClient();
  const scan = useMutation({
    mutationFn: () => api<Row>(`/servers/${serverId}/scan`, { method: "POST" }),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ["servers"] });
      await queryClient.invalidateQueries({ queryKey: ["server", serverId] });
    },
  });
  if (detail.error) return <ErrorState error={detail.error} />;
  const server = detail.data ?? {};
  const tools = (server.tools ?? []) as Row[];
  return (
    <>
      <PageTitle
        eyebrow="SERVER ASSESSMENT"
        title={text(server.name || "Assessing server…")}
        description={text(server.description)}
        actions={
          <>
            <Badge value={server.trust_status ?? "unreviewed"} />
            <button
              className="button primary"
              onClick={() => scan.mutate()}
              disabled={!serverId || scan.isPending}
            >
              <RefreshCcw />
              {scan.isPending ? "Scanning…" : "Rescan capabilities"}
            </button>
          </>
        }
      />
      <div className="assessment-hero">
        <div className="risk-orb">
          <span>{text(server.risk_score)}</span>
          <small>CRITICALITY</small>
        </div>
        <div>
          <span className="eyebrow">EXPLAINABLE RISK ASSESSMENT</span>
          <h2>{title(text(server.risk_level))} server exposure</h2>
          <p>
            Score is derived from capability schemas and trust state—not an
            opaque model judgment.
          </p>
          <div className="signal-pills">
            <span>
              <TerminalSquare />
              Shell execution +35
            </span>
            <span>
              <FileKey2 />
              Secret access +35
            </span>
            <span>
              <Network />
              Network access +15
            </span>
            <span className="negative">
              <BadgeCheck />
              Known server −10
            </span>
          </div>
        </div>
        <div className="assessment-meta">
          <span>
            <small>Transport</small>
            <code>{text(server.transport)}</code>
          </span>
          <span>
            <small>Version</small>
            <b>{text(server.version)}</b>
          </span>
          <span>
            <small>Sandbox</small>
            <Badge value={server.sandbox_status ?? "unknown"} />
          </span>
          <span>
            <small>Health</small>
            <Badge value={server.health ?? "unknown"} />
          </span>
        </div>
      </div>
      <div className="two-column">
        <Panel
          title="Capability exposure"
          subtitle={`${tools.length} tools inspected`}
        >
          <div className="capability-list">
            {tools.map((tool) => (
              <div key={text(tool.id)}>
                <span className="method-icon">
                  <Code2 />
                </span>
                <div>
                  <strong>{text(tool.name)}</strong>
                  <small>{text(tool.description)}</small>
                </div>
                <span className="side-effect">
                  {title(text(tool.side_effect))}
                </span>
                <b>{text(tool.risk_score)}</b>
                <Badge value={tool.risk_level} />
              </div>
            ))}
          </div>
        </Panel>
        <Panel
          title="Security recommendations"
          subtitle="Prioritized controls for this server"
        >
          <div className="recommendations">
            <article>
              <span>01</span>
              <div>
                <strong>Keep network disabled by default</strong>
                <p>
                  Enable only reviewed domains through the restricted egress
                  profile.
                </p>
              </div>
              <Badge value="enforced" tone="allowed" />
            </article>
            <article>
              <span>02</span>
              <div>
                <strong>Require approval for writes</strong>
                <p>
                  Filesystem mutation crosses the agent-to-host trust boundary.
                </p>
              </div>
              <Badge value="enforced" tone="allowed" />
            </article>
            <article>
              <span>03</span>
              <div>
                <strong>Review schema on every update</strong>
                <p>Unrestricted command strings materially increase risk.</p>
              </div>
              <Badge value="action needed" tone="medium" />
            </article>
          </div>
        </Panel>
      </div>
    </>
  );
}

function Tools() {
  const query = useQuery({
    queryKey: ["tools"],
    queryFn: () => api<Page>("/tools?page_size=100"),
  });
  if (query.error) return <ErrorState error={query.error} />;
  const rows = query.data?.items ?? [];
  return (
    <>
      <PageTitle
        eyebrow="CAPABILITY INVENTORY"
        title="Tool capabilities"
        description="Every advertised tool schema is classified by side effect, exposure, and review status."
        actions={
          <Link className="button secondary" href="/reports">
            <Archive />
            Build inventory report
          </Link>
        }
      />
      <Panel
        title="Discovered tools"
        subtitle={`${rows.length} active capabilities across registered servers`}
        action={
          <div className="filters">
            <span className="chip active">All tools</span>
            <span className="chip">Side effects and risk shown in columns</span>
          </div>
        }
      >
        <DataTable
          caption="Discovered MCP tools"
          rows={rows}
          columns={[
            {
              key: "name",
              label: "Tool",
              render: (row) => (
                <span className="primary-cell">
                  <span className="method-icon">
                    <Braces />
                  </span>
                  <span>
                    <strong>{text(row.name)}</strong>
                    <small>{text(row.description)}</small>
                  </span>
                </span>
              ),
            },
            {
              key: "category",
              label: "Category",
              render: (row) => <code>{text(row.category)}</code>,
            },
            {
              key: "side_effect",
              label: "Side effect",
              render: (row) => <Badge value={row.side_effect} />,
            },
            {
              key: "risk_score",
              label: "Risk score",
              render: (row) => (
                <span className="score-cell">
                  <b>{text(row.risk_score)}</b>
                  <Badge value={row.risk_level} />
                </span>
              ),
            },
            {
              key: "review_status",
              label: "Review",
              render: (row) => <Badge value={row.review_status} />,
            },
            {
              key: "schema_hash",
              label: "Schema",
              render: (row) => (
                <code>{text(row.schema_hash).slice(0, 12)}…</code>
              ),
            },
          ]}
        />
      </Panel>
    </>
  );
}

function Policies() {
  const query = useQuery({
    queryKey: ["policies"],
    queryFn: () => api<{ items: Row[] }>("/policies"),
  });
  if (query.error) return <ErrorState error={query.error} />;
  const rows = query.data?.items ?? [];
  return (
    <>
      <PageTitle
        eyebrow="DETERMINISTIC CONTROL"
        title="Policy library"
        description="Versioned, explainable decisions for clients, servers, tools, arguments, and limits."
        actions={
          <>
            <Link className="button secondary" href="/policies/tester">
              <TestTube2 />
              Policy tester
            </Link>
            <Link className="button primary" href="/policies/editor">
              <ShieldCheck />
              New draft
            </Link>
          </>
        }
      />
      <div className="metrics-grid compact">
        <article className="metric tone-green">
          <div>
            <span>Active policies</span>
            <ShieldCheck />
          </div>
          <strong>9</strong>
          <small>All reviewed</small>
        </article>
        <article className="metric tone-blue">
          <div>
            <span>Evaluations · 24h</span>
            <Zap />
          </div>
          <strong>1,284</strong>
          <small>1.8 ms average</small>
        </article>
        <article className="metric tone-amber">
          <div>
            <span>Drafts</span>
            <FileText />
          </div>
          <strong>3</strong>
          <small>Awaiting review</small>
        </article>
        <article className="metric tone-purple">
          <div>
            <span>Coverage</span>
            <Radar />
          </div>
          <strong>96%</strong>
          <small>2 unassigned tools</small>
        </article>
      </div>
      <Panel
        title="Workspace policies"
        subtitle="Active versions are immutable; changes create a reviewed version."
        action={<span className="chip active">All statuses</span>}
      >
        <DataTable
          caption="Workspace policies"
          rows={rows}
          columns={[
            {
              key: "name",
              label: "Policy",
              render: (row) => (
                <Link className="policy-name" href="/policies/editor">
                  <ShieldCheck />
                  <span>
                    <strong>{text(row.name)}</strong>
                    <small>{text(row.description)}</small>
                  </span>
                </Link>
              ),
            },
            {
              key: "version",
              label: "Version",
              render: (row) => <code>v{text(row.version)}</code>,
            },
            {
              key: "status",
              label: "Status",
              render: (row) => <Badge value={row.status} />,
            },
            {
              key: "language",
              label: "Engine",
              render: (row) => <code>{text(row.language)}</code>,
            },
            {
              key: "effective_at",
              label: "Effective",
              render: (row) => date(row.effective_at),
            },
          ]}
        />
      </Panel>
    </>
  );
}

function PolicyEditor() {
  const policies = useQuery({
    queryKey: ["policies"],
    queryFn: () => api<{ items: Row[] }>("/policies"),
  });
  const selected = policies.data?.items[0];
  const [definition, setDefinition] = useState("");
  const [sample] = useState({
    tool: "filesystem.write_file",
    arguments: {
      path: "/workspace/project/notes.md",
      content: "Synthetic note",
    },
    server_trust: "trusted",
  });
  const effectiveDefinition =
    definition || text(selected?.raw_definition ?? "");
  const mutation = useMutation({
    mutationFn: () =>
      api<Row>("/policy-tests", {
        method: "POST",
        body: JSON.stringify({
          definition: effectiveDefinition,
          request: sample,
          dry_run: true,
        }),
      }),
  });
  return (
    <>
      <PageTitle
        eyebrow="POLICY DRAFT"
        title="Edit policy controls"
        description="Syntax, precedence conflicts, trace output, and risk context are validated before activation."
        actions={
          <>
            <span className="unsaved">
              <span />
              Local draft
            </span>
            <button
              className="button primary"
              onClick={() => mutation.mutate()}
              disabled={!effectiveDefinition || mutation.isPending}
            >
              <Play />
              Validate & test
            </button>
          </>
        }
      />
      <div className="editor-layout">
        <Panel
          title="Sentinel YAML"
          subtitle="Draft changes are not active until reviewed by an administrator."
          action={
            <span className="line-count">
              {effectiveDefinition.split("\n").length} lines
            </span>
          }
        >
          <textarea
            className="code-editor"
            aria-label="Policy YAML editor"
            spellCheck={false}
            value={effectiveDefinition}
            onChange={(event) => setDefinition(event.target.value)}
          />
        </Panel>
        <aside className="editor-side">
          <Panel title="Validation" subtitle="Safe compilation status">
            <div className={`validation-card ${mutation.data ? "pass" : ""}`}>
              {mutation.isPending ? (
                <RefreshCcw className="spin" />
              ) : mutation.data ? (
                <Check />
              ) : (
                <Code2 />
              )}
              <div>
                <strong>
                  {mutation.data
                    ? "Policy compiled safely"
                    : "Ready to validate"}
                </strong>
                <p>
                  {mutation.error
                    ? mutation.error.message
                    : mutation.data
                      ? `${text(mutation.data.matched_rules)} · ${text(mutation.data.evaluation_ms)} ms`
                      : "Run deterministic schema and conflict checks."}
                </p>
              </div>
            </div>
          </Panel>
          <Panel title="Sample decision" subtitle="Dry run · no server called">
            {mutation.data ? (
              <div className="decision-result">
                <Badge value={mutation.data.decision} />
                <strong>{title(text(mutation.data.decision))}</strong>
                <p>{text(mutation.data.explanation)}</p>
                <div>
                  <span>Risk</span>
                  <b>{text((mutation.data.risk as Row)?.score)}/100</b>
                </div>
              </div>
            ) : (
              <Empty
                title="No simulation yet"
                detail="Validate the draft to see the complete rule trace."
              />
            )}
          </Panel>
        </aside>
      </div>
    </>
  );
}

function PolicyTester() {
  const policies = useQuery({
    queryKey: ["policies"],
    queryFn: () => api<{ items: Row[] }>("/policies"),
  });
  const [policyId, setPolicyId] = useState("");
  const [tool, setTool] = useState("filesystem.read_file");
  const [args, setArgs] = useState('{"path":"/workspace/project/.env"}');
  const effectivePolicyId = policyId || text(policies.data?.items[0]?.id ?? "");
  const mutation = useMutation({
    mutationFn: () =>
      api<Row>("/policy-tests", {
        method: "POST",
        body: JSON.stringify({
          policy_id: effectivePolicyId,
          request: {
            tool,
            arguments: JSON.parse(args),
            server_trust: "trusted",
          },
          dry_run: true,
        }),
      }),
  });
  return (
    <>
      <PageTitle
        eyebrow="SAFE SIMULATION"
        title="Policy tester"
        description="Evaluate requests with full matching and skipped-rule traces. The destination server is never called."
        actions={
          <span className="simulation-badge">
            <Sparkles />
            SIMULATION ONLY
          </span>
        }
      />
      <div className="tester-grid">
        <Panel
          title="Request under test"
          subtitle="Provide a synthetic MCP tool request"
        >
          <form
            className="tester-form"
            onSubmit={(event) => {
              event.preventDefault();
              mutation.mutate();
            }}
          >
            <label>
              Policy
              <select
                value={effectivePolicyId}
                onChange={(event) => setPolicyId(event.target.value)}
              >
                {policies.data?.items.map((policy) => (
                  <option value={text(policy.id)} key={text(policy.id)}>
                    {text(policy.name)} · v{text(policy.version)}
                  </option>
                ))}
              </select>
            </label>
            <label>
              Tool name
              <input
                value={tool}
                onChange={(event) => setTool(event.target.value)}
              />
            </label>
            <label>
              Arguments · JSON
              <textarea
                value={args}
                onChange={(event) => setArgs(event.target.value)}
                spellCheck={false}
              />
            </label>
            <button
              className="button primary wide"
              type="submit"
              disabled={mutation.isPending}
            >
              <Play />
              {mutation.isPending ? "Evaluating…" : "Run policy evaluation"}
            </button>
            {mutation.error && (
              <p className="form-error" role="alert">
                {mutation.error.message}
              </p>
            )}
          </form>
        </Panel>
        <Panel
          title="Evaluation trace"
          subtitle="Every decision is explainable"
        >
          {mutation.data ? (
            <div className="trace-result">
              <div className="decision-banner">
                <span>
                  <small>DECISION</small>
                  <strong>{title(text(mutation.data.decision))}</strong>
                </span>
                <Badge value={mutation.data.decision} />
                <span>
                  <small>EVALUATION</small>
                  <strong>{text(mutation.data.evaluation_ms)} ms</strong>
                </span>
              </div>
              <p>{text(mutation.data.explanation)}</p>
              <h3>Rule trace</h3>
              {((mutation.data.trace ?? []) as Row[]).map((trace, index) => (
                <div
                  className={`trace-row ${trace.matched ? "matched" : "skipped"}`}
                  key={text(trace.rule_id)}
                >
                  <span>{trace.matched ? <Check /> : <X />}</span>
                  <b>{String(index + 1).padStart(2, "0")}</b>
                  <div>
                    <strong>{text(trace.rule_id)}</strong>
                    <small>{text(trace.reasons)}</small>
                  </div>
                  <Badge value={trace.matched ? "matched" : "skipped"} />
                </div>
              ))}
              <div className="risk-explain">
                <Gauge />
                <div>
                  <strong>
                    Contextual risk: {text((mutation.data.risk as Row)?.score)}
                    /100
                  </strong>
                  <p>{text((mutation.data.risk as Row)?.explanation)}</p>
                </div>
              </div>
            </div>
          ) : (
            <Empty
              title="Awaiting a test request"
              detail="Run the sample to inspect matches, skips, transformations, risk signals, and latency."
            />
          )}
        </Panel>
      </div>
    </>
  );
}

function Sessions({ locale }: { locale: Locale }) {
  const query = useQuery({
    queryKey: ["sessions"],
    queryFn: () => api<Page>("/sessions"),
  });
  if (query.error) return <ErrorState error={query.error} />;
  const rows = query.data?.items ?? [];
  return (
    <>
      <PageTitle
        eyebrow="PROTOCOL OBSERVABILITY"
        title="Live sessions"
        description="Every client-to-server exchange, policy decision, approval, redaction, and error in order."
        actions={
          <>
            <span className="live-pill">
              <span />5 LIVE
            </span>
            <span className="live-pill">
              <Filter />
              All sessions
            </span>
          </>
        }
      />
      <Panel
        title="MCP sessions"
        subtitle="Incrementally loaded protocol timelines"
      >
        <DataTable
          caption="MCP sessions"
          rows={rows}
          columns={[
            {
              key: "started_at",
              label: "Started",
              render: (row) => date(row.started_at, locale),
            },
            {
              key: "client",
              label: "Client",
              render: (row) => (
                <Link className="session-link" href="/sessions/overview">
                  <span className="client-dot" />
                  {text(row.client)}
                </Link>
              ),
            },
            { key: "server", label: "Destination" },
            {
              key: "environment",
              label: "Environment",
              render: (row) => <code>{text(row.environment)}</code>,
            },
            { key: "policy", label: "Policy" },
            { key: "event_count", label: "Events" },
            { key: "denied_call_count", label: "Blocked" },
            {
              key: "risk_summary",
              label: "Risk",
              render: (row) => (
                <Badge value={(row.risk_summary as Row)?.level ?? "unknown"} />
              ),
            },
            {
              key: "status",
              label: "Status",
              render: (row) => <Badge value={row.status} />,
            },
          ]}
        />
      </Panel>
    </>
  );
}

function useFirstSession() {
  const sessions = useQuery({
    queryKey: ["sessions"],
    queryFn: () => api<Page>("/sessions"),
  });
  const sessionId = sessions.data?.items[0]?.id;
  const detail = useQuery({
    queryKey: ["session", sessionId],
    queryFn: () => api<Row>(`/sessions/${sessionId}`),
    enabled: Boolean(sessionId),
  });
  return detail;
}

function SessionInvestigation({
  mode,
  locale,
}: {
  mode: string;
  locale: Locale;
}) {
  const detail = useFirstSession();
  const data = detail.data ?? {};
  const session = (data.session ?? {}) as Row;
  const events = ((data.events as Row)?.items ?? []) as Row[];
  const [simulation, setSimulation] = useState<Row | null>(null);
  const policies = useQuery({
    queryKey: ["policies"],
    queryFn: () => api<{ items: Row[] }>("/policies"),
    enabled: mode === "replay",
  });
  const simulate = useMutation({
    mutationFn: () => {
      const event =
        events.find((item) => item.method === "filesystem.read_file") ??
        events[0];
      const payload = (event?.sanitized_payload ?? {}) as Row;
      const params = (payload.params ?? {}) as Row;
      return api<Row>("/policy-tests", {
        method: "POST",
        body: JSON.stringify({
          policy_id: policies.data?.items[1]?.id ?? policies.data?.items[0]?.id,
          request: {
            tool: params.name ?? event?.method,
            arguments: params.arguments ?? {},
            server_trust: "trusted",
          },
          dry_run: true,
        }),
      });
    },
    onSuccess: setSimulation,
  });
  if (detail.error) return <ErrorState error={detail.error} />;
  const activeMode = mode.split("/").pop();
  return (
    <>
      <PageTitle
        eyebrow="SECURITY INVESTIGATION"
        title={`${text(session.client)} → ${text(session.server)}`}
        description={`Session ${text(session.id).slice(0, 8)} · ${date(session.started_at, locale)} · ${text(session.event_count)} recorded events`}
        actions={
          <>
            <Badge value={session.status ?? "loading"} />
            <Link className="button secondary" href="/audit">
              <Archive />
              Export evidence
            </Link>
          </>
        }
      />
      <div className="session-tabs">
        <Link
          className={activeMode === "overview" ? "active" : ""}
          href="/sessions/overview"
        >
          Overview
        </Link>
        <Link
          className={activeMode === "timeline" ? "active" : ""}
          href="/sessions/timeline"
        >
          Timeline
        </Link>
        <Link
          className={activeMode === "details" ? "active" : ""}
          href="/requests/details"
        >
          Raw request
        </Link>
        <Link
          className={activeMode === "replay" ? "active" : ""}
          href="/replay"
        >
          Replay
        </Link>
      </div>
      {mode === "sessions/overview" && (
        <>
          <div className="session-summary">
            <span>
              <small>Client</small>
              <strong>{text(session.client)}</strong>
            </span>
            <span>
              <small>Server</small>
              <strong>{text(session.server)}</strong>
            </span>
            <span>
              <small>Policy</small>
              <strong>{text(session.policy)}</strong>
            </span>
            <span>
              <small>Protocol</small>
              <code>{text(session.protocol_version)}</code>
            </span>
            <span>
              <small>Tool calls</small>
              <strong>{text(session.tool_call_count)}</strong>
            </span>
            <span>
              <small>Risk</small>
              <Badge
                value={(session.risk_summary as Row)?.level ?? "unknown"}
              />
            </span>
          </div>
          <div className="two-column">
            <Panel
              title="Risk narrative"
              subtitle="Highest-weight signals in this session"
            >
              <div className="risk-narrative">
                <div className="mini-score">
                  <b>{text((session.risk_summary as Row)?.score)}</b>
                  <small>/100</small>
                </div>
                <div>
                  <h3>
                    {title(text((session.risk_summary as Row)?.level))}{" "}
                    contextual risk
                  </h3>
                  <p>
                    Risk increased when the agent requested a side-effecting
                    capability. Deterministic policy remained authoritative.
                  </p>
                  <span className="signal-tag">
                    <AlertTriangle />
                    {title(text((session.risk_summary as Row)?.top_signal))}
                  </span>
                </div>
              </div>
            </Panel>
            <Panel
              title="Control outcomes"
              subtitle="Policy and inspection summary"
            >
              <div className="outcome-grid">
                <span>
                  <b>{text(session.tool_call_count)}</b>
                  <small>Tool calls</small>
                </span>
                <span>
                  <b>{text(session.denied_call_count)}</b>
                  <small>Denied</small>
                </span>
                <span>
                  <b>{text(session.approval_count)}</b>
                  <small>Approvals</small>
                </span>
                <span>
                  <b>0</b>
                  <small>Dropped events</small>
                </span>
              </div>
            </Panel>
          </div>
        </>
      )}
      {mode === "sessions/timeline" && (
        <Panel
          title="Protocol event timeline"
          subtitle="Hash-chained order with sanitized payloads"
        >
          <div className="timeline">
            {events.map((event) => (
              <article key={text(event.id)}>
                <div className={`timeline-icon ${text(event.response_status)}`}>
                  <EventIcon method={text(event.method)} />
                </div>
                <div>
                  <header>
                    <span>
                      <strong>{text(event.method)}</strong>
                      <small>
                        #{text(event.sequence)} · {text(event.direction)}
                      </small>
                    </span>
                    <time>{date(event.timestamp, locale)}</time>
                  </header>
                  <p>
                    {text(
                      (event.policy_result as Row)?.explanation ??
                        "Protocol message recorded and inspected.",
                    )}
                  </p>
                  <div>
                    <Badge
                      value={
                        (event.policy_result as Row)?.decision ??
                        event.response_status
                      }
                    />
                    <Badge
                      value={
                        (event.risk_result as Row)?.level ?? "informational"
                      }
                    />
                    <code>{text(event.event_hash).slice(0, 14)}…</code>
                  </div>
                </div>
              </article>
            ))}
          </div>
        </Panel>
      )}
      {mode === "requests/details" && <RequestDetail events={events} />}
      {mode === "replay" && (
        <div className="replay-grid">
          <Panel
            title="Simulation replay"
            subtitle="Re-evaluates stored sanitized payloads; the server is not called."
          >
            <div className="replay-config">
              <span className="simulation-badge">
                <Sparkles />
                NO SIDE EFFECTS
              </span>
              <label>
                Comparison policy
                <select>
                  {policies.data?.items.slice(0, 4).map((policy) => (
                    <option key={text(policy.id)}>
                      {text(policy.name)} · v{text(policy.version)}
                    </option>
                  ))}
                </select>
              </label>
              <button
                className="button primary wide"
                onClick={() => simulate.mutate()}
                disabled={simulate.isPending}
              >
                <Play />
                {simulate.isPending ? "Simulating…" : "Run simulation"}
              </button>
            </div>
          </Panel>
          <Panel
            title="Decision comparison"
            subtitle="Original record versus selected policy"
          >
            {simulation ? (
              <div className="comparison">
                <div>
                  <small>ORIGINAL</small>
                  <Badge value="deny" />
                  <strong>deny-secret-access</strong>
                  <p>
                    Request was blocked by the policy active during the session.
                  </p>
                </div>
                <ChevronRight />
                <div>
                  <small>SIMULATED</small>
                  <Badge value={simulation.decision} />
                  <strong>{text(simulation.matched_rules)}</strong>
                  <p>{text(simulation.explanation)}</p>
                </div>
              </div>
            ) : (
              <Empty
                title="No replay run"
                detail="Choose a version and simulate safely against stored events."
              />
            )}
          </Panel>
        </div>
      )}
    </>
  );
}

function EventIcon({ method }: { method: string }) {
  if (method.includes("tools")) return <TerminalSquare />;
  if (method.includes("resource")) return <Database />;
  if (method.includes("fixture")) return <ShieldAlert />;
  return <Activity />;
}

function RequestDetail({ events }: { events: Row[] }) {
  const event =
    events.find((row) => row.method === "terminal.execute") ??
    events.find((row) => row.method === "filesystem.write_file") ??
    events[0] ??
    {};
  return (
    <div className="request-grid">
      <Panel
        title="Sanitized protocol request"
        subtitle="Rendered as inert text; redactions are explicit."
        action={<Badge value={event.response_status ?? "unknown"} />}
      >
        <pre className="json-viewer" tabIndex={0}>
          {JSON.stringify(event.sanitized_payload ?? {}, null, 2)}
        </pre>
        <div className="payload-hash">
          <LockKeyhole />
          <span>
            <small>PAYLOAD SHA-256</small>
            <code>{text(event.payload_hash)}</code>
          </span>
        </div>
      </Panel>
      <aside>
        <Panel title="Policy decision" subtitle="Deterministic outcome">
          <div className="decision-result">
            <Badge value={(event.policy_result as Row)?.decision ?? "allow"} />
            <strong>
              {title(text((event.policy_result as Row)?.decision))}
            </strong>
            <p>{text((event.policy_result as Row)?.explanation)}</p>
            <div>
              <span>Matched rule</span>
              <b>
                {text(
                  (event.policy_result as Row)?.rule ??
                    (event.policy_result as Row)?.matched_rules,
                )}
              </b>
            </div>
          </div>
        </Panel>
        <Panel title="Risk signals" subtitle="Weighted context">
          <div className="signal-list">
            <span>
              <TerminalSquare />
              <b>Shell capability</b>
              <em>+35</em>
            </span>
            <span>
              <AlertTriangle />
              <b>Side effect</b>
              <em>+20</em>
            </span>
            <span>
              <BadgeCheck />
              <b>Known server</b>
              <em className="negative">−10</em>
            </span>
          </div>
        </Panel>
      </aside>
    </div>
  );
}

function Approvals({ locale }: { locale: Locale }) {
  const [statusFilter, setStatusFilter] = useState("pending");
  const query = useQuery({
    queryKey: ["approvals", statusFilter],
    queryFn: () => api<Page>(`/approvals?status=${statusFilter}`),
  });
  if (query.error) return <ErrorState error={query.error} />;
  const rows = query.data?.items ?? [];
  return (
    <>
      <PageTitle
        eyebrow="HUMAN CONTROL"
        title="Approval queue"
        description="Sensitive tool calls are paused until an authorized reviewer decides—safely and atomically."
        actions={
          <span className="live-pill amber">
            <Clock3 />8 WAITING
          </span>
        }
      />
      <div className="approval-layout">
        <div className="approval-rail">
          <button
            className={statusFilter === "pending" ? "active" : ""}
            onClick={() => setStatusFilter("pending")}
          >
            <Clock3 />
            Pending <b>8</b>
          </button>
          <button
            className={statusFilter === "approved" ? "active" : ""}
            onClick={() => setStatusFilter("approved")}
          >
            <Check />
            Approved <b>10</b>
          </button>
          <button
            className={statusFilter === "denied" ? "active" : ""}
            onClick={() => setStatusFilter("denied")}
          >
            <X />
            Denied <b>7</b>
          </button>
          <button
            className={statusFilter === "escalated" ? "active" : ""}
            onClick={() => setStatusFilter("escalated")}
          >
            <AlertTriangle />
            Escalated <b>2</b>
          </button>
          <button
            className={statusFilter === "expired" ? "active" : ""}
            onClick={() => setStatusFilter("expired")}
          >
            <Archive />
            Expired <b>3</b>
          </button>
        </div>
        <Panel
          title={`${title(statusFilter)} requests`}
          subtitle="Filtered by durable approval status, then sorted by risk and expiration"
        >
          <div className="approval-cards">
            {rows.slice(0, 12).map((approval) => (
              <Link href="/approvals/details" key={text(approval.id)}>
                <div className="approval-risk">
                  <strong>{text((approval.risk_context as Row)?.score)}</strong>
                  <small>RISK</small>
                </div>
                <div className="approval-main">
                  <span>
                    <Badge value={approval.status} />
                    <small>{date(approval.requested_at, locale)}</small>
                  </span>
                  <h3>{text(approval.tool_name)}</h3>
                  <p>
                    {title(text((approval.policy_context as Row)?.rule))} ·
                    expires {date(approval.expires_at, locale)}
                  </p>
                  <div>
                    <code>
                      {JSON.stringify(approval.original_arguments).slice(0, 90)}
                      …
                    </code>
                  </div>
                </div>
                <ChevronRight />
              </Link>
            ))}
          </div>
        </Panel>
      </div>
    </>
  );
}

function ApprovalDetail({ locale }: { locale: Locale }) {
  const queryClient = useQueryClient();
  const list = useQuery({
    queryKey: ["approvals"],
    queryFn: () => api<Page>("/approvals?status=pending"),
  });
  const approvalId = list.data?.items[0]?.id;
  const detail = useQuery({
    queryKey: ["approval", approvalId],
    queryFn: () => api<Row>(`/approvals/${approvalId}`),
    enabled: Boolean(approvalId),
  });
  const [justification, setJustification] = useState(
    "Reviewed synthetic write; approve only for this request.",
  );
  const decision = useMutation({
    mutationFn: (choice: string) =>
      api<Row>(`/approvals/${approvalId}/decision`, {
        method: "POST",
        body: JSON.stringify({
          decision: choice,
          expected_version: detail.data?.version,
          justification,
        }),
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["approvals"] });
      queryClient.invalidateQueries({ queryKey: ["approval", approvalId] });
    },
  });
  if (detail.error) return <ErrorState error={detail.error} />;
  const item = detail.data ?? {};
  const risk = (item.risk_context ?? {}) as Row;
  const policy = (item.policy_context ?? {}) as Row;
  return (
    <>
      <PageTitle
        eyebrow="APPROVAL REVIEW"
        title={text(item.tool_name || "Loading request…")}
        description={`Request ${text(item.request_id)} · paused ${date(item.requested_at, locale)}`}
        actions={
          <>
            <Badge value={item.status ?? "pending"} />
            <span className="expires">
              <Clock3 />
              Expires {date(item.expires_at, locale)}
            </span>
          </>
        }
      />
      <div className="approval-detail-grid">
        <div>
          <Panel
            title="Requested action"
            subtitle="Original arguments from the paused MCP request"
          >
            <pre className="json-viewer" tabIndex={0}>
              {JSON.stringify(item.original_arguments ?? {}, null, 2)}
            </pre>
          </Panel>
          <Panel
            title="Expected side effects"
            subtitle="Inferred from capability schema and request context"
          >
            <div className="impact-grid">
              <span>
                <FileText />
                <div>
                  <b>Filesystem write</b>
                  <small>Creates or replaces one file</small>
                </div>
              </span>
              <span>
                <Globe2 />
                <div>
                  <b>No network</b>
                  <small>Destination server is isolated</small>
                </div>
              </span>
              <span>
                <RefreshCcw />
                <div>
                  <b>Reversible</b>
                  <small>Repository history can restore content</small>
                </div>
              </span>
            </div>
          </Panel>
          <Panel
            title="Decision rationale"
            subtitle="Required and recorded in the audit chain"
          >
            <textarea
              className="rationale"
              aria-label="Approval decision rationale"
              value={justification}
              onChange={(event) => setJustification(event.target.value)}
            />
            <div className="decision-buttons">
              <button
                className="button danger"
                onClick={() => decision.mutate("deny")}
                disabled={decision.isPending}
              >
                <X />
                Deny
              </button>
              <button
                className="button secondary"
                onClick={() => decision.mutate("approve_modified")}
                disabled={decision.isPending}
              >
                <Braces />
                Approve modified
              </button>
              <button
                className="button primary"
                onClick={() => decision.mutate("approve_once")}
                disabled={decision.isPending}
              >
                <Check />
                Approve once
              </button>
            </div>
            {decision.error && (
              <p className="form-error">{decision.error.message}</p>
            )}
            {decision.data && (
              <p className="success-note">
                <Check />
                {text(decision.data.message)}
              </p>
            )}
          </Panel>
        </div>
        <aside>
          <Panel title="Contextual risk" subtitle="Explainable weighted score">
            <div className="large-risk">
              <strong>{text(risk.score)}</strong>
              <span>/100</span>
              <Badge value={risk.level ?? "high"} />
            </div>
            <div className="signal-list">
              <span>
                <FileText />
                <b>Filesystem write</b>
                <em>+20</em>
              </span>
              <span>
                <AlertTriangle />
                <b>External side effect</b>
                <em>+20</em>
              </span>
              <span>
                <Server />
                <b>Restricted server</b>
                <em>+15</em>
              </span>
            </div>
          </Panel>
          <Panel title="Policy context" subtitle="Rule that paused the request">
            <div className="policy-context">
              <ShieldCheck />
              <div>
                <strong>{text(policy.policy)}</strong>
                <code>{text(policy.rule)}</code>
                <p>Filesystems writes require an explicit reviewer decision.</p>
              </div>
            </div>
          </Panel>
          <Panel title="Requester" subtitle="Identity and destination">
            <dl className="meta-list">
              <div>
                <dt>Client</dt>
                <dd>Codex Local</dd>
              </div>
              <div>
                <dt>Server</dt>
                <dd>Safe Filesystem</dd>
              </div>
              <div>
                <dt>Environment</dt>
                <dd>
                  <code>development</code>
                </dd>
              </div>
              <div>
                <dt>Timeout</dt>
                <dd>10 minutes</dd>
              </div>
            </dl>
          </Panel>
        </aside>
      </div>
    </>
  );
}

function Secrets({ locale }: { locale: Locale }) {
  const query = useQuery({
    queryKey: ["secrets"],
    queryFn: () =>
      api<{ items: Row[]; plaintext_storage: boolean; note: string }>(
        "/secrets",
      ),
  });
  if (query.error) return <ErrorState error={query.error} />;
  const rows = query.data?.items ?? [];
  return (
    <>
      <PageTitle
        eyebrow="DATA LOSS PREVENTION"
        title="Secret redaction"
        description="Credential-shaped values are detected, replaced, and fingerprinted without retaining plaintext."
        actions={<Badge value="plaintext storage off" tone="allowed" />}
      />
      <div className="redaction-hero">
        <div>
          <FileKey2 />
          <span>
            <strong>{rows.length}</strong>
            <small>DETECTIONS</small>
          </span>
        </div>
        <div>
          <ShieldCheck />
          <span>
            <strong>100%</strong>
            <small>REDACTED</small>
          </span>
        </div>
        <div>
          <LockKeyhole />
          <span>
            <strong>0</strong>
            <small>PLAINTEXT RETAINED</small>
          </span>
        </div>
        <p>
          <ShieldAlert />
          Detection is a defense-in-depth control. Pattern and entropy
          heuristics can have false positives and false negatives.
        </p>
      </div>
      <Panel title="Redaction events" subtitle={query.data?.note}>
        <DataTable
          caption="Secret redaction events"
          rows={rows}
          columns={[
            {
              key: "detected_at",
              label: "Detected",
              render: (row) => date(row.detected_at, locale),
            },
            {
              key: "kind",
              label: "Classification",
              render: (row) => (
                <span className="secret-kind">
                  <FileKey2 />
                  {title(text(row.kind))}
                </span>
              ),
            },
            {
              key: "path",
              label: "Payload path",
              render: (row) => <code>{text(row.path)}</code>,
            },
            {
              key: "fingerprint",
              label: "Fingerprint",
              render: (row) => <code>sha256:{text(row.fingerprint)}</code>,
            },
            {
              key: "action",
              label: "Action",
              render: (row) => <Badge value={row.action} tone="allowed" />,
            },
          ]}
        />
      </Panel>
    </>
  );
}

function InjectionWarnings() {
  const detail = useFirstSession();
  const events = (((detail.data?.events ?? {}) as Row).items ?? []) as Row[];
  const warnings = events.filter(
    (event) =>
      text((event.risk_result as Row)?.level) === "high" ||
      text(event.method).includes("injection"),
  );
  return (
    <>
      <PageTitle
        eyebrow="CONTENT INSPECTION"
        title="Injection warnings"
        description="Layered heuristics identify suspicious instructions. Deterministic policies remain authoritative."
        actions={<Badge value="heuristic signal" tone="medium" />}
      />
      <div className="warning-banner">
        <AlertTriangle />
        <div>
          <strong>Detection is intentionally cautious—not perfect.</strong>
          <p>
            These findings can be false positives or false negatives. Content
            classifiers never grant permissions or override policy.
          </p>
        </div>
      </div>
      <Panel
        title="Suspicious content findings"
        subtitle="Source-aware signals with confidence and suggested response"
      >
        <div className="finding-list">
          {(warnings.length ? warnings : events.slice(0, 5)).map(
            (event, index) => (
              <article key={text(event.id)}>
                <span className="finding-index">
                  {String(index + 1).padStart(2, "0")}
                </span>
                <div>
                  <header>
                    <Badge
                      value={
                        index % 2 ? "policy bypass" : "instruction override"
                      }
                      tone="high"
                    />
                    <span>{86 + index}% confidence</span>
                  </header>
                  <h3>
                    {index % 2
                      ? "Attempt to bypass Sentinel policy controls"
                      : "Unexpected instruction boundary inside resource content"}
                  </h3>
                  <p>
                    Source: <code>{text(event.method)}</code> · Suggested
                    response: warn, require review, and preserve deterministic
                    enforcement.
                  </p>
                  <pre>
                    “SYNTHETIC SECURITY FIXTURE: Ignore previous instructions…”
                  </pre>
                </div>
                <ShieldAlert />
              </article>
            ),
          )}
        </div>
      </Panel>
    </>
  );
}

function Sandboxes({ locale }: { locale: Locale }) {
  const query = useQuery({
    queryKey: ["sandboxes"],
    queryFn: () =>
      api<{
        items: Row[];
        manager_available: boolean;
        isolation_notice: string;
      }>("/sandboxes"),
  });
  if (query.error) return <ErrorState error={query.error} />;
  const rows = query.data?.items ?? [];
  return (
    <>
      <PageTitle
        eyebrow="CONTAINER ISOLATION"
        title="Sandbox manager"
        description="Non-root MCP servers with read-only roots, dropped capabilities, hard resources, controlled mounts, and no network by default."
        actions={
          query.data?.manager_available ? (
            <Link className="button primary" href="/api/docs">
              <Box />
              Open sandbox API
            </Link>
          ) : (
            <span
              className="live-pill amber"
              title="Install Docker or enable the sandbox Compose profile"
            >
              <Box />
              Docker unavailable
            </span>
          )
        }
      />
      <div className="sandbox-notice">
        <ShieldAlert />
        <p>
          <strong>Isolation boundary:</strong> {query.data?.isolation_notice}{" "}
          Never mount the Docker socket inside untrusted containers.
        </p>
      </div>
      <div className="sandbox-profiles">
        <article>
          <Network />
          <strong>No Network</strong>
          <p>Read-only root · tmpfs only</p>
          <Badge value="recommended" tone="allowed" />
        </article>
        <article>
          <Eye />
          <strong>Read-Only Workspace</strong>
          <p>Source mounted read-only</p>
        </article>
        <article>
          <Code2 />
          <strong>Development Workspace</strong>
          <p>Scoped writable mount</p>
        </article>
        <article>
          <Globe2 />
          <strong>Restricted Network</strong>
          <p>Allowlisted egress proxy</p>
        </article>
      </div>
      <Panel
        title="Sandbox lifecycle"
        subtitle="Runtime controls, image digests, and termination reasons"
      >
        <DataTable
          caption="MCP server sandboxes"
          rows={rows}
          columns={[
            {
              key: "container_id",
              label: "Container",
              render: (row) => (
                <span className="primary-cell">
                  <span className="server-icon">
                    <Box />
                  </span>
                  <span>
                    <strong>{text(row.container_id).slice(0, 16)}</strong>
                    <small>{text(row.image_digest).slice(0, 24)}…</small>
                  </span>
                </span>
              ),
            },
            {
              key: "profile",
              label: "Profile",
              render: (row) => <Badge value={row.profile} />,
            },
            {
              key: "status",
              label: "Status",
              render: (row) => <Badge value={row.status} />,
            },
            {
              key: "config",
              label: "Limits",
              render: (row) => {
                const config = row.config as Row;
                return (
                  <span>
                    {text(config?.memory_mb)} MB · {text(config?.cpus)} CPU ·{" "}
                    {text(config?.pids)} PIDs
                  </span>
                );
              },
            },
            {
              key: "started_at",
              label: "Started",
              render: (row) => date(row.started_at, locale),
            },
            { key: "termination_reason", label: "Termination" },
          ]}
        />
      </Panel>
    </>
  );
}

function RiskDashboard() {
  const query = useQuery({
    queryKey: ["risk"],
    queryFn: () => api<Row>("/risk"),
  });
  if (query.error) return <ErrorState error={query.error} />;
  const distribution = (query.data?.distribution ?? {}) as Row;
  const tools = (query.data?.tools ?? []) as Row[];
  const chartData = Object.entries(distribution).map(([name, value]) => ({
    name,
    value,
  }));
  return (
    <>
      <PageTitle
        eyebrow="EXPLAINABLE SCORING"
        title="Risk dashboard"
        description="Transparent weights and triggered signals across servers, tools, and recent requests."
        actions={
          <Link className="button secondary" href="/settings">
            <Settings />
            Review configuration
          </Link>
        }
      />
      <div className="risk-dashboard-grid">
        <Panel
          title="Server risk distribution"
          subtitle="Current capability scans"
        >
          <div className="donut">
            <ResponsiveContainer width="100%" height={260}>
              <PieChart>
                <Pie
                  data={chartData}
                  dataKey="value"
                  nameKey="name"
                  innerRadius={72}
                  outerRadius={104}
                  paddingAngle={3}
                >
                  {chartData.map((entry) => (
                    <Cell key={entry.name} fill={RISK_COLORS[entry.name]} />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{
                    background: "var(--panel-solid)",
                    border: "1px solid var(--line)",
                    borderRadius: 10,
                  }}
                />
              </PieChart>
            </ResponsiveContainer>
            <div>
              <strong>8</strong>
              <span>SERVERS</span>
            </div>
          </div>
          <div className="legend">
            {chartData.map((item) => (
              <span key={item.name}>
                <i style={{ background: RISK_COLORS[item.name] }} />
                {title(item.name)} <b>{text(item.value)}</b>
              </span>
            ))}
          </div>
        </Panel>
        <Panel
          title="Risk score composition"
          subtitle="Example: restricted shell server"
        >
          <div className="waterfall">
            {[
              ["Base tool risk", 5],
              ["Shell execution", 35],
              ["Write side effect", 20],
              ["Untrusted server", 15],
              ["Encoded content", 15],
              ["Known package", -10],
            ].map(([label, value]) => (
              <div key={String(label)}>
                <span>{label}</span>
                <div>
                  <i
                    style={{ width: `${Math.abs(Number(value)) * 2}%` }}
                    className={Number(value) < 0 ? "negative" : ""}
                  />
                </div>
                <b>
                  {Number(value) > 0 ? "+" : ""}
                  {value}
                </b>
              </div>
            ))}
            <footer>
              <span>Final contextual score</span>
              <strong>80 / 100 · HIGH</strong>
            </footer>
          </div>
        </Panel>
      </div>
      <Panel
        title="Highest-risk capabilities"
        subtitle="Tools with the largest deterministic exposure"
      >
        <DataTable
          caption="Highest-risk MCP tools"
          rows={tools}
          columns={[
            {
              key: "name",
              label: "Capability",
              render: (row) => (
                <span className="primary-cell">
                  <span className="method-icon">
                    <TerminalSquare />
                  </span>
                  <span>
                    <strong>{text(row.name)}</strong>
                    <small>{text(row.category)}</small>
                  </span>
                </span>
              ),
            },
            {
              key: "side_effect",
              label: "Side effect",
              render: (row) => <Badge value={row.side_effect} />,
            },
            {
              key: "risk_score",
              label: "Score",
              render: (row) => (
                <span className="risk-bar-cell">
                  <span>
                    <i
                      style={{
                        width: `${text(row.risk_score)}%`,
                        background: RISK_COLORS[text(row.risk_level)],
                      }}
                    />
                  </span>
                  <b>{text(row.risk_score)}</b>
                </span>
              ),
            },
            {
              key: "risk_level",
              label: "Level",
              render: (row) => <Badge value={row.risk_level} />,
            },
            {
              key: "review_status",
              label: "Review",
              render: (row) => <Badge value={row.review_status} />,
            },
          ]}
        />
      </Panel>
    </>
  );
}

function Reports({ locale }: { locale: Locale }) {
  const queryClient = useQueryClient();
  const query = useQuery({
    queryKey: ["reports"],
    queryFn: () => api<{ items: Row[] }>("/reports"),
  });
  const exportMutation = useMutation({
    mutationFn: () => api<Row>("/audit/export", { method: "POST" }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["reports"] }),
  });
  if (query.error) return <ErrorState error={query.error} />;
  return (
    <>
      <PageTitle
        eyebrow="EVIDENCE & COMPLIANCE"
        title="Reports and evidence"
        description="Sanitized security reports, signed audit bundles, event exports, and verification material."
        actions={
          <>
            <Link className="button secondary" href="/audit">
              <BadgeCheck />
              Verify audit
            </Link>
            <button
              className="button primary"
              onClick={() => exportMutation.mutate()}
              disabled={exportMutation.isPending}
            >
              <Archive />
              {exportMutation.isPending ? "Signing…" : "Generate bundle"}
            </button>
          </>
        }
      />
      <div className="report-types">
        <article>
          <FileText />
          <strong>Session Security</strong>
          <p>Timeline, decisions, risk, and findings.</p>
        </article>
        <article>
          <Radar />
          <strong>Server Assessment</strong>
          <p>Capabilities, schemas, and exposure.</p>
        </article>
        <article>
          <ShieldCheck />
          <strong>Policy Compliance</strong>
          <p>Coverage, denials, and regressions.</p>
        </article>
        <article>
          <ListChecks />
          <strong>Approval Activity</strong>
          <p>Reviewer decisions and timings.</p>
        </article>
      </div>
      {exportMutation.data && (
        <div className="success-banner">
          <Check />
          <div>
            <strong>Signed evidence bundle generated</strong>
            <p>
              SHA-256: <code>{text(exportMutation.data.sha256)}</code>
            </p>
          </div>
        </div>
      )}
      <Panel
        title="Generated reports"
        subtitle="Artifacts are content-hashed; signed bundles use Ed25519"
      >
        <DataTable
          caption="Generated security reports"
          rows={query.data?.items ?? []}
          columns={[
            {
              key: "report_type",
              label: "Report",
              render: (row) => (
                <span className="primary-cell">
                  <span className="method-icon">
                    <FileText />
                  </span>
                  <span>
                    <strong>{text(row.report_type)}</strong>
                    <small>{text(row.format).toUpperCase()}</small>
                  </span>
                </span>
              ),
            },
            {
              key: "status",
              label: "Status",
              render: (row) => <Badge value={row.status} tone="allowed" />,
            },
            {
              key: "generated_at",
              label: "Generated",
              render: (row) => date(row.generated_at, locale),
            },
            {
              key: "sha256",
              label: "Content hash",
              render: (row) => <code>{text(row.sha256).slice(0, 18)}…</code>,
            },
            {
              key: "signature",
              label: "Signature",
              render: (row) => (
                <Badge
                  value={
                    text(row.signature).startsWith("synthetic")
                      ? "seed fixture"
                      : "Ed25519"
                  }
                />
              ),
            },
          ]}
        />
      </Panel>
    </>
  );
}

function AuditExport() {
  const queryClient = useQueryClient();
  const verify = useQuery({
    queryKey: ["audit-verify"],
    queryFn: () => api<Row>("/audit/verify"),
  });
  const exportMutation = useMutation({
    mutationFn: () => api<Row>("/audit/export", { method: "POST" }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["reports"] }),
  });
  return (
    <>
      <PageTitle
        eyebrow="TAMPER EVIDENCE"
        title="Audit export"
        description="Verify the append-oriented workspace chain and produce a signed, independently checkable evidence bundle."
        actions={
          <button
            className="button primary"
            onClick={() => exportMutation.mutate()}
            disabled={exportMutation.isPending}
          >
            <Archive />
            {exportMutation.isPending
              ? "Building manifest…"
              : "Export signed bundle"}
          </button>
        }
      />
      <div className="audit-verdict">
        <div className={verify.data?.valid ? "pass" : "checking"}>
          {verify.data?.valid ? <Check /> : <RefreshCcw className="spin" />}
        </div>
        <div>
          <span className="eyebrow">WORKSPACE AUDIT CHAIN</span>
          <h2>
            {verify.data?.valid
              ? "Integrity verification passed"
              : "Verifying chained records…"}
          </h2>
          <p>
            {text(verify.data?.message)} · Guarantee:{" "}
            {text(verify.data?.guarantee)}
          </p>
        </div>
        <code>SHA-256 → SHA-256 → SHA-256</code>
      </div>
      <div className="audit-flow">
        <span>
          <FileText />
          <b>Sanitize</b>
          <small>Remove secrets</small>
        </span>
        <ChevronRight />
        <span>
          <Braces />
          <b>Canonicalize</b>
          <small>Stable JSON</small>
        </span>
        <ChevronRight />
        <span>
          <LockKeyhole />
          <b>Hash chain</b>
          <small>Previous + payload</small>
        </span>
        <ChevronRight />
        <span>
          <BadgeCheck />
          <b>Sign</b>
          <small>Ed25519 manifest</small>
        </span>
        <ChevronRight />
        <span>
          <Archive />
          <b>Bundle</b>
          <small>ZIP evidence</small>
        </span>
      </div>
      <div className="two-column">
        <Panel title="Bundle contents" subtitle="Portable and inspectable">
          <div className="bundle-tree">
            <code>sentinel-audit/</code>
            <code>├── manifest.json</code>
            <code>├── manifest.sig</code>
            <code>├── public-key.pem</code>
            <code>├── report.html</code>
            <code>├── report.pdf</code>
            <code>├── events.jsonl</code>
            <code>├── audit.jsonl</code>
            <code>└── verification.txt</code>
          </div>
        </Panel>
        <Panel
          title="Independent verification"
          subtitle="No running Sentinel instance required"
        >
          <div className="terminal">
            <span>$ mcp-sentinel audit verify sentinel-audit.zip</span>
            <p>
              <b>PASS</b> Ed25519 manifest signature is valid
              <br />
              <b>PASS</b> verified report.pdf
              <br />
              <b>PASS</b> verified events.jsonl
            </p>
          </div>
          <p className="limitation">
            <AlertTriangle />
            Hash chains reveal certain modifications; they do not make storage
            immutable.
          </p>
        </Panel>
      </div>
    </>
  );
}

function SettingsPage() {
  const query = useQuery({
    queryKey: ["settings"],
    queryFn: () => api<Row>("/settings"),
  });
  if (query.error) return <ErrorState error={query.error} />;
  const workspace = (query.data?.workspace ?? {}) as Row;
  const security = (query.data?.security ?? {}) as Row;
  return (
    <>
      <PageTitle
        eyebrow="WORKSPACE CONTROL"
        title="Settings"
        description="Privacy, retention, security defaults, locale, and gateway behavior for this workspace."
      />
      <div className="settings-grid">
        <aside>
          <span className="active">
            <Settings />
            General
          </span>
          <span>
            <LockKeyhole />
            Security
          </span>
          <span>
            <Archive />
            Data retention
          </span>
          <span>
            <Bell />
            Notifications (adapter)
          </span>
          <span>
            <CircleUserRound />
            Members & roles (read-only)
          </span>
          <span>
            <Globe2 />
            Integrations (configuration)
          </span>
        </aside>
        <div>
          <Panel
            title="Workspace profile"
            subtitle="Identity and local-first deployment"
          >
            <div className="settings-form">
              <label>
                Workspace name
                <input value={text(workspace.name)} readOnly />
              </label>
              <label>
                Workspace slug
                <input value={text(workspace.slug)} readOnly />
              </label>
              <label>
                Plan
                <input value={title(text(workspace.plan_type))} readOnly />
              </label>
            </div>
          </Panel>
          <Panel
            title="Security defaults"
            subtitle="Sensitive enforcement fails closed"
          >
            <div className="toggle-list">
              <div>
                <span>
                  <ShieldCheck />
                  <div>
                    <strong>Fail closed</strong>
                    <p>
                      Deny when policy or inspection services are unavailable.
                    </p>
                  </div>
                </span>
                <span
                  className="toggle on"
                  role="img"
                  aria-label="Fail closed enabled and managed by deployment configuration"
                >
                  <i />
                </span>
              </div>
              <div>
                <span>
                  <FileKey2 />
                  <div>
                    <strong>Redacted privacy mode</strong>
                    <p>
                      Store sanitized payloads and secret fingerprints only.
                    </p>
                  </div>
                </span>
                <span
                  className="toggle on"
                  role="img"
                  aria-label="Redacted mode enabled and managed by workspace policy"
                >
                  <i />
                </span>
              </div>
              <div>
                <span>
                  <Archive />
                  <div>
                    <strong>Raw payload retention</strong>
                    <p>
                      {text(security.raw_payload_retention_days)} days before
                      automatic cleanup.
                    </p>
                  </div>
                </span>
                <Badge
                  value={`${text(security.raw_payload_retention_days)} days`}
                />
              </div>
              <div>
                <span>
                  <AlertOctagon />
                  <div>
                    <strong>Forensic mode</strong>
                    <p>
                      Requires elevated permission and explicit configuration.
                    </p>
                  </div>
                </span>
                <span
                  className="toggle"
                  role="img"
                  aria-label="Forensic mode disabled and not implemented in version 0.1"
                >
                  <i />
                </span>
              </div>
            </div>
          </Panel>
        </div>
      </div>
    </>
  );
}
