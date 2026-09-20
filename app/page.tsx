'use client';

import {
  Activity,
  AlertCircle,
  AlertTriangle,
  Archive,
  ArrowUpRight,
  Boxes,
  Building2,
  Check,
  ChevronLeft,
  ChevronRight,
  CircleDot,
  Clock3,
  Download,
  Fingerprint,
  Inbox,
  Languages,
  LayoutDashboard,
  LoaderCircle,
  LockKeyhole,
  LogIn,
  Network,
  PencilLine,
  Plus,
  Radar,
  RefreshCw,
  ScanLine,
  ScrollText,
  Search,
  Settings,
  ShieldCheck,
  Terminal,
  Wifi,
  WifiOff,
  X,
} from 'lucide-react';
import {
  QueryClient,
  QueryClientProvider,
  useMutation,
  useQuery,
  useQueryClient,
} from '@tanstack/react-query';
import { createContext, useContext, useEffect, useMemo, useState } from 'react';

import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { Badge } from '@/components/ui/badge';
import { Button, buttonVariants } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Checkbox } from '@/components/ui/checkbox';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import {
  NativeSelect,
  NativeSelectOption,
} from '@/components/ui/native-select';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import { Switch } from '@/components/ui/switch';
import { SettingsPanel } from '@/app/settings-panel';
import { apiEndpoint, apiRequest } from '@/app/client-api';
import { clearWorkspaceCache, isSecureLanOrigin } from '@/app/client-security';
import { cn } from '@/lib/utils';

type View =
  | 'dashboard'
  | 'assets'
  | 'incidents'
  | 'scans'
  | 'checks'
  | 'settings';
type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
type ScanStatus = 'queued' | 'running' | 'succeeded' | 'partial' | 'failed';
type Locale = 'tr' | 'en';

type Asset = {
  id: string;
  hostname: string;
  port: number;
  label: string;
  owner: string;
  environment: string;
  tags: string[];
  allowPrivate: boolean;
  enabled: boolean;
  scanProfile: 'native' | 'deep';
  expiryWarningDays: number;
  scanIntervalMinutes: number;
  lastScanAt: string | null;
  nextScanAt: string | null;
  latestGrade: string | null;
  latestStatus: ScanStatus | 'never_scanned';
  certificateExpiresAt: string | null;
  latestIp: string | null;
  source: 'manual' | 'crt.name';
  parentAssetId: string | null;
  discoveredAt: string | null;
  firstSeenAt: string | null;
  discoveredAssetCount: number;
  openIncidentCount: number;
  criticalIncidentCount: number;
};

type Scan = {
  id: string;
  assetId: string;
  hostname: string;
  port: number;
  profile: 'native' | 'deep';
  trigger: 'manual' | 'scheduled' | 'initial';
  status: ScanStatus;
  startedAt: string | null;
  finishedAt: string | null;
  durationMs: number | null;
  grade: string | null;
  scannerVersion: string | null;
  errorCode: string | null;
  errorMessage: string | null;
  observations: Record<string, unknown> | null;
  createdAt: string;
};

type Incident = {
  id: string;
  assetId: string;
  hostname: string;
  port: number;
  owner: string;
  ruleKey: string;
  severity: Severity;
  status: 'open' | 'acknowledged' | 'resolved';
  title: string;
  description: string;
  evidence: Record<string, unknown>;
  firstSeenAt: string;
  lastSeenAt: string;
  resolvedAt: string | null;
  occurrenceCount: number;
  scanId: string | null;
};

type DashboardData = {
  summary: {
    totalAssets: number;
    openIncidents: number;
    criticalIncidents: number;
    expiringSoon: number;
    healthyPercentage: number;
    runningScans: number;
    queuedScans: number;
  };
  assets: Asset[];
  incidents: Incident[];
  recentScans: Scan[];
  generatedAt: string;
};

type IncidentPage = {
  incidents: Incident[];
  total: number;
  counts: Record<Severity, number>;
  limit: number;
  offset: number;
};

type AppUser = {
  id: string;
  username: string;
  displayName: string;
  role: 'admin' | 'operator' | 'viewer';
  enabled: boolean;
};

type BootstrapState = {
  setupRequired: boolean;
  setupCodeRequired: boolean;
  language: Locale;
  organization: string;
  lanEnabled: boolean;
  authEnabled: boolean;
  defaultScanProfile: 'native' | 'deep';
  defaultExpiryWarningDays: number;
  defaultScanIntervalMinutes: number;
  authenticated: boolean;
  authenticationRequired: boolean;
  lanAccessBlocked: boolean;
  originAllowed: boolean;
  user: AppUser | null;
  suggestedOrigins: string[];
};

type CheckDefinition = {
  key: string;
  title: string;
  category: string;
  severity: Severity | 'dynamic';
  source: string;
  enabled: boolean;
  requires?: string;
  recommendedCadence?: 'daily' | 'weekly' | 'monthly';
};

type Health = {
  ok: boolean;
  version: string;
  bind: string;
  privateTargetsAllowed: boolean;
  publicDnsResolver: string | null;
  subdomainDiscovery: {
    enabled: boolean;
    provider: 'crt.name';
    limit: number;
  };
  engines: {
    native: { available: boolean; version: string };
    testssl: {
      available: boolean;
      version: string | null;
      path: string;
      error: string | null;
    };
    running: number;
    concurrency: number;
  };
};

async function api<T>(path: string, init: RequestInit = {}): Promise<T> {
  return apiRequest<T>(path, init);
}

const LocaleContext = createContext<Locale>('tr');
const AccessContext = createContext<'admin' | 'operator' | 'viewer'>('viewer');

function useLocale() {
  return useContext(LocaleContext);
}

function useAccess() {
  const role = useContext(AccessContext);
  return {
    role,
    canOperate: role === 'admin' || role === 'operator',
    isAdmin: role === 'admin',
  };
}

function say(locale: Locale, turkish: string, english: string) {
  return locale === 'en' ? english : turkish;
}

const severityMeta: Record<
  Severity,
  { label: string; className: string; dot: string }
> = {
  critical: {
    label: 'Kritik',
    className: 'border-critical/20 bg-critical/8 text-critical',
    dot: 'bg-critical',
  },
  high: {
    label: 'Yüksek',
    className: 'border-orange-500/20 bg-orange-500/8 text-orange-700',
    dot: 'bg-orange-500',
  },
  medium: {
    label: 'Orta',
    className: 'border-warning/20 bg-warning/8 text-warning',
    dot: 'bg-warning',
  },
  low: {
    label: 'Düşük',
    className: 'border-sky-500/20 bg-sky-500/8 text-sky-700',
    dot: 'bg-sky-500',
  },
  info: {
    label: 'Bilgi',
    className: 'border-border bg-muted text-muted-foreground',
    dot: 'bg-muted-foreground',
  },
};

const scanStatusMeta: Record<
  ScanStatus | 'never_scanned',
  { label: string; className: string }
> = {
  queued: { label: 'Kuyrukta', className: 'text-sky-700' },
  running: { label: 'Taranıyor', className: 'text-primary' },
  succeeded: { label: 'Başarılı', className: 'text-healthy' },
  partial: { label: 'Kısmi', className: 'text-warning' },
  failed: { label: 'Başarısız', className: 'text-critical' },
  never_scanned: { label: 'Taranmadı', className: 'text-muted-foreground' },
};

const navItems = (locale: Locale) => [
  {
    id: 'dashboard' as const,
    label: say(locale, 'Genel bakış', 'Overview'),
    icon: LayoutDashboard,
  },
  {
    id: 'assets' as const,
    label: say(locale, 'Varlıklar', 'Assets'),
    icon: Boxes,
  },
  {
    id: 'incidents' as const,
    label: say(locale, "Incident'lar", 'Incidents'),
    icon: AlertTriangle,
  },
  {
    id: 'scans' as const,
    label: say(locale, 'Taramalar', 'Scans'),
    icon: ScanLine,
  },
  {
    id: 'checks' as const,
    label: say(locale, 'Kontroller', 'Checks'),
    icon: ScrollText,
  },
];

const viewCopyTr: Record<
  View,
  { eyebrow: string; title: string; description: string }
> = {
  dashboard: {
    eyebrow: 'Güvenlik operasyon merkezi',
    title: 'Sertifika görünürlüğü, tek ekranda.',
    description:
      'Domain envanterinizi izleyin, TLS risklerini erkenden yakalayın ve bulguları sahiplerine ulaştırın.',
  },
  assets: {
    eyebrow: 'Varlık envanteri',
    title: 'İzlenen TLS uçları',
    description:
      'Sahiplik, ortam, yenileme eşiği ve tarama profilini tek yerden yönetin.',
  },
  incidents: {
    eyebrow: 'Risk kuyruğu',
    title: "Açık incident'lar",
    description:
      'Kritik riskleri önceleyin, sahiplenin ve güvenilir bir taramayla kapandığını doğrulayın.',
  },
  scans: {
    eyebrow: 'Tarama geçmişi',
    title: 'Motor aktivitesi',
    description:
      'Native TLS ve testssl.sh çalışmalarının durumunu, süresini ve kanıtlarını inceleyin.',
  },
  checks: {
    eyebrow: 'Kontrol kataloğu',
    title: 'Alarm şablonları',
    description:
      'Probe sonuçlarından incident üreten sürümlenebilir kontrolleri görün.',
  },
  settings: {
    eyebrow: 'Yerel çalışma alanı',
    title: 'Motor ve güvenlik ayarları',
    description: 'Tarayıcı yeteneklerini ve güvenli varsayılanları doğrulayın.',
  },
};

const viewCopyEn: typeof viewCopyTr = {
  dashboard: {
    eyebrow: 'Security operations center',
    title: 'Certificate visibility, in one place.',
    description:
      'Monitor your domain inventory, catch TLS risks early, and route findings to owners.',
  },
  assets: {
    eyebrow: 'Asset inventory',
    title: 'Monitored TLS endpoints',
    description:
      'Manage ownership, environment, renewal thresholds, and scan profiles.',
  },
  incidents: {
    eyebrow: 'Risk queue',
    title: 'Open incidents',
    description:
      'Prioritize critical risks, acknowledge them, and verify closure with a reliable scan.',
  },
  scans: {
    eyebrow: 'Scan history',
    title: 'Engine activity',
    description:
      'Review the status, duration, and evidence of native TLS and testssl.sh runs.',
  },
  checks: {
    eyebrow: 'Check catalog',
    title: 'Alert templates',
    description:
      'Inspect versionable checks that turn probe observations into incidents.',
  },
  settings: {
    eyebrow: 'Workspace',
    title: 'Engine and security settings',
    description: 'Manage access, language, defaults, and scanner capabilities.',
  },
};

function formatDate(
  value: string | null,
  includeTime = true,
  locale: Locale = 'tr',
) {
  if (!value) return '—';
  return new Intl.DateTimeFormat(locale === 'en' ? 'en-GB' : 'tr-TR', {
    day: '2-digit',
    month: 'short',
    ...(includeTime ? { hour: '2-digit', minute: '2-digit' } : {}),
  }).format(new Date(value));
}

function relativeTime(value: string | null, locale: Locale = 'tr') {
  if (!value) return say(locale, 'Henüz yok', 'Not yet');
  const seconds = Math.round((Date.parse(value) - Date.now()) / 1000);
  const formatter = new Intl.RelativeTimeFormat(locale, { numeric: 'auto' });
  if (Math.abs(seconds) < 60) return formatter.format(seconds, 'second');
  const minutes = Math.round(seconds / 60);
  if (Math.abs(minutes) < 60) return formatter.format(minutes, 'minute');
  const hours = Math.round(minutes / 60);
  if (Math.abs(hours) < 24) return formatter.format(hours, 'hour');
  return formatter.format(Math.round(hours / 24), 'day');
}

function expiryLabel(value: string | null, locale: Locale = 'tr') {
  if (!value) return '—';
  const days = Math.ceil((Date.parse(value) - Date.now()) / 86_400_000);
  if (days < 0)
    return say(
      locale,
      `${Math.abs(days)} gün gecikti`,
      `${Math.abs(days)} days overdue`,
    );
  if (days === 0) return say(locale, 'Bugün', 'Today');
  return say(locale, `${days} gün`, `${days} days`);
}

function durationLabel(milliseconds: number | null, locale: Locale = 'tr') {
  if (milliseconds == null) return '—';
  if (milliseconds < 1_000) return `${milliseconds} ms`;
  if (milliseconds < 60_000)
    return `${(milliseconds / 1_000).toFixed(1)} ${say(locale, 'sn', 'sec')}`;
  return `${Math.floor(milliseconds / 60_000)} ${say(locale, 'dk', 'min')} ${Math.round((milliseconds % 60_000) / 1_000)} ${say(locale, 'sn', 'sec')}`;
}

function displayValue(value: unknown) {
  if (value == null || value === '') return '—';
  if (
    typeof value === 'string' ||
    typeof value === 'number' ||
    typeof value === 'boolean'
  ) {
    return String(value);
  }
  return JSON.stringify(value);
}

function SeverityBadge({ severity }: { severity: Severity }) {
  const locale = useLocale();
  const meta = severityMeta[severity];
  const english = {
    critical: 'Critical',
    high: 'High',
    medium: 'Medium',
    low: 'Low',
    info: 'Info',
  }[severity];
  return (
    <Badge variant="outline" className={meta.className}>
      <span className={cn('size-1.5 rounded-full', meta.dot)} />{' '}
      {locale === 'en' ? english : meta.label}
    </Badge>
  );
}

function ScanStatusBadge({ status }: { status: ScanStatus | 'never_scanned' }) {
  const locale = useLocale();
  const meta = scanStatusMeta[status];
  const english = {
    queued: 'Queued',
    running: 'Running',
    succeeded: 'Succeeded',
    partial: 'Partial',
    failed: 'Failed',
    never_scanned: 'Not scanned',
  }[status];
  const active = status === 'queued' || status === 'running';
  return (
    <Badge variant="outline" className={cn('gap-1.5', meta.className)}>
      {active ? (
        <LoaderCircle className="size-3 animate-spin" />
      ) : (
        <span
          className={cn(
            'size-1.5 rounded-full bg-current',
            status === 'succeeded' && 'bg-healthy',
          )}
        />
      )}
      {locale === 'en' ? english : meta.label}
    </Badge>
  );
}

function MetricCard({
  label,
  value,
  note,
  icon: Icon,
  tone,
}: {
  label: string;
  value: string | number;
  note: string;
  icon: typeof Boxes;
  tone?: string;
}) {
  return (
    <Card className="relative overflow-hidden bg-card/82">
      <CardHeader className="flex-row items-center justify-between">
        <span className="text-xs font-medium text-muted-foreground">
          {label}
        </span>
        <Icon className={cn('size-4', tone)} />
      </CardHeader>
      <CardContent>
        <div className="flex items-baseline gap-3">
          <span className={cn('font-mono text-3xl font-semibold', tone)}>
            {value}
          </span>
          <span className="text-[11px] text-muted-foreground">{note}</span>
        </div>
      </CardContent>
    </Card>
  );
}

function EmptyState({
  icon: Icon,
  title,
  description,
  action,
}: {
  icon: typeof Inbox;
  title: string;
  description: string;
  action?: React.ReactNode;
}) {
  return (
    <div className="grid min-h-60 place-items-center px-6 py-10 text-center">
      <div className="max-w-sm">
        <span className="mx-auto grid size-11 place-items-center rounded-xl border border-border bg-muted/60 text-muted-foreground">
          <Icon className="size-5" />
        </span>
        <h3 className="mt-4 font-heading text-sm font-semibold">{title}</h3>
        <p className="mt-1.5 text-xs leading-5 text-muted-foreground">
          {description}
        </p>
        {action ? <div className="mt-4">{action}</div> : null}
      </div>
    </div>
  );
}

function AuthShell({ children }: { children: React.ReactNode }) {
  return (
    <main className="relative grid min-h-screen place-items-center overflow-hidden bg-background px-4 py-10 text-foreground">
      <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(circle_at_20%_20%,color-mix(in_oklab,var(--primary)_13%,transparent),transparent_34%),radial-gradient(circle_at_80%_75%,color-mix(in_oklab,var(--critical)_8%,transparent),transparent_38%)]" />
      <div className="relative w-full max-w-3xl">{children}</div>
    </main>
  );
}

type SetupForm = {
  language: Locale;
  organization: string;
  authEnabled: boolean;
  lanEnabled: boolean;
  lanOrigin: string;
  username: string;
  displayName: string;
  password: string;
  passwordConfirm: string;
  setupCode: string;
  sessionTtlHours: string;
  defaultScanProfile: 'native' | 'deep';
  defaultExpiryWarningDays: string;
  defaultScanIntervalMinutes: string;
};

function SetupWizard({
  bootstrap,
  onComplete,
}: {
  bootstrap: BootstrapState;
  onComplete: () => void;
}) {
  const browserOrigin =
    typeof window === 'undefined' ? '' : window.location.origin;
  const suggestedLanOrigin =
    (browserOrigin && isSecureLanOrigin(browserOrigin)
      ? browserOrigin
      : bootstrap.suggestedOrigins.find(isSecureLanOrigin)) || '';
  const [step, setStep] = useState(0);
  const [form, setForm] = useState<SetupForm>({
    language: bootstrap.language || 'tr',
    organization: '',
    authEnabled: true,
    lanEnabled: false,
    lanOrigin: suggestedLanOrigin,
    username: 'admin',
    displayName: '',
    password: '',
    passwordConfirm: '',
    setupCode: '',
    sessionTtlHours: '12',
    defaultScanProfile: bootstrap.defaultScanProfile,
    defaultExpiryWarningDays: String(bootstrap.defaultExpiryWarningDays),
    defaultScanIntervalMinutes: String(bootstrap.defaultScanIntervalMinutes),
  });
  const [firstAsset, setFirstAsset] = useState({
    hostname: '',
    port: '443',
    label: '',
    owner: '',
    environment: 'production',
    discoverSubdomains: false,
    authorized: false,
  });
  const locale = form.language;
  useEffect(() => {
    document.documentElement.lang = locale;
  }, [locale]);
  const change = <K extends keyof SetupForm>(key: K, value: SetupForm[K]) =>
    setForm((current) => ({ ...current, [key]: value }));
  const mutation = useMutation({
    mutationFn: () => {
      const currentOrigin =
        typeof window === 'undefined' ? '' : window.location.origin;
      const allowedOrigins = [
        'http://localhost:3000',
        'http://127.0.0.1:3000',
        currentOrigin,
        form.lanEnabled ? form.lanOrigin : '',
      ].filter(Boolean);
      return api('/api/setup', {
        method: 'POST',
        body: JSON.stringify({
          ...form,
          authEnabled: form.lanEnabled ? true : form.authEnabled,
          allowedOrigins,
          sessionTtlHours: Number(form.sessionTtlHours),
          defaultExpiryWarningDays: Number(form.defaultExpiryWarningDays),
          defaultScanIntervalMinutes: Number(form.defaultScanIntervalMinutes),
        }),
      });
    },
    onSuccess: () => setStep(3),
  });
  const assetMutation = useMutation({
    mutationFn: () =>
      api('/api/assets', {
        method: 'POST',
        body: JSON.stringify({
          ...firstAsset,
          port: Number(firstAsset.port),
          scanProfile: form.defaultScanProfile,
          expiryWarningDays: Number(form.defaultExpiryWarningDays),
          scanIntervalMinutes: Number(form.defaultScanIntervalMinutes),
          scanNow: true,
        }),
      }),
    onSuccess: onComplete,
  });
  const steps = [
    say(locale, 'Çalışma alanı', 'Workspace'),
    say(locale, 'Erişim', 'Access'),
    say(locale, 'Yönetici ve varsayılanlar', 'Admin and defaults'),
    say(locale, 'İlk varlık', 'First asset'),
  ];
  const canContinue =
    (step === 0 && form.organization.trim().length > 0) ||
    (step === 1 && (!form.lanEnabled || isSecureLanOrigin(form.lanOrigin))) ||
    (step === 2 &&
      form.username.length >= 3 &&
      form.password.length >= 12 &&
      form.password === form.passwordConfirm &&
      (!bootstrap.setupCodeRequired || form.setupCode.length >= 12));

  return (
    <AuthShell>
      <Card className="overflow-hidden bg-card/95 shadow-2xl shadow-black/10">
        <div className="grid md:grid-cols-[220px_minmax(0,1fr)]">
          <div className="bg-incident p-6 text-white">
            <span className="grid size-11 place-items-center rounded-xl bg-primary text-primary-foreground">
              <Fingerprint className="size-6" />
            </span>
            <h1 className="mt-5 font-heading text-xl font-semibold">
              HostCanvas
            </h1>
            <p className="mt-2 text-xs leading-5 text-white/55">
              {say(
                locale,
                'Yerel domain envanterinizi ve güvenlik kontrollerini başlatın.',
                'Start your local domain inventory and security checks.',
              )}
            </p>
            <ol className="mt-8 space-y-4">
              {steps.map((label, index) => (
                <li key={label} className="flex items-center gap-3 text-xs">
                  <span
                    className={cn(
                      'grid size-7 place-items-center rounded-full border font-mono',
                      index <= step
                        ? 'border-primary bg-primary text-primary-foreground'
                        : 'border-white/15 text-white/40',
                    )}
                  >
                    {index < step ? <Check className="size-3.5" /> : index + 1}
                  </span>
                  <span
                    className={index <= step ? 'text-white' : 'text-white/40'}
                  >
                    {label}
                  </span>
                </li>
              ))}
            </ol>
          </div>

          <div className="p-5 sm:p-7">
            <div className="flex items-start justify-between gap-4">
              <div>
                <p className="font-mono text-[10px] font-semibold uppercase tracking-[0.16em] text-primary">
                  {say(locale, 'İlk kurulum', 'First-time setup')}
                </p>
                <h2 className="mt-2 font-heading text-xl font-semibold">
                  {steps[step]}
                </h2>
              </div>
              <div className="flex rounded-lg border border-border p-1">
                {(['tr', 'en'] as Locale[]).map((language) => (
                  <button
                    type="button"
                    key={language}
                    onClick={() => change('language', language)}
                    className={cn(
                      'rounded-md px-2.5 py-1 text-[10px] font-semibold uppercase',
                      form.language === language
                        ? 'bg-primary text-primary-foreground'
                        : 'text-muted-foreground',
                    )}
                  >
                    {language}
                  </button>
                ))}
              </div>
            </div>

            {step === 0 ? (
              <div className="mt-7 space-y-5">
                <div className="space-y-2">
                  <Label htmlFor="setup-organization">
                    {say(locale, 'Ekip veya kurum adı', 'Team or organization')}
                  </Label>
                  <div className="relative">
                    <Building2 className="absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" />
                    <Input
                      id="setup-organization"
                      value={form.organization}
                      onChange={(event) =>
                        change('organization', event.target.value)
                      }
                      placeholder={say(
                        locale,
                        'Örn. Acme SOC',
                        'e.g. Acme SOC',
                      )}
                      className="pl-9"
                    />
                  </div>
                </div>
                <Alert className="border-primary/20 bg-primary/5">
                  <Languages />
                  <AlertTitle>
                    {say(
                      locale,
                      'Dil daha sonra değiştirilebilir',
                      'Language can be changed later',
                    )}
                  </AlertTitle>
                  <AlertDescription>
                    {say(
                      locale,
                      'Seçiminiz bu cihazdaki çalışma alanına kaydedilir.',
                      'Your choice is saved for this workspace.',
                    )}
                  </AlertDescription>
                </Alert>
              </div>
            ) : null}

            {step === 1 ? (
              <div className="mt-7 space-y-4">
                <div className="flex items-start justify-between gap-4 rounded-xl border border-border p-4">
                  <div>
                    <p className="text-sm font-medium">
                      {say(locale, 'Giriş koruması', 'Sign-in protection')}
                    </p>
                    <p className="mt-1 text-xs leading-5 text-muted-foreground">
                      {say(
                        locale,
                        'Panel açılırken yönetici parolası ister.',
                        'Require the admin password when opening the panel.',
                      )}
                    </p>
                  </div>
                  <Switch
                    aria-label={say(
                      locale,
                      'Giriş koruması',
                      'Sign-in protection',
                    )}
                    checked={form.authEnabled || form.lanEnabled}
                    onCheckedChange={(checked) =>
                      change('authEnabled', checked)
                    }
                    disabled={form.lanEnabled}
                  />
                </div>
                <div className="flex items-start justify-between gap-4 rounded-xl border border-border p-4">
                  <div>
                    <div className="flex items-center gap-2">
                      <Wifi className="size-4 text-primary" />
                      <p className="text-sm font-medium">
                        {say(locale, 'LAN erişimi', 'LAN access')}
                      </p>
                    </div>
                    <p className="mt-1 text-xs leading-5 text-muted-foreground">
                      {say(
                        locale,
                        'Ekip üyeleri HTTPS üzerinden, kimlik doğrulayarak erişir.',
                        'Teammates connect over HTTPS and must sign in.',
                      )}
                    </p>
                  </div>
                  <Switch
                    aria-label={say(locale, 'LAN erişimi', 'LAN access')}
                    checked={form.lanEnabled}
                    onCheckedChange={(checked) =>
                      setForm((current) => ({
                        ...current,
                        lanEnabled: checked,
                        authEnabled: checked ? true : current.authEnabled,
                      }))
                    }
                  />
                </div>
                {form.lanEnabled ? (
                  <div className="space-y-2">
                    <Label htmlFor="setup-lan-origin">
                      {say(locale, 'LAN panel adresi', 'LAN panel address')}
                    </Label>
                    <Input
                      id="setup-lan-origin"
                      value={form.lanOrigin}
                      onChange={(event) =>
                        change('lanOrigin', event.target.value)
                      }
                      placeholder="https://192.168.1.20:3443"
                      className="font-mono text-xs"
                      list="setup-origin-suggestions"
                    />
                    <datalist id="setup-origin-suggestions">
                      {bootstrap.suggestedOrigins.map((origin) => (
                        <option key={origin} value={origin}>
                          {origin}
                        </option>
                      ))}
                    </datalist>
                    <p className="text-[11px] leading-5 text-muted-foreground">
                      {say(
                        locale,
                        'HTTPS adresi gereklidir; örneğin https://192.168.1.20:3443. Caddy adresi ve sertifikası bu adresle eşleşmelidir.',
                        'An HTTPS address is required, such as https://192.168.1.20:3443. The Caddy address and certificate must match it.',
                      )}
                    </p>
                  </div>
                ) : null}
              </div>
            ) : null}

            {step === 2 ? (
              <div className="mt-7 space-y-4">
                <div className="grid gap-4 sm:grid-cols-2">
                  <div className="space-y-2">
                    <Label htmlFor="setup-username">
                      {say(locale, 'Yönetici kullanıcı adı', 'Admin username')}
                    </Label>
                    <Input
                      id="setup-username"
                      value={form.username}
                      onChange={(event) =>
                        change('username', event.target.value)
                      }
                      autoComplete="username"
                    />
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="setup-name">
                      {say(locale, 'Görünen ad', 'Display name')}
                    </Label>
                    <Input
                      id="setup-name"
                      value={form.displayName}
                      onChange={(event) =>
                        change('displayName', event.target.value)
                      }
                      placeholder={say(
                        locale,
                        'SOC Yöneticisi',
                        'SOC Administrator',
                      )}
                    />
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="setup-password">
                      {say(locale, 'Parola', 'Password')}
                    </Label>
                    <Input
                      id="setup-password"
                      type="password"
                      value={form.password}
                      onChange={(event) =>
                        change('password', event.target.value)
                      }
                      autoComplete="new-password"
                    />
                    <p className="text-[10px] text-muted-foreground">
                      {say(
                        locale,
                        'En az 12 karakter',
                        'At least 12 characters',
                      )}
                    </p>
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="setup-password-confirm">
                      {say(locale, 'Parola tekrarı', 'Confirm password')}
                    </Label>
                    <Input
                      id="setup-password-confirm"
                      type="password"
                      value={form.passwordConfirm}
                      onChange={(event) =>
                        change('passwordConfirm', event.target.value)
                      }
                      autoComplete="new-password"
                    />
                  </div>
                </div>
                {bootstrap.setupCodeRequired ? (
                  <div className="space-y-2 rounded-lg border border-warning/25 bg-warning/5 p-3">
                    <Label htmlFor="setup-code">
                      {say(locale, 'Sunucu kurulum kodu', 'Server setup code')}
                    </Label>
                    <Input
                      id="setup-code"
                      value={form.setupCode}
                      onChange={(event) =>
                        change(
                          'setupCode',
                          event.target.value.trim().toUpperCase(),
                        )
                      }
                      className="font-mono uppercase"
                      placeholder="A1B2C3D4E5F6"
                    />
                    <p className="text-[10px] text-muted-foreground">
                      {say(
                        locale,
                        'Kod sunucu konsolunda gösterilir ve 15 dakika geçerlidir. Süresi dolarsa sayfayı yenileyip konsoldaki yeni kodu kullanın.',
                        'The server console shows a code valid for 15 minutes. If it expires, reload this page and use the new code in the console.',
                      )}
                    </p>
                  </div>
                ) : null}
                <div className="grid gap-4 sm:grid-cols-3">
                  <div className="space-y-2">
                    <Label htmlFor="setup-default-profile">
                      {say(locale, 'Varsayılan profil', 'Default profile')}
                    </Label>
                    <NativeSelect
                      id="setup-default-profile"
                      value={form.defaultScanProfile}
                      onChange={(event) =>
                        change(
                          'defaultScanProfile',
                          event.target.value as 'native' | 'deep',
                        )
                      }
                    >
                      <NativeSelectOption value="native">
                        Native
                      </NativeSelectOption>
                      <NativeSelectOption value="deep">
                        testssl.sh
                      </NativeSelectOption>
                    </NativeSelect>
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="setup-expiry-threshold">
                      {say(locale, 'Bitiş eşiği', 'Expiry threshold')}
                    </Label>
                    <Input
                      id="setup-expiry-threshold"
                      type="number"
                      min="1"
                      max="365"
                      value={form.defaultExpiryWarningDays}
                      onChange={(event) =>
                        change('defaultExpiryWarningDays', event.target.value)
                      }
                    />
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="setup-scan-interval">
                      {say(locale, 'Tarama aralığı', 'Scan interval')}
                    </Label>
                    <NativeSelect
                      id="setup-scan-interval"
                      value={form.defaultScanIntervalMinutes}
                      onChange={(event) =>
                        change('defaultScanIntervalMinutes', event.target.value)
                      }
                    >
                      <NativeSelectOption value="360">6h</NativeSelectOption>
                      <NativeSelectOption value="720">12h</NativeSelectOption>
                      <NativeSelectOption value="1440">24h</NativeSelectOption>
                    </NativeSelect>
                  </div>
                </div>
              </div>
            ) : null}

            {step === 3 ? (
              <div className="mt-7 space-y-5">
                <Alert className="border-primary/20 bg-primary/5">
                  <ScanLine />
                  <AlertTitle>
                    {say(locale, 'Çalışma alanı hazır', 'Workspace is ready')}
                  </AlertTitle>
                  <AlertDescription>
                    {say(
                      locale,
                      'İlk domain varlığınızı şimdi ekleyip ilk taramayı başlatabilir veya bu adımı atlayabilirsiniz.',
                      'Add your first domain asset and start its initial scan now, or skip this step.',
                    )}
                  </AlertDescription>
                </Alert>
                <div className="grid gap-4 sm:grid-cols-[minmax(0,1fr)_100px]">
                  <div className="space-y-2">
                    <Label htmlFor="setup-asset-host">Hostname</Label>
                    <Input
                      id="setup-asset-host"
                      value={firstAsset.hostname}
                      onChange={(event) =>
                        setFirstAsset((current) => ({
                          ...current,
                          hostname: event.target.value,
                        }))
                      }
                      placeholder="example.com"
                      className="font-mono"
                    />
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="setup-asset-port">Port</Label>
                    <Input
                      id="setup-asset-port"
                      type="number"
                      min="1"
                      max="65535"
                      value={firstAsset.port}
                      onChange={(event) =>
                        setFirstAsset((current) => ({
                          ...current,
                          port: event.target.value,
                        }))
                      }
                      className="font-mono"
                    />
                  </div>
                </div>
                <div className="grid gap-4 sm:grid-cols-3">
                  <div className="space-y-2">
                    <Label htmlFor="setup-asset-label">
                      {say(locale, 'Görünen ad', 'Display name')}
                    </Label>
                    <Input
                      id="setup-asset-label"
                      value={firstAsset.label}
                      onChange={(event) =>
                        setFirstAsset((current) => ({
                          ...current,
                          label: event.target.value,
                        }))
                      }
                    />
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="setup-asset-owner">
                      {say(locale, 'Sorumlu ekip', 'Owner')}
                    </Label>
                    <Input
                      id="setup-asset-owner"
                      value={firstAsset.owner}
                      onChange={(event) =>
                        setFirstAsset((current) => ({
                          ...current,
                          owner: event.target.value,
                        }))
                      }
                    />
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="setup-asset-environment">
                      {say(locale, 'Ortam', 'Environment')}
                    </Label>
                    <NativeSelect
                      id="setup-asset-environment"
                      value={firstAsset.environment}
                      onChange={(event) =>
                        setFirstAsset((current) => ({
                          ...current,
                          environment: event.target.value,
                        }))
                      }
                    >
                      <NativeSelectOption value="production">
                        {say(locale, 'Üretim', 'Production')}
                      </NativeSelectOption>
                      <NativeSelectOption value="staging">
                        Staging
                      </NativeSelectOption>
                      <NativeSelectOption value="development">
                        {say(locale, 'Geliştirme', 'Development')}
                      </NativeSelectOption>
                      <NativeSelectOption value="other">
                        {say(locale, 'Diğer', 'Other')}
                      </NativeSelectOption>
                    </NativeSelect>
                  </div>
                </div>
                <div className="flex gap-3 rounded-lg border border-border bg-muted/35 p-3 text-xs leading-5">
                  <Checkbox
                    id="setup-asset-discovery"
                    checked={firstAsset.discoverSubdomains}
                    onCheckedChange={(checked) =>
                      setFirstAsset((current) => ({
                        ...current,
                        discoverSubdomains: checked === true,
                      }))
                    }
                    className="mt-0.5"
                  />
                  <Label
                    htmlFor="setup-asset-discovery"
                    className="block cursor-pointer font-normal"
                  >
                    <span className="block font-medium">
                      {say(
                        locale,
                        'crt.name ile subdomain keşfi yap',
                        'Discover subdomains with crt.name',
                      )}
                    </span>
                    <span className="mt-1 block text-muted-foreground">
                      {say(
                        locale,
                        'Kök domain ücretsiz dış servise gönderilir; bulunan hostname’ler tarama kuyruğunu doldurmadan asset olarak eklenir.',
                        'The apex domain is sent to the free external service; discovered hostnames are added as assets without flooding the scan queue.',
                      )}
                    </span>
                  </Label>
                </div>
                <label className="flex cursor-pointer gap-3 rounded-lg border border-border bg-muted/35 p-3 text-xs leading-5">
                  <Checkbox
                    checked={firstAsset.authorized}
                    onCheckedChange={(checked) =>
                      setFirstAsset((current) => ({
                        ...current,
                        authorized: checked === true,
                      }))
                    }
                    className="mt-0.5"
                  />
                  <span>
                    {say(
                      locale,
                      'Bu sistemi tarama yetkim olduğunu doğruluyorum.',
                      'I confirm that I am authorized to scan this system.',
                    )}
                  </span>
                </label>
                {assetMutation.error ? (
                  <p className="text-xs text-critical">
                    {assetMutation.error.message}
                  </p>
                ) : null}
              </div>
            ) : null}

            {mutation.error ? (
              <Alert variant="destructive" className="mt-5">
                <AlertCircle />
                <AlertTitle>
                  {say(
                    locale,
                    'Kurulum tamamlanamadı',
                    'Setup could not be completed',
                  )}
                </AlertTitle>
                <AlertDescription>{mutation.error.message}</AlertDescription>
              </Alert>
            ) : null}

            <div className="mt-7 flex items-center justify-between border-t border-border pt-5">
              {step < 3 ? (
                <Button
                  variant="ghost"
                  onClick={() => setStep((current) => Math.max(0, current - 1))}
                  disabled={step === 0 || mutation.isPending}
                >
                  <ChevronLeft data-icon="inline-start" />{' '}
                  {say(locale, 'Geri', 'Back')}
                </Button>
              ) : (
                <span />
              )}
              {step < 2 ? (
                <Button
                  onClick={() => setStep((current) => current + 1)}
                  disabled={!canContinue}
                >
                  {say(locale, 'Devam', 'Continue')}{' '}
                  <ChevronRight data-icon="inline-end" />
                </Button>
              ) : step === 2 ? (
                <Button
                  onClick={() => mutation.mutate()}
                  disabled={!canContinue || mutation.isPending}
                >
                  {mutation.isPending ? (
                    <LoaderCircle
                      className="animate-spin"
                      data-icon="inline-start"
                    />
                  ) : (
                    <ShieldCheck data-icon="inline-start" />
                  )}
                  {say(locale, 'Çalışma alanını oluştur', 'Create workspace')}
                </Button>
              ) : (
                <div className="flex gap-2">
                  <Button
                    variant="ghost"
                    onClick={onComplete}
                    disabled={assetMutation.isPending}
                  >
                    {say(locale, 'Şimdilik atla', 'Skip for now')}
                  </Button>
                  <Button
                    onClick={() => assetMutation.mutate()}
                    disabled={
                      !firstAsset.hostname ||
                      !firstAsset.authorized ||
                      assetMutation.isPending
                    }
                  >
                    {assetMutation.isPending ? (
                      <LoaderCircle
                        className="animate-spin"
                        data-icon="inline-start"
                      />
                    ) : (
                      <Plus data-icon="inline-start" />
                    )}
                    {say(locale, 'Varlığı ekle', 'Add asset')}
                  </Button>
                </div>
              )}
            </div>
          </div>
        </div>
      </Card>
    </AuthShell>
  );
}

function LoginScreen({
  bootstrap,
  onAuthenticated,
}: {
  bootstrap: BootstrapState;
  onAuthenticated: () => void;
}) {
  const queryClient = useQueryClient();
  const locale = bootstrap.language;
  const [username, setUsername] = useState('admin');
  const [password, setPassword] = useState('');
  const mutation = useMutation({
    mutationFn: () =>
      api('/api/session', {
        method: 'POST',
        body: JSON.stringify({ username, password }),
      }),
    onSuccess: () => {
      clearWorkspaceCache(queryClient);
      onAuthenticated();
    },
  });
  return (
    <AuthShell>
      <Card className="mx-auto max-w-md bg-card/95 shadow-2xl shadow-black/10">
        <CardHeader className="border-b border-border pb-5">
          <span className="grid size-11 place-items-center rounded-xl bg-primary text-primary-foreground">
            <LockKeyhole className="size-5" />
          </span>
          <CardTitle className="mt-4 text-xl">
            {say(locale, 'HostCanvas’a giriş', 'Sign in to HostCanvas')}
          </CardTitle>
          <p className="mt-1 text-xs leading-5 text-muted-foreground">
            {bootstrap.organization || 'HostCanvas'} ·{' '}
            {say(locale, 'Korumalı çalışma alanı', 'Protected workspace')}
          </p>
        </CardHeader>
        <CardContent className="pt-5">
          <form
            className="space-y-4"
            onSubmit={(event) => {
              event.preventDefault();
              mutation.mutate();
            }}
          >
            <div className="space-y-2">
              <Label htmlFor="login-username">
                {say(locale, 'Kullanıcı adı', 'Username')}
              </Label>
              <Input
                id="login-username"
                value={username}
                onChange={(event) => setUsername(event.target.value)}
                autoComplete="username"
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="login-password">
                {say(locale, 'Parola', 'Password')}
              </Label>
              <Input
                id="login-password"
                type="password"
                value={password}
                onChange={(event) => setPassword(event.target.value)}
                autoComplete="current-password"
              />
            </div>
            {mutation.error ? (
              <p className="text-xs text-critical">{mutation.error.message}</p>
            ) : null}
            <Button
              className="w-full"
              type="submit"
              disabled={!username || !password || mutation.isPending}
            >
              {mutation.isPending ? (
                <LoaderCircle
                  className="animate-spin"
                  data-icon="inline-start"
                />
              ) : (
                <LogIn data-icon="inline-start" />
              )}
              {say(locale, 'Giriş yap', 'Sign in')}
            </Button>
          </form>
        </CardContent>
      </Card>
    </AuthShell>
  );
}

function LanBlockedScreen({ bootstrap }: { bootstrap: BootstrapState }) {
  const locale = bootstrap.language;
  return (
    <AuthShell>
      <Card className="mx-auto max-w-lg bg-card/95">
        <CardContent className="py-10 text-center">
          <span className="mx-auto grid size-12 place-items-center rounded-xl bg-warning/10 text-warning">
            <WifiOff className="size-6" />
          </span>
          <h1 className="mt-5 font-heading text-xl font-semibold">
            {say(
              locale,
              'Bu LAN adresine izin verilmemiş',
              'This LAN address is not allowed',
            )}
          </h1>
          <p className="mx-auto mt-2 max-w-sm text-sm leading-6 text-muted-foreground">
            {say(
              locale,
              'HostCanvas’ı sunucunun localhost adresinden açın; Ayarlar bölümünde LAN erişimini etkinleştirip bu panel adresini ekleyin.',
              'Open HostCanvas from localhost on the server, then enable LAN access and add this panel address in Settings.',
            )}
          </p>
          <p className="mt-5 font-mono text-[11px] text-muted-foreground">
            {say(
              locale,
              'İzin verilecek adresi localhost oturumunuzdan kopyalayın.',
              'Copy the origin to allow from your localhost session.',
            )}
          </p>
        </CardContent>
      </Card>
    </AuthShell>
  );
}

type AddAssetForm = {
  hostname: string;
  port: string;
  label: string;
  owner: string;
  environment: string;
  scanProfile: 'native' | 'deep';
  expiryWarningDays: string;
  scanIntervalMinutes: string;
  allowPrivate: boolean;
  discoverSubdomains: boolean;
  authorized: boolean;
};

type DiscoveryResult = {
  requested: boolean;
  provider: 'crt.name';
  status: 'skipped' | 'disabled' | 'completed' | 'failed';
  totalFound: number;
  createdCount: number;
  existingCount: number;
  truncated: boolean;
  error: string | null;
};

type AssetDefaults = Pick<
  BootstrapState,
  | 'defaultScanProfile'
  | 'defaultExpiryWarningDays'
  | 'defaultScanIntervalMinutes'
>;

function initialAssetForm(defaults: AssetDefaults): AddAssetForm {
  return {
    hostname: '',
    port: '443',
    label: '',
    owner: '',
    environment: 'production',
    scanProfile: defaults.defaultScanProfile,
    expiryWarningDays: String(defaults.defaultExpiryWarningDays),
    scanIntervalMinutes: String(defaults.defaultScanIntervalMinutes),
    allowPrivate: false,
    discoverSubdomains: false,
    authorized: false,
  };
}

function AddAssetDialog({
  open,
  onOpenChange,
  health,
  defaults,
  onCreated,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  health?: Health;
  defaults: AssetDefaults;
  onCreated: (message: string) => void;
}) {
  const queryClient = useQueryClient();
  const locale = useLocale();
  const [form, setForm] = useState<AddAssetForm>(() =>
    initialAssetForm(defaults),
  );
  const createMutation = useMutation({
    mutationFn: () =>
      api<{ asset: Asset; scan: Scan | null; discovery: DiscoveryResult }>(
        '/api/assets',
        {
          method: 'POST',
          body: JSON.stringify({
            ...form,
            port: Number(form.port),
            expiryWarningDays: Number(form.expiryWarningDays),
            scanIntervalMinutes: Number(form.scanIntervalMinutes),
            authorized: form.authorized,
            scanNow: true,
          }),
        },
      ),
    onSuccess: async ({ asset, discovery }) => {
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: ['dashboard'] }),
        queryClient.invalidateQueries({ queryKey: ['scans'] }),
      ]);
      setForm(initialAssetForm(defaults));
      onOpenChange(false);
      const discoveryMessage =
        discovery.status === 'completed'
          ? say(
              locale,
              ` ${discovery.createdCount} yeni subdomain asset olarak eklendi${discovery.truncated ? `; sonuç ${health?.subdomainDiscovery.limit || 200} kayıtla sınırlandı` : ''}.`,
              ` ${discovery.createdCount} new subdomains were added as assets${discovery.truncated ? `; results were limited to ${health?.subdomainDiscovery.limit || 200} records` : ''}.`,
            )
          : discovery.status === 'failed' || discovery.status === 'disabled'
            ? say(
                locale,
                ` Subdomain keşfi tamamlanamadı: ${discovery.error}`,
                ` Subdomain discovery could not complete: ${discovery.error}`,
              )
            : '';
      onCreated(
        `${say(
          locale,
          `${asset.hostname}:${asset.port} envantere eklendi ve tarama kuyruğuna alındı.`,
          `${asset.hostname}:${asset.port} was added to inventory and queued for scanning.`,
        )}${discoveryMessage}`,
      );
    },
  });

  const change = <K extends keyof AddAssetForm>(
    key: K,
    value: AddAssetForm[K],
  ) => setForm((current) => ({ ...current, [key]: value }));

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-h-[92vh] overflow-y-auto sm:max-w-xl">
        <DialogHeader>
          <DialogTitle>
            {say(locale, 'Envantere varlık ekle', 'Add asset to inventory')}
          </DialogTitle>
          <DialogDescription>
            {say(
              locale,
              'Yalnızca tarama yetkiniz olan hostname’leri ekleyin. Protokol veya URL yolu girmeyin.',
              'Add only hostnames you are authorized to scan. Do not enter a protocol or URL path.',
            )}
          </DialogDescription>
        </DialogHeader>
        <form
          onSubmit={(event) => {
            event.preventDefault();
            createMutation.mutate();
          }}
          className="space-y-5"
        >
          {createMutation.error ? (
            <Alert variant="destructive">
              <AlertCircle />
              <AlertTitle>
                {say(locale, 'Varlık eklenemedi', 'Could not add asset')}
              </AlertTitle>
              <AlertDescription>
                {createMutation.error.message}
              </AlertDescription>
            </Alert>
          ) : null}

          <div className="grid gap-4 sm:grid-cols-[minmax(0,1fr)_110px]">
            <div className="space-y-2">
              <Label htmlFor="asset-hostname">Hostname</Label>
              <Input
                id="asset-hostname"
                value={form.hostname}
                onChange={(event) => change('hostname', event.target.value)}
                placeholder="example.com"
                className="h-10 font-mono"
                autoComplete="off"
                required
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="asset-port">Port</Label>
              <Input
                id="asset-port"
                type="number"
                min="1"
                max="65535"
                value={form.port}
                onChange={(event) => change('port', event.target.value)}
                className="h-10 font-mono"
                required
              />
            </div>
          </div>

          <div className="grid gap-4 sm:grid-cols-2">
            <div className="space-y-2">
              <Label htmlFor="asset-label">
                {say(locale, 'Görünen ad', 'Display name')}
              </Label>
              <Input
                id="asset-label"
                value={form.label}
                onChange={(event) => change('label', event.target.value)}
                placeholder={say(locale, 'Ödeme API', 'Payments API')}
                className="h-10"
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="asset-owner">
                {say(locale, 'Sorumlu ekip', 'Owner team')}
              </Label>
              <Input
                id="asset-owner"
                value={form.owner}
                onChange={(event) => change('owner', event.target.value)}
                placeholder="Platform"
                className="h-10"
              />
            </div>
          </div>

          <div className="grid gap-4 sm:grid-cols-2">
            <div className="space-y-2">
              <Label htmlFor="asset-environment">
                {say(locale, 'Ortam', 'Environment')}
              </Label>
              <NativeSelect
                id="asset-environment"
                value={form.environment}
                onChange={(event) => change('environment', event.target.value)}
                className="w-full"
              >
                <NativeSelectOption value="production">
                  {say(locale, 'Üretim', 'Production')}
                </NativeSelectOption>
                <NativeSelectOption value="staging">Staging</NativeSelectOption>
                <NativeSelectOption value="development">
                  {say(locale, 'Geliştirme', 'Development')}
                </NativeSelectOption>
                <NativeSelectOption value="other">
                  {say(locale, 'Diğer', 'Other')}
                </NativeSelectOption>
              </NativeSelect>
            </div>
            <div className="space-y-2">
              <Label htmlFor="asset-profile">
                {say(locale, 'Tarama profili', 'Scan profile')}
              </Label>
              <NativeSelect
                id="asset-profile"
                value={form.scanProfile}
                onChange={(event) =>
                  change('scanProfile', event.target.value as 'native' | 'deep')
                }
                className="w-full"
              >
                <NativeSelectOption value="native">
                  Native · {say(locale, 'hızlı', 'quick')}
                </NativeSelectOption>
                <NativeSelectOption
                  value="deep"
                  disabled={!health?.engines.testssl.available}
                >
                  testssl.sh · {say(locale, 'derin', 'deep')}
                </NativeSelectOption>
              </NativeSelect>
            </div>
          </div>

          <div className="grid gap-4 sm:grid-cols-2">
            <div className="space-y-2">
              <Label htmlFor="asset-expiry">
                {say(locale, 'Bitiş uyarısı (gün)', 'Expiry warning (days)')}
              </Label>
              <Input
                id="asset-expiry"
                type="number"
                min="1"
                max="365"
                value={form.expiryWarningDays}
                onChange={(event) =>
                  change('expiryWarningDays', event.target.value)
                }
                className="h-10 font-mono"
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="asset-interval">
                {say(locale, 'Tarama aralığı', 'Scan interval')}
              </Label>
              <NativeSelect
                id="asset-interval"
                value={form.scanIntervalMinutes}
                onChange={(event) =>
                  change('scanIntervalMinutes', event.target.value)
                }
                className="w-full"
              >
                <NativeSelectOption value="60">
                  {say(locale, 'Her saat', 'Hourly')}
                </NativeSelectOption>
                <NativeSelectOption value="360">
                  {say(locale, '6 saatte bir', 'Every 6 hours')}
                </NativeSelectOption>
                <NativeSelectOption value="720">
                  {say(locale, '12 saatte bir', 'Every 12 hours')}
                </NativeSelectOption>
                <NativeSelectOption value="1440">
                  {say(locale, 'Günde bir', 'Daily')}
                </NativeSelectOption>
                <NativeSelectOption value="10080">
                  {say(locale, 'Haftada bir', 'Weekly')}
                </NativeSelectOption>
              </NativeSelect>
            </div>
          </div>

          <div className="flex gap-3 rounded-lg border border-border bg-muted/35 p-3">
            <Checkbox
              id="asset-discovery"
              checked={form.discoverSubdomains}
              onCheckedChange={(checked) =>
                change('discoverSubdomains', checked === true)
              }
              disabled={health?.subdomainDiscovery.enabled === false}
              className="mt-0.5"
            />
            <Label
              htmlFor="asset-discovery"
              className="block cursor-pointer font-normal"
            >
              <span className="flex items-center gap-2 text-sm font-medium">
                <Network className="size-4 text-primary" />
                {say(
                  locale,
                  'crt.name ile subdomain keşfi',
                  'Subdomain discovery with crt.name',
                )}
              </span>
              <span className="mt-1 block text-xs leading-5 text-muted-foreground">
                {say(
                  locale,
                  `Kök domain crt.name servisine gönderilir. En fazla ${health?.subdomainDiscovery.limit || 200} doğrulanmış hostname asset olarak eklenir; taramalar kademeli planlanır.`,
                  `The apex domain is sent to crt.name. Up to ${health?.subdomainDiscovery.limit || 200} validated hostnames are added as assets with staggered scans.`,
                )}
              </span>
            </Label>
          </div>

          {health?.privateTargetsAllowed ? (
            <div className="flex gap-3 rounded-lg border border-border bg-muted/35 p-3">
              <Checkbox
                id="asset-private"
                checked={form.allowPrivate}
                onCheckedChange={(checked) =>
                  change('allowPrivate', checked === true)
                }
                className="mt-0.5"
              />
              <Label
                htmlFor="asset-private"
                className="block cursor-pointer font-normal"
              >
                <span className="block text-sm font-medium">
                  {say(locale, 'İç ağ hedefi', 'Internal network target')}
                </span>
                <span className="mt-1 block text-xs leading-5 text-muted-foreground">
                  {say(
                    locale,
                    'Private/loopback çözümlemeye bu varlık için izin verir. Yalnızca kontrolünüzdeki ağlarda kullanın.',
                    'Allows private/loopback resolution for this asset. Use only on networks you control.',
                  )}
                </span>
              </Label>
            </div>
          ) : null}

          <div className="flex gap-3 rounded-lg border border-primary/20 bg-primary/5 p-3">
            <Checkbox
              id="asset-authorized"
              checked={form.authorized}
              onCheckedChange={(checked) =>
                change('authorized', checked === true)
              }
              className="mt-0.5"
            />
            <Label
              htmlFor="asset-authorized"
              className="block cursor-pointer font-normal"
            >
              <span className="block text-sm font-medium">
                {say(
                  locale,
                  'Tarama yetkisini onaylıyorum',
                  'I confirm scan authorization',
                )}
              </span>
              <span className="mt-1 block text-xs leading-5 text-muted-foreground">
                {say(
                  locale,
                  'Bu sistemin sahibi olduğumu veya güvenlik taraması için açık iznim bulunduğunu onaylıyorum.',
                  'I confirm that I own this system or have explicit permission to scan it.',
                )}
              </span>
            </Label>
          </div>

          <DialogFooter className="-mx-4 -mb-4">
            <Button
              type="button"
              variant="outline"
              onClick={() => onOpenChange(false)}
            >
              {say(locale, 'Vazgeç', 'Cancel')}
            </Button>
            <Button
              type="submit"
              disabled={
                !form.hostname || !form.authorized || createMutation.isPending
              }
            >
              {createMutation.isPending ? (
                <LoaderCircle
                  className="animate-spin"
                  data-icon="inline-start"
                />
              ) : (
                <Plus data-icon="inline-start" />
              )}
              {say(locale, 'Ekle ve tara', 'Add and scan')}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

function EditAssetDialog({
  asset,
  health,
  onClose,
  onSuccess,
}: {
  asset: Asset | null;
  health?: Health;
  onClose: () => void;
  onSuccess: (message: string) => void;
}) {
  const locale = useLocale();
  const queryClient = useQueryClient();
  const [form, setForm] = useState(() => ({
    label: asset?.label || '',
    owner: asset?.owner || '',
    environment: asset?.environment || 'production',
    tags: asset?.tags.join(', ') || '',
    scanProfile: asset?.scanProfile || 'native',
    expiryWarningDays: String(asset?.expiryWarningDays || 30),
    scanIntervalMinutes: String(asset?.scanIntervalMinutes || 720),
    allowPrivate: asset?.allowPrivate || false,
  }));
  const mutation = useMutation({
    mutationFn: () =>
      api<{ asset: Asset }>(`/api/assets/${asset?.id}`, {
        method: 'PATCH',
        body: JSON.stringify({
          ...form,
          tags: form.tags
            .split(',')
            .map((tag) => tag.trim())
            .filter(Boolean),
          expiryWarningDays: Number(form.expiryWarningDays),
          scanIntervalMinutes: Number(form.scanIntervalMinutes),
        }),
      }),
    onSuccess: async ({ asset: updated }) => {
      await queryClient.invalidateQueries({ queryKey: ['dashboard'] });
      onSuccess(
        say(
          locale,
          `${updated.hostname} ayarları güncellendi.`,
          `${updated.hostname} settings updated.`,
        ),
      );
      onClose();
    },
  });

  return (
    <Dialog open={Boolean(asset)} onOpenChange={(open) => !open && onClose()}>
      <DialogContent className="max-h-[92vh] overflow-y-auto sm:max-w-xl">
        {asset ? (
          <form
            className="space-y-5"
            onSubmit={(event) => {
              event.preventDefault();
              mutation.mutate();
            }}
          >
            <DialogHeader>
              <DialogTitle>
                {say(
                  locale,
                  'Varlık ayarlarını düzenle',
                  'Edit asset settings',
                )}
              </DialogTitle>
              <DialogDescription className="font-mono">
                {asset.hostname}:{asset.port}
              </DialogDescription>
            </DialogHeader>
            {mutation.error ? (
              <Alert variant="destructive">
                <AlertCircle />
                <AlertTitle>
                  {say(
                    locale,
                    'Varlık güncellenemedi',
                    'Could not update asset',
                  )}
                </AlertTitle>
                <AlertDescription>{mutation.error.message}</AlertDescription>
              </Alert>
            ) : null}
            <div className="grid gap-4 sm:grid-cols-2">
              <div className="space-y-2">
                <Label htmlFor="edit-asset-label">
                  {say(locale, 'Görünen ad', 'Display name')}
                </Label>
                <Input
                  id="edit-asset-label"
                  value={form.label}
                  onChange={(event) =>
                    setForm((current) => ({
                      ...current,
                      label: event.target.value,
                    }))
                  }
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="edit-asset-owner">
                  {say(locale, 'Sorumlu ekip', 'Owner team')}
                </Label>
                <Input
                  id="edit-asset-owner"
                  value={form.owner}
                  onChange={(event) =>
                    setForm((current) => ({
                      ...current,
                      owner: event.target.value,
                    }))
                  }
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="edit-asset-environment">
                  {say(locale, 'Ortam', 'Environment')}
                </Label>
                <NativeSelect
                  id="edit-asset-environment"
                  value={form.environment}
                  onChange={(event) =>
                    setForm((current) => ({
                      ...current,
                      environment: event.target.value,
                    }))
                  }
                >
                  <NativeSelectOption value="production">
                    {say(locale, 'Üretim', 'Production')}
                  </NativeSelectOption>
                  <NativeSelectOption value="staging">
                    Staging
                  </NativeSelectOption>
                  <NativeSelectOption value="development">
                    {say(locale, 'Geliştirme', 'Development')}
                  </NativeSelectOption>
                  <NativeSelectOption value="other">
                    {say(locale, 'Diğer', 'Other')}
                  </NativeSelectOption>
                </NativeSelect>
              </div>
              <div className="space-y-2">
                <Label htmlFor="edit-asset-profile">
                  {say(locale, 'Tarama profili', 'Scan profile')}
                </Label>
                <NativeSelect
                  id="edit-asset-profile"
                  value={form.scanProfile}
                  onChange={(event) =>
                    setForm((current) => ({
                      ...current,
                      scanProfile: event.target.value as 'native' | 'deep',
                    }))
                  }
                >
                  <NativeSelectOption value="native">Native</NativeSelectOption>
                  <NativeSelectOption
                    value="deep"
                    disabled={!health?.engines.testssl.available}
                  >
                    testssl.sh
                  </NativeSelectOption>
                </NativeSelect>
              </div>
              <div className="space-y-2">
                <Label htmlFor="edit-asset-expiry">
                  {say(locale, 'Bitiş uyarısı (gün)', 'Expiry warning (days)')}
                </Label>
                <Input
                  id="edit-asset-expiry"
                  type="number"
                  min="1"
                  max="365"
                  value={form.expiryWarningDays}
                  onChange={(event) =>
                    setForm((current) => ({
                      ...current,
                      expiryWarningDays: event.target.value,
                    }))
                  }
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="edit-asset-interval">
                  {say(locale, 'Tarama aralığı', 'Scan interval')}
                </Label>
                <NativeSelect
                  id="edit-asset-interval"
                  value={form.scanIntervalMinutes}
                  onChange={(event) =>
                    setForm((current) => ({
                      ...current,
                      scanIntervalMinutes: event.target.value,
                    }))
                  }
                >
                  <NativeSelectOption value="60">1h</NativeSelectOption>
                  <NativeSelectOption value="360">6h</NativeSelectOption>
                  <NativeSelectOption value="720">12h</NativeSelectOption>
                  <NativeSelectOption value="1440">24h</NativeSelectOption>
                  <NativeSelectOption value="10080">7d</NativeSelectOption>
                </NativeSelect>
              </div>
              <div className="space-y-2 sm:col-span-2">
                <Label htmlFor="edit-asset-tags">
                  {say(locale, 'Etiketler', 'Tags')}
                </Label>
                <Input
                  id="edit-asset-tags"
                  value={form.tags}
                  onChange={(event) =>
                    setForm((current) => ({
                      ...current,
                      tags: event.target.value,
                    }))
                  }
                  placeholder={say(
                    locale,
                    'internet, kritik, ödeme',
                    'internet, critical, payments',
                  )}
                />
              </div>
            </div>
            {health?.privateTargetsAllowed ? (
              <label className="flex cursor-pointer gap-3 rounded-lg border border-border bg-muted/35 p-3 text-xs leading-5">
                <Checkbox
                  checked={form.allowPrivate}
                  onCheckedChange={(checked) =>
                    setForm((current) => ({
                      ...current,
                      allowPrivate: checked === true,
                    }))
                  }
                  className="mt-0.5"
                />
                <span>
                  {say(
                    locale,
                    'Bu varlık için private/loopback hedef çözümlemesine izin ver.',
                    'Allow private/loopback target resolution for this asset.',
                  )}
                </span>
              </label>
            ) : null}
            <DialogFooter className="-mx-4 -mb-4">
              <Button type="button" variant="outline" onClick={onClose}>
                {say(locale, 'Vazgeç', 'Cancel')}
              </Button>
              <Button type="submit" disabled={mutation.isPending}>
                {mutation.isPending ? (
                  <LoaderCircle
                    className="animate-spin"
                    data-icon="inline-start"
                  />
                ) : (
                  <Check data-icon="inline-start" />
                )}
                {say(locale, 'Değişiklikleri kaydet', 'Save changes')}
              </Button>
            </DialogFooter>
          </form>
        ) : null}
      </DialogContent>
    </Dialog>
  );
}

function IncidentDetailDialog({
  incident,
  onClose,
  onUpdated,
}: {
  incident: Incident | null;
  onClose: () => void;
  onUpdated: (message: string) => void;
}) {
  const queryClient = useQueryClient();
  const locale = useLocale();
  const { canOperate } = useAccess();
  const mutation = useMutation({
    mutationFn: (status: Incident['status']) =>
      api<{ incident: Incident }>(`/api/incidents/${incident?.id}`, {
        method: 'PATCH',
        body: JSON.stringify({ status }),
      }),
    onSuccess: async ({ incident: updated }) => {
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: ['dashboard'] }),
        queryClient.invalidateQueries({ queryKey: ['incidents'] }),
      ]);
      onUpdated(
        updated.status === 'acknowledged'
          ? say(locale, 'Incident sahiplenildi.', 'Incident acknowledged.')
          : updated.status === 'resolved'
            ? say(
                locale,
                'Incident manuel olarak kapatıldı.',
                'Incident resolved manually.',
              )
            : say(locale, 'Incident yeniden açıldı.', 'Incident reopened.'),
      );
      onClose();
    },
  });

  return (
    <Dialog
      open={Boolean(incident)}
      onOpenChange={(open) => !open && onClose()}
    >
      <DialogContent className="sm:max-w-xl">
        {incident ? (
          <>
            <DialogHeader>
              <div className="mb-2 flex items-center gap-2">
                <SeverityBadge severity={incident.severity} />
                <Badge variant="outline" className="font-mono text-[10px]">
                  {incident.ruleKey}
                </Badge>
              </div>
              <DialogTitle>{incident.title}</DialogTitle>
              <DialogDescription>{incident.description}</DialogDescription>
            </DialogHeader>
            <div className="grid grid-cols-2 gap-px overflow-hidden rounded-lg border border-border bg-border text-xs sm:grid-cols-4">
              {[
                [
                  say(locale, 'Hedef', 'Target'),
                  `${incident.hostname}:${incident.port}`,
                ],
                [
                  say(locale, 'Sahip', 'Owner'),
                  incident.owner || say(locale, 'Atanmamış', 'Unassigned'),
                ],
                [
                  say(locale, 'İlk görülme', 'First seen'),
                  formatDate(incident.firstSeenAt, true, locale),
                ],
                [
                  say(locale, 'Tekrar', 'Occurrences'),
                  say(
                    locale,
                    `${incident.occurrenceCount} kez`,
                    `${incident.occurrenceCount} times`,
                  ),
                ],
              ].map(([label, value]) => (
                <div key={label} className="bg-card p-3">
                  <p className="text-[10px] uppercase tracking-wider text-muted-foreground">
                    {label}
                  </p>
                  <p className="mt-1.5 break-all font-mono text-[11px]">
                    {value}
                  </p>
                </div>
              ))}
            </div>
            <div>
              <p className="mb-2 text-xs font-medium">
                {say(locale, 'Kanıt', 'Evidence')}
              </p>
              <pre className="max-h-52 overflow-auto rounded-lg bg-incident p-3 font-mono text-[10px] leading-5 text-white/72">
                {JSON.stringify(incident.evidence, null, 2)}
              </pre>
            </div>
            {mutation.error ? (
              <p className="text-xs text-critical">{mutation.error.message}</p>
            ) : null}
            <DialogFooter>
              <Button variant="outline" onClick={onClose}>
                {say(locale, 'Kapat', 'Close')}
              </Button>
              {canOperate &&
              incident.status !== 'acknowledged' &&
              incident.status !== 'resolved' ? (
                <Button
                  variant="secondary"
                  onClick={() => mutation.mutate('acknowledged')}
                  disabled={mutation.isPending}
                >
                  <CircleDot data-icon="inline-start" />{' '}
                  {say(locale, 'Sahiplen', 'Acknowledge')}
                </Button>
              ) : null}
              {canOperate && incident.status !== 'resolved' ? (
                <Button
                  onClick={() => mutation.mutate('resolved')}
                  disabled={mutation.isPending}
                >
                  <Check data-icon="inline-start" />{' '}
                  {say(locale, 'Çözüldü olarak işaretle', 'Mark resolved')}
                </Button>
              ) : canOperate ? (
                <Button
                  onClick={() => mutation.mutate('open')}
                  disabled={mutation.isPending}
                >
                  {say(locale, 'Yeniden aç', 'Reopen')}
                </Button>
              ) : null}
            </DialogFooter>
          </>
        ) : null}
      </DialogContent>
    </Dialog>
  );
}

function ScanDetailDialog({
  scan,
  onClose,
}: {
  scan: Scan | null;
  onClose: () => void;
}) {
  const locale = useLocale();
  const certificate = (
    scan?.observations as {
      tls?: { certificate?: Record<string, unknown> };
    } | null
  )?.tls?.certificate;
  return (
    <Dialog open={Boolean(scan)} onOpenChange={(open) => !open && onClose()}>
      <DialogContent className="max-h-[90vh] overflow-y-auto sm:max-w-2xl">
        {scan ? (
          <>
            <DialogHeader>
              <div className="mb-2 flex items-center gap-2">
                <ScanStatusBadge status={scan.status} />
                <Badge variant="outline" className="uppercase">
                  {scan.profile}
                </Badge>
              </div>
              <DialogTitle className="font-mono">
                {scan.hostname}:{scan.port}
              </DialogTitle>
              <DialogDescription>
                {formatDate(scan.startedAt || scan.createdAt, true, locale)} ·{' '}
                {durationLabel(scan.durationMs, locale)}
              </DialogDescription>
            </DialogHeader>
            {scan.errorMessage ? (
              <Alert variant="destructive">
                <AlertTriangle />
                <AlertTitle>
                  {scan.errorCode || say(locale, 'Tarama hatası', 'Scan error')}
                </AlertTitle>
                <AlertDescription>{scan.errorMessage}</AlertDescription>
              </Alert>
            ) : null}
            {certificate ? (
              <div className="grid gap-px overflow-hidden rounded-lg border border-border bg-border text-xs sm:grid-cols-2">
                {[
                  ['Subject', displayValue(certificate.subject)],
                  ['Issuer', displayValue(certificate.issuer)],
                  [
                    say(locale, 'Geçerlilik sonu', 'Valid until'),
                    typeof certificate.validTo === 'string'
                      ? formatDate(certificate.validTo, false, locale)
                      : '—',
                  ],
                  ['Fingerprint', displayValue(certificate.fingerprint256)],
                ].map(([label, value]) => (
                  <div key={label} className="min-w-0 bg-card p-3">
                    <p className="text-[10px] uppercase tracking-wider text-muted-foreground">
                      {label}
                    </p>
                    <p className="mt-1.5 break-all font-mono text-[10px] leading-5">
                      {value}
                    </p>
                  </div>
                ))}
              </div>
            ) : null}
            {scan.observations ? (
              <details>
                <summary className="cursor-pointer text-xs font-medium">
                  {say(
                    locale,
                    'Normalize edilmiş gözlemler',
                    'Normalized observations',
                  )}
                </summary>
                <pre className="mt-2 max-h-72 overflow-auto rounded-lg bg-incident p-3 font-mono text-[10px] leading-5 text-white/72">
                  {JSON.stringify(scan.observations, null, 2)}
                </pre>
              </details>
            ) : null}
            <DialogFooter>
              <Button variant="outline" onClick={onClose}>
                {say(locale, 'Kapat', 'Close')}
              </Button>
            </DialogFooter>
          </>
        ) : null}
      </DialogContent>
    </Dialog>
  );
}

function DashboardView({
  data,
  onAdd,
  onViewIncident,
  onViewScan,
  onChangeView,
}: {
  data: DashboardData;
  onAdd: () => void;
  onViewIncident: (incident: Incident) => void;
  onViewScan: (scan: Scan) => void;
  onChangeView: (view: View) => void;
}) {
  const locale = useLocale();
  const { canOperate } = useAccess();
  const priorityAssets = [...data.assets]
    .sort(
      (first, second) =>
        second.criticalIncidentCount - first.criticalIncidentCount ||
        second.openIncidentCount - first.openIncidentCount,
    )
    .slice(0, 6);
  const priorityIncident = data.incidents[0];

  return (
    <>
      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <MetricCard
          label={say(locale, 'Toplam varlık', 'Total assets')}
          value={data.summary.totalAssets}
          note={
            data.summary.totalAssets
              ? say(locale, 'aktif endpoint', 'active endpoints')
              : say(locale, 'envanter boş', 'empty inventory')
          }
          icon={Boxes}
        />
        <MetricCard
          label={say(locale, 'Açık incident', 'Open incidents')}
          value={String(data.summary.openIncidents).padStart(2, '0')}
          note={`${data.summary.criticalIncidents} ${say(locale, 'kritik', 'critical')}`}
          icon={AlertTriangle}
          tone="text-critical"
        />
        <MetricCard
          label={say(locale, '30 gün içinde dolacak', 'Expiring in 30 days')}
          value={data.summary.expiringSoon}
          note={say(locale, 'yenileme penceresi', 'renewal window')}
          icon={Clock3}
          tone="text-warning"
        />
        <MetricCard
          label={say(locale, 'Sağlıklı yüzey', 'Healthy surface')}
          value={`%${data.summary.healthyPercentage}`}
          note={say(locale, 'incidentsız varlık', 'assets without incidents')}
          icon={ShieldCheck}
          tone="text-healthy"
        />
      </div>

      <div className="mt-4 grid gap-4 xl:grid-cols-[minmax(0,1.65fr)_minmax(300px,.8fr)]">
        <Card className="bg-card/82">
          <CardHeader className="border-b border-border pb-4">
            <div className="flex items-center justify-between gap-3">
              <div>
                <CardTitle>
                  {say(locale, 'Öncelikli varlıklar', 'Priority assets')}
                </CardTitle>
                <p className="mt-1 text-xs text-muted-foreground">
                  {say(
                    locale,
                    'Risk ve sertifika durumuna göre sıralandı',
                    'Sorted by risk and certificate status',
                  )}
                </p>
              </div>
              <Button
                variant="ghost"
                size="sm"
                onClick={() => onChangeView('assets')}
              >
                {say(locale, 'Tümünü gör', 'View all')}{' '}
                <ChevronRight data-icon="inline-end" />
              </Button>
            </div>
          </CardHeader>
          <CardContent className="px-0">
            {priorityAssets.length ? (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead className="pl-4">Domain</TableHead>
                    <TableHead>{say(locale, 'Risk', 'Risk')}</TableHead>
                    <TableHead className="hidden md:table-cell">
                      {say(locale, 'Bitiş', 'Expiry')}
                    </TableHead>
                    <TableHead className="hidden sm:table-cell">
                      {say(locale, 'Skor', 'Grade')}
                    </TableHead>
                    <TableHead className="hidden lg:table-cell">
                      {say(locale, 'Son tarama', 'Last scan')}
                    </TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {priorityAssets.map((asset) => (
                    <TableRow key={asset.id}>
                      <TableCell className="pl-4">
                        <p className="font-mono text-xs font-medium">
                          {asset.hostname}
                        </p>
                        <p className="mt-1 text-[11px] text-muted-foreground">
                          {asset.owner ||
                            say(
                              locale,
                              'Sahip atanmamış',
                              'No owner assigned',
                            )}{' '}
                          · :{asset.port}
                        </p>
                      </TableCell>
                      <TableCell>
                        {asset.openIncidentCount ? (
                          <Badge
                            variant="outline"
                            className={
                              asset.criticalIncidentCount
                                ? severityMeta.critical.className
                                : severityMeta.medium.className
                            }
                          >
                            {asset.openIncidentCount}{' '}
                            {say(locale, 'açık', 'open')}
                          </Badge>
                        ) : (
                          <Badge
                            variant="outline"
                            className="border-healthy/20 bg-healthy/8 text-healthy"
                          >
                            {say(locale, 'Temiz', 'Clear')}
                          </Badge>
                        )}
                      </TableCell>
                      <TableCell className="hidden font-mono text-xs md:table-cell">
                        {expiryLabel(asset.certificateExpiresAt, locale)}
                      </TableCell>
                      <TableCell className="hidden sm:table-cell">
                        <span className="grid size-7 place-items-center rounded-md bg-muted font-mono text-xs font-bold">
                          {asset.latestGrade || '—'}
                        </span>
                      </TableCell>
                      <TableCell className="hidden text-xs text-muted-foreground lg:table-cell">
                        {relativeTime(asset.lastScanAt, locale)}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            ) : (
              <EmptyState
                icon={Radar}
                title={say(locale, 'İzlenen varlık yok', 'No monitored assets')}
                description={say(
                  locale,
                  'İlk domaini eklediğinizde sertifika bilgileri ve incident’lar burada görünecek.',
                  'Certificate details and incidents will appear here after you add your first domain.',
                )}
                action={
                  canOperate ? (
                    <Button onClick={onAdd}>
                      <Plus data-icon="inline-start" />{' '}
                      {say(locale, 'İlk varlığı ekle', 'Add first asset')}
                    </Button>
                  ) : undefined
                }
              />
            )}
          </CardContent>
        </Card>

        {priorityIncident ? (
          <Card className="bg-incident text-incident-foreground ring-0">
            <CardHeader>
              <div className="flex items-center justify-between">
                <SeverityBadge severity={priorityIncident.severity} />
                <span className="font-mono text-[10px] text-white/45">
                  {priorityIncident.ruleKey}
                </span>
              </div>
              <CardTitle className="mt-5 text-lg text-white">
                {priorityIncident.title}
              </CardTitle>
            </CardHeader>
            <CardContent>
              <p className="font-mono text-xs text-white/62">
                {priorityIncident.hostname}:{priorityIncident.port}
              </p>
              <div className="mt-5 grid grid-cols-2 gap-3 border-y border-white/10 py-4 text-xs">
                <div>
                  <p className="text-white/42">
                    {say(locale, 'İlk görülme', 'First seen')}
                  </p>
                  <p className="mt-1 font-mono text-white/82">
                    {formatDate(priorityIncident.firstSeenAt, true, locale)}
                  </p>
                </div>
                <div>
                  <p className="text-white/42">
                    {say(locale, 'Sorumlu ekip', 'Owner team')}
                  </p>
                  <p className="mt-1 text-white/82">
                    {priorityIncident.owner ||
                      say(locale, 'Atanmamış', 'Unassigned')}
                  </p>
                </div>
              </div>
              <Button
                className="mt-4 w-full bg-white text-incident hover:bg-white/90"
                onClick={() => onViewIncident(priorityIncident)}
              >
                {say(locale, 'Incident’ı incele', 'Review incident')}{' '}
                <ArrowUpRight data-icon="inline-end" />
              </Button>
            </CardContent>
          </Card>
        ) : (
          <Card className="bg-incident text-incident-foreground ring-0">
            <EmptyState
              icon={ShieldCheck}
              title={say(locale, 'Açık incident yok', 'No open incidents')}
              description={say(
                locale,
                'Güvenilir taramalarda saptanan riskler burada önceliklendirilecek.',
                'Risks detected by reliable scans will be prioritized here.',
              )}
            />
          </Card>
        )}
      </div>

      <Card className="mt-4 bg-card/82">
        <CardHeader className="flex-row items-center justify-between border-b border-border pb-4">
          <div>
            <CardTitle>
              {say(locale, 'Son tarama akışı', 'Recent scan activity')}
            </CardTitle>
            <p className="mt-1 text-xs text-muted-foreground">
              {say(
                locale,
                'Kuyruk ve tamamlanan son işler',
                'Latest queued and completed jobs',
              )}
            </p>
          </div>
          <Badge variant="outline" className="gap-1.5">
            <Activity className="size-3" />
            {data.summary.runningScans
              ? `${data.summary.runningScans} ${say(locale, 'aktif', 'active')}`
              : say(locale, 'Hazır', 'Ready')}
          </Badge>
        </CardHeader>
        <CardContent className="grid gap-3 pt-1 sm:grid-cols-2 xl:grid-cols-3">
          {data.recentScans.length ? (
            data.recentScans.slice(0, 6).map((scan) => (
              <button
                key={scan.id}
                type="button"
                onClick={() => onViewScan(scan)}
                className="flex items-center gap-3 rounded-lg bg-muted/55 p-3 text-left transition-colors hover:bg-muted"
              >
                <span className="grid size-8 place-items-center rounded-lg bg-background font-mono text-xs font-bold">
                  {scan.status === 'running' || scan.status === 'queued' ? (
                    <LoaderCircle className="size-4 animate-spin text-primary" />
                  ) : (
                    scan.grade || <X className="size-4 text-critical" />
                  )}
                </span>
                <span className="min-w-0 flex-1">
                  <span className="block truncate font-mono text-[11px] font-medium">
                    {scan.hostname}:{scan.port}
                  </span>
                  <span className="mt-0.5 block text-[10px] text-muted-foreground">
                    {locale === 'en'
                      ? (
                          {
                            queued: 'Queued',
                            running: 'Running',
                            succeeded: 'Succeeded',
                            partial: 'Partial',
                            failed: 'Failed',
                          } as Record<ScanStatus, string>
                        )[scan.status]
                      : scanStatusMeta[scan.status].label}{' '}
                    · {durationLabel(scan.durationMs, locale)}
                  </span>
                </span>
              </button>
            ))
          ) : (
            <p className="col-span-full py-5 text-center text-xs text-muted-foreground">
              {say(
                locale,
                'Henüz tarama çalıştırılmadı.',
                'No scans have run yet.',
              )}
            </p>
          )}
        </CardContent>
      </Card>
    </>
  );
}

function AssetsView({
  assets,
  testsslAvailable,
  onAdd,
  onScan,
  onEdit,
  onArchive,
}: {
  assets: Asset[];
  testsslAvailable: boolean;
  onAdd: () => void;
  onScan: (asset: Asset, profile: 'native' | 'deep') => void;
  onEdit: (asset: Asset) => void;
  onArchive: (asset: Asset) => void;
}) {
  const locale = useLocale();
  const { canOperate } = useAccess();
  const [search, setSearch] = useState('');
  const [environment, setEnvironment] = useState('all');
  const filtered = assets.filter((asset) => {
    const haystack =
      `${asset.hostname} ${asset.label} ${asset.owner} ${asset.source}`.toLowerCase();
    return (
      haystack.includes(search.toLowerCase()) &&
      (environment === 'all' || asset.environment === environment)
    );
  });

  return (
    <Card className="bg-card/82">
      <CardHeader className="border-b border-border pb-4">
        <div className="flex flex-col justify-between gap-3 sm:flex-row sm:items-center">
          <div className="flex flex-1 gap-2">
            <div className="relative max-w-sm flex-1">
              <Search className="absolute left-2.5 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" />
              <Input
                value={search}
                onChange={(event) => setSearch(event.target.value)}
                placeholder={say(
                  locale,
                  'Domain, etiket veya ekip ara',
                  'Search domain, label, or team',
                )}
                className="pl-8"
                aria-label={say(locale, 'Varlık ara', 'Search assets')}
              />
            </div>
            <NativeSelect
              value={environment}
              onChange={(event) => setEnvironment(event.target.value)}
              aria-label={say(locale, 'Ortam filtresi', 'Environment filter')}
            >
              <NativeSelectOption value="all">
                {say(locale, 'Tüm ortamlar', 'All environments')}
              </NativeSelectOption>
              <NativeSelectOption value="production">
                {say(locale, 'Üretim', 'Production')}
              </NativeSelectOption>
              <NativeSelectOption value="staging">Staging</NativeSelectOption>
              <NativeSelectOption value="development">
                {say(locale, 'Geliştirme', 'Development')}
              </NativeSelectOption>
              <NativeSelectOption value="other">
                {say(locale, 'Diğer', 'Other')}
              </NativeSelectOption>
            </NativeSelect>
          </div>
          <div className="flex gap-2">
            <a
              href={apiEndpoint('/api/export/assets.csv')}
              download
              className={buttonVariants({ variant: 'outline' })}
            >
              <Download data-icon="inline-start" /> CSV
            </a>
            {canOperate ? (
              <Button onClick={onAdd}>
                <Plus data-icon="inline-start" />{' '}
                {say(locale, 'Varlık ekle', 'Add asset')}
              </Button>
            ) : null}
          </div>
        </div>
      </CardHeader>
      <CardContent className="px-0">
        {filtered.length ? (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="pl-4">
                  {say(locale, 'Varlık', 'Asset')}
                </TableHead>
                <TableHead>
                  {say(locale, 'Sahip / ortam', 'Owner / environment')}
                </TableHead>
                <TableHead className="hidden md:table-cell">
                  {say(locale, 'Sertifika bitişi', 'Certificate expiry')}
                </TableHead>
                <TableHead>{say(locale, 'Durum', 'Status')}</TableHead>
                {canOperate ? (
                  <TableHead className="text-right pr-4">
                    {say(locale, 'İşlem', 'Action')}
                  </TableHead>
                ) : null}
              </TableRow>
            </TableHeader>
            <TableBody>
              {filtered.map((asset) => (
                <TableRow key={asset.id}>
                  <TableCell className="pl-4">
                    <div className="flex items-center gap-3">
                      <span className="grid size-9 place-items-center rounded-lg bg-muted text-muted-foreground">
                        {asset.source === 'crt.name' ? (
                          <Network className="size-4" />
                        ) : (
                          <LockKeyhole className="size-4" />
                        )}
                      </span>
                      <div className="min-w-0">
                        <p className="font-mono text-xs font-medium">
                          {asset.hostname}:{asset.port}
                        </p>
                        <div className="mt-1 flex flex-wrap items-center gap-1.5 text-[11px] text-muted-foreground">
                          <span>{asset.label || asset.hostname}</span>
                          {asset.source === 'crt.name' ? (
                            <Badge
                              variant="outline"
                              className="h-5 px-1.5 text-[9px]"
                            >
                              crt.name
                            </Badge>
                          ) : null}
                          {asset.discoveredAssetCount > 0 ? (
                            <Badge
                              variant="secondary"
                              className="h-5 px-1.5 text-[9px]"
                            >
                              +{asset.discoveredAssetCount}{' '}
                              {say(locale, 'keşfedilen', 'discovered')}
                            </Badge>
                          ) : null}
                        </div>
                      </div>
                    </div>
                  </TableCell>
                  <TableCell>
                    <p className="text-xs">
                      {asset.owner || say(locale, 'Atanmamış', 'Unassigned')}
                    </p>
                    <p className="mt-1 text-[10px] uppercase tracking-wider text-muted-foreground">
                      {asset.environment}
                    </p>
                  </TableCell>
                  <TableCell className="hidden md:table-cell">
                    <p className="font-mono text-xs">
                      {expiryLabel(asset.certificateExpiresAt, locale)}
                    </p>
                    <p className="mt-1 text-[10px] text-muted-foreground">
                      {formatDate(asset.certificateExpiresAt, false, locale)}
                    </p>
                  </TableCell>
                  <TableCell>
                    <div className="flex flex-col items-start gap-1.5">
                      <ScanStatusBadge status={asset.latestStatus} />
                      {asset.openIncidentCount ? (
                        <span className="text-[10px] text-critical">
                          {asset.openIncidentCount}{' '}
                          {say(locale, 'açık incident', 'open incidents')}
                        </span>
                      ) : null}
                    </div>
                  </TableCell>
                  {canOperate ? (
                    <TableCell className="pr-4">
                      <div className="flex justify-end gap-1">
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => onScan(asset, 'native')}
                          disabled={
                            asset.latestStatus === 'queued' ||
                            asset.latestStatus === 'running'
                          }
                        >
                          <ScanLine /> {say(locale, 'Hızlı', 'Quick')}
                        </Button>
                        <Button
                          variant="ghost"
                          size="icon-sm"
                          title={say(locale, 'Düzenle', 'Edit')}
                          aria-label={say(
                            locale,
                            `${asset.hostname} varlığını düzenle`,
                            `Edit ${asset.hostname}`,
                          )}
                          onClick={() => onEdit(asset)}
                        >
                          <PencilLine />
                        </Button>
                        <Button
                          variant="ghost"
                          size="icon-sm"
                          title={say(
                            locale,
                            'testssl.sh derin taraması',
                            'testssl.sh deep scan',
                          )}
                          aria-label={say(
                            locale,
                            `${asset.hostname} için derin tarama`,
                            `Deep scan for ${asset.hostname}`,
                          )}
                          onClick={() => onScan(asset, 'deep')}
                          disabled={
                            !testsslAvailable ||
                            asset.latestStatus === 'queued' ||
                            asset.latestStatus === 'running'
                          }
                        >
                          <Terminal />
                        </Button>
                        <Button
                          variant="ghost"
                          size="icon-sm"
                          title={say(locale, 'Arşivle', 'Archive')}
                          aria-label={say(
                            locale,
                            `${asset.hostname} varlığını arşivle`,
                            `Archive ${asset.hostname}`,
                          )}
                          onClick={() => onArchive(asset)}
                        >
                          <Archive />
                        </Button>
                      </div>
                    </TableCell>
                  ) : null}
                </TableRow>
              ))}
            </TableBody>
          </Table>
        ) : (
          <EmptyState
            icon={search || environment !== 'all' ? Search : Boxes}
            title={
              search || environment !== 'all'
                ? say(locale, 'Eşleşen varlık yok', 'No matching assets')
                : say(locale, 'Envanter boş', 'Inventory is empty')
            }
            description={
              search || environment !== 'all'
                ? say(
                    locale,
                    'Arama veya ortam filtresini değiştirin.',
                    'Change the search or environment filter.',
                  )
                : say(
                    locale,
                    'İlk yetkili domaininizi ekleyerek envanter ve güvenlik görünürlüğünü başlatın.',
                    'Add your first authorized domain to start inventory and security visibility.',
                  )
            }
            action={
              canOperate && !search && environment === 'all' ? (
                <Button onClick={onAdd}>
                  <Plus data-icon="inline-start" />{' '}
                  {say(locale, 'Varlık ekle', 'Add asset')}
                </Button>
              ) : undefined
            }
          />
        )}
      </CardContent>
    </Card>
  );
}

function IncidentsView({
  onSelect,
}: {
  onSelect: (incident: Incident) => void;
}) {
  const locale = useLocale();
  const [severity, setSeverity] = useState('all');
  const [page, setPage] = useState(0);
  const pageSize = 50;
  const incidentsQuery = useQuery({
    queryKey: ['incidents', 'active', severity, page],
    queryFn: () => {
      const parameters = new URLSearchParams({
        status: 'active',
        limit: String(pageSize),
        offset: String(page * pageSize),
      });
      if (severity !== 'all') parameters.set('severity', severity);
      return api<IncidentPage>(`/api/incidents?${parameters}`);
    },
    placeholderData: (previous) => previous,
    refetchInterval: 15_000,
  });
  const response = incidentsQuery.data;
  const incidents = response?.incidents || [];
  const counts = response?.counts || {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  };
  const total = response?.total || 0;
  const pageCount = Math.max(1, Math.ceil(total / pageSize));
  const currentPage = response ? Math.floor(response.offset / pageSize) : page;

  const chooseSeverity = (item: string) => {
    setSeverity((current) => (current === item ? 'all' : item));
    setPage(0);
  };

  return (
    <div className="space-y-4">
      <div className="grid gap-3 sm:grid-cols-4">
        {(['critical', 'high', 'medium', 'low'] as Severity[]).map((item) => (
          <button
            type="button"
            key={item}
            onClick={() => chooseSeverity(item)}
            className={cn(
              'rounded-xl border bg-card/82 p-4 text-left transition-colors hover:bg-muted/40',
              severity === item && 'border-primary ring-2 ring-primary/10',
            )}
          >
            <SeverityBadge severity={item} />
            <p className="mt-4 font-mono text-2xl font-semibold">
              {counts[item]}
            </p>
          </button>
        ))}
      </div>
      <Card className="bg-card/82">
        <CardHeader className="flex-row items-center justify-between border-b border-border pb-4">
          <div>
            <CardTitle>
              {say(locale, 'Aktif risk kuyruğu', 'Active risk queue')}
            </CardTitle>
            <p className="mt-1 text-xs text-muted-foreground">
              {severity === 'all'
                ? say(locale, 'Tüm önem seviyeleri', 'All severity levels')
                : say(
                    locale,
                    `${severityMeta[severity as Severity].label} önem seviyesi`,
                    `${severity} severity`,
                  )}
            </p>
          </div>
          {severity !== 'all' ? (
            <Button
              variant="ghost"
              size="sm"
              onClick={() => chooseSeverity(severity)}
            >
              {say(locale, 'Filtreyi temizle', 'Clear filter')}
            </Button>
          ) : (
            <Badge variant="outline">
              {total} {say(locale, 'açık', 'open')}
            </Badge>
          )}
        </CardHeader>
        <CardContent className="px-0">
          {incidentsQuery.isPending && !response ? (
            <div className="grid min-h-48 place-items-center">
              <LoaderCircle className="size-5 animate-spin text-primary" />
            </div>
          ) : incidentsQuery.error ? (
            <div className="p-4">
              <Alert variant="destructive">
                <AlertCircle />
                <AlertTitle>
                  {say(
                    locale,
                    'Incident listesi yüklenemedi',
                    'Could not load incidents',
                  )}
                </AlertTitle>
                <AlertDescription>
                  {incidentsQuery.error.message}
                </AlertDescription>
              </Alert>
            </div>
          ) : incidents.length ? (
            <div className="divide-y divide-border">
              {incidents.map((incident) => (
                <button
                  type="button"
                  key={incident.id}
                  onClick={() => onSelect(incident)}
                  className="grid w-full gap-3 px-4 py-4 text-left transition-colors hover:bg-muted/40 md:grid-cols-[110px_minmax(0,1fr)_190px_90px] md:items-center"
                >
                  <SeverityBadge severity={incident.severity} />
                  <span className="min-w-0">
                    <span className="block truncate text-sm font-medium">
                      {incident.title}
                    </span>
                    <span className="mt-1 block truncate font-mono text-[10px] text-muted-foreground">
                      {incident.hostname}:{incident.port} · {incident.ruleKey}
                    </span>
                  </span>
                  <span className="text-xs text-muted-foreground">
                    {incident.owner ||
                      say(locale, 'Sahip atanmamış', 'No owner assigned')}
                  </span>
                  <span className="flex items-center justify-between text-[10px] text-muted-foreground">
                    {relativeTime(incident.lastSeenAt, locale)}
                    <ChevronRight className="size-4" />
                  </span>
                </button>
              ))}
            </div>
          ) : (
            <EmptyState
              icon={ShieldCheck}
              title={say(
                locale,
                'Bu filtrede açık incident yok',
                'No open incidents in this filter',
              )}
              description={say(
                locale,
                'Yeni bir güvenilir tarama risk saptarsa burada otomatik olarak açılacak.',
                'A new reliable scan will open one automatically when it detects a risk.',
              )}
            />
          )}
          {total > pageSize ? (
            <div className="flex items-center justify-between border-t border-border px-4 py-3">
              <p className="text-[11px] text-muted-foreground">
                {currentPage * pageSize + 1}–
                {Math.min((currentPage + 1) * pageSize, total)} / {total}
              </p>
              <div className="flex items-center gap-2">
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => setPage(Math.max(0, currentPage - 1))}
                  disabled={currentPage === 0 || incidentsQuery.isFetching}
                >
                  <ChevronLeft data-icon="inline-start" />{' '}
                  {say(locale, 'Önceki', 'Previous')}
                </Button>
                <span className="font-mono text-[10px] text-muted-foreground">
                  {currentPage + 1} / {pageCount}
                </span>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() =>
                    setPage(Math.min(pageCount - 1, currentPage + 1))
                  }
                  disabled={
                    currentPage + 1 >= pageCount || incidentsQuery.isFetching
                  }
                >
                  {say(locale, 'Sonraki', 'Next')}{' '}
                  <ChevronRight data-icon="inline-end" />
                </Button>
              </div>
            </div>
          ) : null}
        </CardContent>
      </Card>
    </div>
  );
}

function ScansView({ onSelect }: { onSelect: (scan: Scan) => void }) {
  const locale = useLocale();
  const scansQuery = useQuery({
    queryKey: ['scans'],
    queryFn: () => api<{ scans: Scan[] }>('/api/scans'),
    refetchInterval: (query) =>
      query.state.data?.scans.some(
        (scan) => scan.status === 'queued' || scan.status === 'running',
      )
        ? 2_500
        : 15_000,
  });
  const scans = scansQuery.data?.scans || [];
  return (
    <Card className="bg-card/82">
      <CardHeader className="border-b border-border pb-4">
        <div className="flex items-center justify-between">
          <div>
            <CardTitle>
              {say(locale, 'Tarama geçmişi', 'Scan history')}
            </CardTitle>
            <p className="mt-1 text-xs text-muted-foreground">
              {say(
                locale,
                'Son 100 native ve derin tarama',
                'Latest 100 native and deep scans',
              )}
            </p>
          </div>
          <Badge variant="outline">
            {scans.length} {say(locale, 'kayıt', 'records')}
          </Badge>
        </div>
      </CardHeader>
      <CardContent className="px-0">
        {scansQuery.isPending && !scansQuery.data ? (
          <div className="grid min-h-48 place-items-center">
            <LoaderCircle className="size-5 animate-spin text-primary" />
          </div>
        ) : scansQuery.error ? (
          <div className="p-4">
            <Alert variant="destructive">
              <AlertCircle />
              <AlertTitle>
                {say(
                  locale,
                  'Tarama geçmişi yüklenemedi',
                  'Could not load scan history',
                )}
              </AlertTitle>
              <AlertDescription>{scansQuery.error.message}</AlertDescription>
            </Alert>
          </div>
        ) : scans.length ? (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="pl-4">
                  {say(locale, 'Hedef', 'Target')}
                </TableHead>
                <TableHead>{say(locale, 'Profil', 'Profile')}</TableHead>
                <TableHead>{say(locale, 'Durum', 'Status')}</TableHead>
                <TableHead className="hidden sm:table-cell">
                  {say(locale, 'Skor', 'Grade')}
                </TableHead>
                <TableHead className="hidden md:table-cell">
                  {say(locale, 'Süre', 'Duration')}
                </TableHead>
                <TableHead className="pr-4 text-right">
                  {say(locale, 'Başlangıç', 'Started')}
                </TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {scans.map((scan) => (
                <TableRow
                  key={scan.id}
                  className="cursor-pointer"
                  onClick={() => onSelect(scan)}
                >
                  <TableCell className="pl-4 font-mono text-xs">
                    {scan.hostname}:{scan.port}
                  </TableCell>
                  <TableCell>
                    <Badge variant="outline" className="uppercase">
                      {scan.profile}
                    </Badge>
                  </TableCell>
                  <TableCell>
                    <ScanStatusBadge status={scan.status} />
                  </TableCell>
                  <TableCell className="hidden sm:table-cell">
                    <span className="font-mono font-semibold">
                      {scan.grade || '—'}
                    </span>
                  </TableCell>
                  <TableCell className="hidden font-mono text-xs md:table-cell">
                    {durationLabel(scan.durationMs, locale)}
                  </TableCell>
                  <TableCell className="pr-4 text-right text-xs text-muted-foreground">
                    {formatDate(scan.startedAt || scan.createdAt, true, locale)}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        ) : (
          <EmptyState
            icon={ScanLine}
            title={say(locale, 'Tarama geçmişi boş', 'Scan history is empty')}
            description={say(
              locale,
              'Bir varlık eklediğinizde ilk native tarama otomatik olarak kuyruğa alınır.',
              'The first native scan is queued automatically when you add an asset.',
            )}
          />
        )}
      </CardContent>
    </Card>
  );
}

function ChecksView({
  checks,
  health,
}: {
  checks: CheckDefinition[];
  health?: Health;
}) {
  const locale = useLocale();
  const grouped = checks.reduce<Record<string, CheckDefinition[]>>(
    (result, check) => {
      (result[check.category] ||= []).push(check);
      return result;
    },
    {},
  );
  return (
    <div className="grid gap-4 xl:grid-cols-[minmax(0,1.5fr)_340px]">
      <div className="space-y-4">
        {Object.entries(grouped).map(([category, items]) => (
          <Card key={category} className="bg-card/82">
            <CardHeader className="border-b border-border pb-3">
              <CardTitle className="text-sm">{category}</CardTitle>
            </CardHeader>
            <CardContent className="divide-y divide-border px-0">
              {items.map((check) => (
                <div
                  key={check.key}
                  className="flex items-center gap-3 px-4 py-3"
                >
                  <span
                    className={cn(
                      'grid size-8 place-items-center rounded-lg',
                      check.enabled
                        ? 'bg-primary/10 text-primary'
                        : 'bg-muted text-muted-foreground',
                    )}
                  >
                    {check.enabled ? (
                      <Check className="size-4" />
                    ) : (
                      <Settings className="size-4" />
                    )}
                  </span>
                  <div className="min-w-0 flex-1">
                    <p className="text-xs font-medium">{check.title}</p>
                    <p className="mt-1 truncate font-mono text-[10px] text-muted-foreground">
                      {check.key}
                    </p>
                  </div>
                  <div className="hidden text-right sm:block">
                    <p className="text-[10px] text-muted-foreground">
                      {check.source}
                      {check.recommendedCadence
                        ? ` · ${
                            check.recommendedCadence === 'daily'
                              ? say(locale, 'Günlük', 'Daily')
                              : check.recommendedCadence === 'weekly'
                                ? say(locale, 'Haftalık', 'Weekly')
                                : say(locale, 'Aylık', 'Monthly')
                          }`
                        : ''}
                    </p>
                    <p className="mt-1 text-[10px] uppercase tracking-wider">
                      {check.severity === 'dynamic'
                        ? say(locale, 'Dinamik', 'Dynamic')
                        : locale === 'en'
                          ? (
                              {
                                critical: 'Critical',
                                high: 'High',
                                medium: 'Medium',
                                low: 'Low',
                                info: 'Info',
                              } as Record<Severity, string>
                            )[check.severity]
                          : severityMeta[check.severity].label}
                    </p>
                  </div>
                  <Badge
                    variant="outline"
                    className={
                      check.enabled ? 'text-healthy' : 'text-muted-foreground'
                    }
                  >
                    {check.enabled
                      ? say(locale, 'Aktif', 'Active')
                      : say(locale, 'Ayar gerekli', 'Configuration required')}
                  </Badge>
                </div>
              ))}
            </CardContent>
          </Card>
        ))}
      </div>
      <div className="space-y-4">
        <Card className="bg-incident text-white ring-0">
          <CardHeader>
            <Badge className="w-fit bg-primary text-primary-foreground">
              {say(locale, 'Mimari', 'Architecture')}
            </Badge>
            <CardTitle className="mt-4 text-lg text-white">
              {say(
                locale,
                'Probe ve kural ayrımı',
                'Probe and rule separation',
              )}
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4 text-xs leading-5 text-white/62">
            <p>
              {say(
                locale,
                'Ağ erişimi yapan probe’lar normalize gözlem üretir. Alarm kuralları aynı gözlemi ağ erişimi olmadan değerlendirir.',
                'Network probes produce normalized observations. Alert rules evaluate those observations without network access.',
              )}
            </p>
            <div className="rounded-lg border border-white/10 bg-white/5 p-3 font-mono text-[10px] text-white/75">
              probe.collect() → observation
              <br />
              rule.evaluate() → pass / fail / unknown
            </div>
            <p>
              <strong className="text-white">unknown</strong>{' '}
              {say(
                locale,
                'sonucu açık incident’ı kapatmaz; yalnızca başarılı bir PASS sonucu kapatabilir.',
                'does not close an open incident; only a successful PASS result can close it.',
              )}
            </p>
          </CardContent>
        </Card>
        <Card className="bg-card/82">
          <CardHeader>
            <CardTitle className="text-sm">
              {say(locale, 'Genişletme noktaları', 'Extension points')}
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3 text-xs">
            {[
              [
                'Public DNS',
                health?.publicDnsResolver ||
                  say(
                    locale,
                    'Resolver ayarlanmamış',
                    'Resolver not configured',
                  ),
              ],
              [
                'testssl.sh',
                health?.engines.testssl.available
                  ? `v${health.engines.testssl.version}`
                  : say(locale, 'Bulunamadı', 'Not found'),
              ],
              [
                say(locale, 'Sonraki paket', 'Next pack'),
                'DNSSEC · dangling CNAME · STARTTLS',
              ],
            ].map(([label, value]) => (
              <div
                key={label}
                className="flex items-center justify-between gap-3 rounded-lg bg-muted/55 p-3"
              >
                <span className="text-muted-foreground">{label}</span>
                <span className="text-right font-mono text-[10px]">
                  {value}
                </span>
              </div>
            ))}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

function SettingsView({
  health,
  locale,
  onLogout,
  onSaved,
}: {
  health?: Health;
  locale: Locale;
  onLogout: () => void;
  onSaved: (message: string) => void;
}) {
  return (
    <SettingsPanel
      health={health}
      locale={locale}
      onLogout={onLogout}
      onSaved={onSaved}
    />
  );
}

function TlsSentinelApp() {
  const queryClient = useQueryClient();
  const [view, setView] = useState<View>('dashboard');
  const [addOpen, setAddOpen] = useState(false);
  const [selectedIncident, setSelectedIncident] = useState<Incident | null>(
    null,
  );
  const [selectedScan, setSelectedScan] = useState<Scan | null>(null);
  const [selectedAsset, setSelectedAsset] = useState<Asset | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const bootstrapQuery = useQuery({
    queryKey: ['bootstrap'],
    queryFn: () => api<BootstrapState>('/api/bootstrap'),
    staleTime: 15_000,
    retry: false,
  });
  const bootstrap = bootstrapQuery.data;
  const locale: Locale = bootstrap?.language || 'tr';
  const canOperate = !bootstrap?.user || bootstrap.user.role !== 'viewer';
  const accessReady = Boolean(
    bootstrap &&
    !bootstrap.setupRequired &&
    !bootstrap.lanAccessBlocked &&
    (!bootstrap.authenticationRequired || bootstrap.authenticated),
  );

  useEffect(() => {
    document.documentElement.lang = locale;
  }, [locale]);

  useEffect(() => {
    const requireAuthentication = () => {
      clearWorkspaceCache(queryClient);
      setSelectedIncident(null);
      setSelectedScan(null);
      setSelectedAsset(null);
      setAddOpen(false);
      setNotice(null);
      queryClient.setQueryData<BootstrapState>(['bootstrap'], (current) =>
        current?.setupRequired
          ? current
          : current
            ? {
                ...current,
                authenticated: false,
                authenticationRequired: true,
                user: null,
              }
            : current,
      );
      void queryClient.invalidateQueries({ queryKey: ['bootstrap'] });
    };
    window.addEventListener(
      'tls-sentinel-auth-required',
      requireAuthentication,
    );
    return () =>
      window.removeEventListener(
        'tls-sentinel-auth-required',
        requireAuthentication,
      );
  }, [queryClient]);

  const dashboardQuery = useQuery({
    queryKey: ['dashboard'],
    queryFn: () => api<DashboardData>('/api/dashboard'),
    enabled: accessReady,
    refetchInterval: (query) => {
      const data = query.state.data;
      const hasActive = data?.recentScans.some(
        (scan) => scan.status === 'queued' || scan.status === 'running',
      );
      return hasActive ? 2_500 : 15_000;
    },
  });
  const healthQuery = useQuery({
    queryKey: ['health'],
    queryFn: () => api<Health>('/api/health'),
    enabled: accessReady,
    staleTime: 60_000,
    refetchInterval: 60_000,
  });
  const checksQuery = useQuery({
    queryKey: ['checks'],
    queryFn: () => api<{ checks: CheckDefinition[] }>('/api/checks'),
    enabled: accessReady,
    staleTime: 60_000,
  });

  const refresh = () => {
    setNotice(null);
    void Promise.all([
      dashboardQuery.refetch(),
      healthQuery.refetch(),
      checksQuery.refetch(),
      queryClient.invalidateQueries({ queryKey: ['incidents'] }),
      queryClient.invalidateQueries({ queryKey: ['scans'] }),
    ]);
  };

  const scanMutation = useMutation({
    mutationFn: ({
      asset,
      profile,
    }: {
      asset: Asset;
      profile: 'native' | 'deep';
    }) =>
      api<{ scan: Scan; created: boolean }>(`/api/assets/${asset.id}/scan`, {
        method: 'POST',
        body: JSON.stringify({ profile }),
      }),
    onSuccess: async ({ created }, variables) => {
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: ['dashboard'] }),
        queryClient.invalidateQueries({ queryKey: ['scans'] }),
      ]);
      setNotice(
        created
          ? say(
              locale,
              `${variables.asset.hostname} için ${variables.profile === 'deep' ? 'derin' : 'hızlı'} tarama kuyruğa alındı.`,
              `${variables.profile === 'deep' ? 'Deep' : 'Quick'} scan queued for ${variables.asset.hostname}.`,
            )
          : say(
              locale,
              `${variables.asset.hostname} için zaten aktif bir tarama var.`,
              `An active scan already exists for ${variables.asset.hostname}.`,
            ),
      );
    },
    onError: (error) => setNotice(error.message),
  });

  const scanAllMutation = useMutation({
    mutationFn: () =>
      api<{ queued: number; existing: number }>('/api/scan-all', {
        method: 'POST',
        body: JSON.stringify({}),
      }),
    onSuccess: async ({ queued, existing }) => {
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: ['dashboard'] }),
        queryClient.invalidateQueries({ queryKey: ['scans'] }),
      ]);
      setNotice(
        say(
          locale,
          `${queued} tarama kuyruğa alındı${existing ? `, ${existing} aktif iş korundu` : ''}.`,
          `${queued} scans queued${existing ? `; ${existing} active jobs kept` : ''}.`,
        ),
      );
    },
    onError: (error) => setNotice(error.message),
  });

  const archiveMutation = useMutation({
    mutationFn: (asset: Asset) =>
      api<{ asset: Asset }>(`/api/assets/${asset.id}`, { method: 'DELETE' }),
    onSuccess: async (_, asset) => {
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: ['dashboard'] }),
        queryClient.invalidateQueries({ queryKey: ['incidents'] }),
        queryClient.invalidateQueries({ queryKey: ['scans'] }),
      ]);
      setNotice(
        say(
          locale,
          `${asset.hostname} arşivlendi; geçmiş taramalar korundu.`,
          `${asset.hostname} archived; scan history was retained.`,
        ),
      );
    },
    onError: (error) => setNotice(error.message),
  });

  const logoutMutation = useMutation({
    mutationFn: () =>
      api<{ ok: boolean }>('/api/session', { method: 'DELETE' }),
    onSuccess: async () => {
      clearWorkspaceCache(queryClient);
      setSelectedIncident(null);
      setSelectedScan(null);
      setSelectedAsset(null);
      setAddOpen(false);
      setNotice(null);
      setView('dashboard');
      await queryClient.invalidateQueries({ queryKey: ['bootstrap'] });
    },
    onError: (error) => setNotice(error.message),
  });

  const data = dashboardQuery.data;
  const health = healthQuery.data;
  const copy = (locale === 'en' ? viewCopyEn : viewCopyTr)[view];
  const loading = dashboardQuery.isPending && !data;
  const connectivityError = dashboardQuery.error || healthQuery.error;

  const content = useMemo(() => {
    if (!data) return null;
    switch (view) {
      case 'dashboard':
        return (
          <DashboardView
            data={data}
            onAdd={() => setAddOpen(true)}
            onViewIncident={setSelectedIncident}
            onViewScan={setSelectedScan}
            onChangeView={setView}
          />
        );
      case 'assets':
        return (
          <AssetsView
            assets={data.assets}
            testsslAvailable={Boolean(health?.engines.testssl.available)}
            onAdd={() => setAddOpen(true)}
            onScan={(asset, profile) => scanMutation.mutate({ asset, profile })}
            onEdit={setSelectedAsset}
            onArchive={(asset) => archiveMutation.mutate(asset)}
          />
        );
      case 'incidents':
        return <IncidentsView onSelect={setSelectedIncident} />;
      case 'scans':
        return <ScansView onSelect={setSelectedScan} />;
      case 'checks':
        return (
          <ChecksView checks={checksQuery.data?.checks || []} health={health} />
        );
      case 'settings':
        return (
          <SettingsView
            health={health}
            locale={locale}
            onLogout={() => logoutMutation.mutate()}
            onSaved={setNotice}
          />
        );
      default:
        return null;
    }
  }, [
    data,
    view,
    health,
    locale,
    checksQuery.data,
    scanMutation,
    archiveMutation,
    logoutMutation,
  ]);

  if (bootstrapQuery.isPending && !bootstrap) {
    return (
      <AuthShell>
        <div className="text-center">
          <LoaderCircle className="mx-auto size-7 animate-spin text-primary" />
          <p className="mt-3 text-xs text-muted-foreground">
            HostCanvas başlatılıyor…
          </p>
        </div>
      </AuthShell>
    );
  }

  if (bootstrapQuery.error || !bootstrap) {
    return (
      <AuthShell>
        <Alert variant="destructive" className="mx-auto max-w-lg bg-card">
          <AlertCircle />
          <AlertTitle>Yerel tarama API’sine ulaşılamıyor</AlertTitle>
          <AlertDescription className="space-y-3">
            <p>{bootstrapQuery.error?.message}</p>
            <Button
              variant="outline"
              size="sm"
              onClick={() => void bootstrapQuery.refetch()}
            >
              <RefreshCw data-icon="inline-start" /> Yeniden dene
            </Button>
          </AlertDescription>
        </Alert>
      </AuthShell>
    );
  }

  if (bootstrap.setupRequired) {
    return (
      <SetupWizard
        bootstrap={bootstrap}
        onComplete={() => void bootstrapQuery.refetch()}
      />
    );
  }

  if (bootstrap.lanAccessBlocked) {
    return <LanBlockedScreen bootstrap={bootstrap} />;
  }

  if (bootstrap.authenticationRequired && !bootstrap.authenticated) {
    return (
      <LoginScreen
        bootstrap={bootstrap}
        onAuthenticated={() => void bootstrapQuery.refetch()}
      />
    );
  }

  return (
    <LocaleContext.Provider value={locale}>
      <AccessContext.Provider value={bootstrap.user?.role || 'admin'}>
        <main className="min-h-screen bg-background text-foreground">
          <div className="mx-auto grid min-h-screen max-w-[1600px] lg:grid-cols-[228px_minmax(0,1fr)]">
            <aside className="hidden border-r border-sidebar-border bg-sidebar px-4 py-5 lg:flex lg:flex-col">
              <button
                type="button"
                onClick={() => setView('dashboard')}
                className="flex h-11 items-center gap-3 px-2 text-left"
              >
                <span className="grid size-9 place-items-center rounded-xl bg-primary text-primary-foreground shadow-[0_8px_24px_-10px_var(--primary)]">
                  <Fingerprint className="size-5" />
                </span>
                <span>
                  <span className="block font-heading text-sm font-semibold tracking-tight">
                    HostCanvas
                  </span>
                  <span className="block font-mono text-[10px] uppercase tracking-[0.14em] text-muted-foreground">
                    Domain monitor
                  </span>
                </span>
              </button>

              <nav
                aria-label={say(locale, 'Ana menü', 'Main menu')}
                className="mt-8 space-y-1"
              >
                {navItems(locale).map((item) => (
                  <button
                    key={item.id}
                    type="button"
                    onClick={() => setView(item.id)}
                    className={cn(
                      'flex h-10 w-full items-center gap-3 rounded-lg px-3 text-left text-sm transition-colors',
                      view === item.id
                        ? 'bg-sidebar-accent font-medium text-sidebar-accent-foreground'
                        : 'text-muted-foreground hover:bg-sidebar-accent/60 hover:text-foreground',
                    )}
                  >
                    <item.icon className="size-4" />
                    <span className="flex-1">{item.label}</span>
                    {item.id === 'incidents' && data?.summary.openIncidents ? (
                      <span className="rounded-full bg-critical/12 px-2 py-0.5 font-mono text-[10px] font-semibold text-critical">
                        {data.summary.openIncidents}
                      </span>
                    ) : null}
                  </button>
                ))}
              </nav>

              <div className="mt-auto space-y-4">
                <div className="rounded-xl border border-border bg-card/70 p-3">
                  <div className="flex items-center gap-2 text-xs font-medium">
                    <span className="relative flex size-2">
                      {health?.ok ? (
                        <>
                          <span className="absolute inline-flex size-full animate-ping rounded-full bg-healthy opacity-50" />
                          <span className="relative inline-flex size-2 rounded-full bg-healthy" />
                        </>
                      ) : (
                        <span className="relative inline-flex size-2 rounded-full bg-critical" />
                      )}
                    </span>
                    {health?.ok
                      ? say(locale, 'Tarama motoru hazır', 'Scanner ready')
                      : say(locale, 'API bekleniyor', 'Waiting for API')}
                  </div>
                  <p className="mt-2 text-[11px] leading-5 text-muted-foreground">
                    Native TLS{' '}
                    {health?.engines.native.available
                      ? say(locale, 'aktif', 'active')
                      : say(locale, 'kapalı', 'disabled')}{' '}
                    · testssl.sh{' '}
                    {health?.engines.testssl.available
                      ? `v${health.engines.testssl.version}`
                      : say(locale, 'bulunamadı', 'not found')}
                  </p>
                </div>
                <button
                  onClick={() => setView('settings')}
                  className={cn(
                    'flex h-9 w-full items-center gap-3 rounded-lg px-3 text-sm text-muted-foreground hover:bg-sidebar-accent hover:text-foreground',
                    view === 'settings' && 'bg-sidebar-accent text-foreground',
                  )}
                >
                  <Settings className="size-4" />{' '}
                  {say(locale, 'Ayarlar', 'Settings')}
                </button>
              </div>
            </aside>

            <section className="min-w-0">
              <header className="sticky top-0 z-20 flex h-16 items-center justify-between border-b border-border bg-background/88 px-4 backdrop-blur-xl sm:px-6 xl:px-10">
                <button
                  type="button"
                  onClick={() => setView('dashboard')}
                  className="flex items-center gap-3 lg:hidden"
                >
                  <span className="grid size-9 place-items-center rounded-xl bg-primary text-primary-foreground">
                    <Fingerprint className="size-5" />
                  </span>
                  <span className="font-heading text-sm font-semibold">
                    HostCanvas
                  </span>
                </button>
                <div className="hidden items-center gap-2 text-sm text-muted-foreground lg:flex">
                  <Radar className="size-4 text-primary" />
                  <span>
                    {bootstrap.organization ||
                      say(locale, 'Yerel çalışma alanı', 'Local workspace')}
                  </span>
                  <span className="text-border">/</span>
                  <span className="text-foreground">{copy.eyebrow}</span>
                </div>
                <div className="flex items-center gap-2">
                  <Button
                    variant="ghost"
                    size="icon"
                    onClick={refresh}
                    aria-label={say(locale, 'Verileri yenile', 'Refresh data')}
                    title={say(locale, 'Yenile', 'Refresh')}
                    disabled={dashboardQuery.isFetching}
                  >
                    <RefreshCw
                      className={
                        dashboardQuery.isFetching ? 'animate-spin' : ''
                      }
                    />
                  </Button>
                  {canOperate ? (
                    <>
                      <Button
                        variant="outline"
                        className="hidden sm:inline-flex"
                        onClick={() => setAddOpen(true)}
                      >
                        <Plus data-icon="inline-start" />{' '}
                        {say(locale, 'Varlık ekle', 'Add asset')}
                      </Button>
                      <Button
                        onClick={() => scanAllMutation.mutate()}
                        disabled={
                          !data?.assets.length || scanAllMutation.isPending
                        }
                      >
                        {scanAllMutation.isPending ? (
                          <LoaderCircle
                            className="animate-spin"
                            data-icon="inline-start"
                          />
                        ) : (
                          <ScanLine data-icon="inline-start" />
                        )}
                        {say(locale, 'Tümünü tara', 'Scan all')}
                      </Button>
                    </>
                  ) : null}
                </div>
              </header>

              <nav
                className="flex gap-1 overflow-x-auto border-b border-border bg-sidebar/55 px-4 py-2 lg:hidden"
                aria-label={say(locale, 'Mobil menü', 'Mobile menu')}
              >
                {navItems(locale).map((item) => (
                  <Button
                    key={item.id}
                    variant={view === item.id ? 'secondary' : 'ghost'}
                    size="sm"
                    onClick={() => setView(item.id)}
                  >
                    <item.icon /> {item.label}
                  </Button>
                ))}
              </nav>

              <div className="px-4 py-6 sm:px-6 xl:px-10 xl:py-8">
                <div className="flex flex-col justify-between gap-4 sm:flex-row sm:items-end">
                  <div>
                    <p className="font-mono text-[11px] font-semibold uppercase tracking-[0.16em] text-primary">
                      {copy.eyebrow}
                    </p>
                    <h1 className="mt-2 font-heading text-2xl font-semibold tracking-[-0.025em] sm:text-3xl">
                      {copy.title}
                    </h1>
                    <p className="mt-2 max-w-2xl text-sm leading-6 text-muted-foreground">
                      {copy.description}
                    </p>
                  </div>
                  <div className="flex items-center gap-2 text-xs text-muted-foreground">
                    <Clock3 className="size-3.5" />
                    {data
                      ? `${say(locale, 'Güncellendi', 'Updated')} ${relativeTime(data.generatedAt, locale)}`
                      : say(locale, 'API bekleniyor', 'Waiting for API')}
                  </div>
                </div>

                {notice ? (
                  <Alert className="mt-5 border-primary/20 bg-primary/5">
                    <Check />
                    <AlertTitle>
                      {say(locale, 'İşlem bilgisi', 'Operation update')}
                    </AlertTitle>
                    <AlertDescription>{notice}</AlertDescription>
                    <button
                      type="button"
                      onClick={() => setNotice(null)}
                      aria-label={say(
                        locale,
                        'Bildirimi kapat',
                        'Dismiss notification',
                      )}
                      className="absolute right-2 top-2 rounded-md p-1 text-muted-foreground hover:bg-muted"
                    >
                      <X className="size-4" />
                    </button>
                  </Alert>
                ) : null}

                {connectivityError ? (
                  <Alert variant="destructive" className="mt-5">
                    <AlertCircle />
                    <AlertTitle>
                      {say(
                        locale,
                        'Yerel tarama API’sine ulaşılamıyor',
                        'Cannot reach the local scanning API',
                      )}
                    </AlertTitle>
                    <AlertDescription>
                      <p>{connectivityError.message}</p>
                      <p className="mt-1 font-mono text-[11px]">npm run dev</p>
                    </AlertDescription>
                  </Alert>
                ) : null}

                <div className="mt-7">
                  {loading ? (
                    <div className="grid min-h-80 place-items-center">
                      <div className="text-center">
                        <LoaderCircle className="mx-auto size-6 animate-spin text-primary" />
                        <p className="mt-3 text-xs text-muted-foreground">
                          {say(
                            locale,
                            'Yerel envanter yükleniyor…',
                            'Loading local inventory…',
                          )}
                        </p>
                      </div>
                    </div>
                  ) : (
                    content
                  )}
                </div>

                <footer className="mt-8 flex flex-col justify-between gap-3 border-t border-border pt-5 text-[10px] text-muted-foreground sm:flex-row sm:items-center">
                  <span>
                    HostCanvas v{health?.version || '0.3.0'} ·{' '}
                    {say(
                      locale,
                      'Telemetry yok · Veriler yerel SQLite’ta',
                      'No telemetry · Data stays in local SQLite',
                    )}
                  </span>
                  <span className="flex items-center gap-1.5">
                    <ShieldCheck className="size-3" />{' '}
                    {say(
                      locale,
                      'Yalnızca yetkili sistemleri tarayın',
                      'Scan authorized systems only',
                    )}
                  </span>
                </footer>
              </div>
            </section>
          </div>

          <AddAssetDialog
            key={`${bootstrap.defaultScanProfile}-${bootstrap.defaultExpiryWarningDays}-${bootstrap.defaultScanIntervalMinutes}`}
            open={addOpen}
            onOpenChange={setAddOpen}
            health={health}
            defaults={bootstrap}
            onCreated={setNotice}
          />
          <IncidentDetailDialog
            incident={selectedIncident}
            onClose={() => setSelectedIncident(null)}
            onUpdated={setNotice}
          />
          <EditAssetDialog
            key={selectedAsset?.id || 'no-selected-asset'}
            asset={selectedAsset}
            health={health}
            onClose={() => setSelectedAsset(null)}
            onSuccess={setNotice}
          />
          <ScanDetailDialog
            scan={selectedScan}
            onClose={() => setSelectedScan(null)}
          />
        </main>
      </AccessContext.Provider>
    </LocaleContext.Provider>
  );
}

export default function Home() {
  const [queryClient] = useState(
    () =>
      new QueryClient({
        defaultOptions: {
          queries: {
            retry: (failures, error) =>
              failures < 1 &&
              ![401, 403].includes(
                Number((error as Error & { status?: number }).status),
              ),
            refetchOnWindowFocus: true,
          },
          mutations: { retry: 0 },
        },
      }),
  );
  return (
    <QueryClientProvider client={queryClient}>
      <TlsSentinelApp />
    </QueryClientProvider>
  );
}
