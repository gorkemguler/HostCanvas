'use client';

import {
  AlertCircle,
  Check,
  Gauge,
  KeyRound,
  LoaderCircle,
  LockKeyhole,
  LogOut,
  Network,
  ServerCog,
  ShieldAlert,
  Terminal,
  Wifi,
} from 'lucide-react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';

import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import {
  NativeSelect,
  NativeSelectOption,
} from '@/components/ui/native-select';
import { Switch } from '@/components/ui/switch';
import { Textarea } from '@/components/ui/textarea';
import { AdminPanel } from '@/app/admin-panel';
import { apiRequest } from '@/app/client-api';
import {
  isLocalPanelOrigin,
  isSecureLanOrigin,
  panelOrigin,
} from '@/app/client-security';

type Locale = 'tr' | 'en';

type AppUser = {
  id: string;
  username: string;
  displayName: string;
  role: 'admin' | 'operator' | 'viewer';
  enabled: boolean;
};

type AppSettings = {
  setupCompleted: boolean;
  language: Locale;
  organization: string;
  lanEnabled: boolean;
  authEnabled: boolean;
  allowedOrigins: string[];
  sessionTtlHours: number;
  defaultScanProfile: 'native' | 'deep';
  defaultExpiryWarningDays: number;
  defaultScanIntervalMinutes: number;
  updatedAt: string;
};

type SettingsResponse = {
  settings: AppSettings;
  user: AppUser | null;
  suggestedOrigins: string[];
};

type Health = {
  bind: string;
  publicDnsResolver: string | null;
  engines: {
    native: { available: boolean; version: string };
    testssl: {
      available: boolean;
      version: string | null;
      error: string | null;
    };
  };
};

function word(locale: Locale, turkish: string, english: string) {
  return locale === 'en' ? english : turkish;
}

function SettingsEditor({
  data,
  health,
  locale,
  onLogout,
  onSaved,
}: {
  data: SettingsResponse;
  health?: Health;
  locale: Locale;
  onLogout: () => void;
  onSaved: (message: string) => void;
}) {
  const queryClient = useQueryClient();
  const isAdmin = !data.user || data.user.role === 'admin';
  const [organization, setOrganization] = useState(data.settings.organization);
  const [language, setLanguage] = useState<Locale>(data.settings.language);
  const [authEnabled, setAuthEnabled] = useState(data.settings.authEnabled);
  const [lanEnabled, setLanEnabled] = useState(data.settings.lanEnabled);
  const [allowedOrigins, setAllowedOrigins] = useState(
    data.settings.allowedOrigins.join('\n'),
  );
  const [sessionTtlHours, setSessionTtlHours] = useState(
    String(data.settings.sessionTtlHours),
  );
  const [defaultScanProfile, setDefaultScanProfile] = useState<
    'native' | 'deep'
  >(data.settings.defaultScanProfile);
  const [defaultExpiryWarningDays, setDefaultExpiryWarningDays] = useState(
    String(data.settings.defaultExpiryWarningDays),
  );
  const [defaultScanIntervalMinutes, setDefaultScanIntervalMinutes] = useState(
    String(data.settings.defaultScanIntervalMinutes),
  );
  const [username, setUsername] = useState(data.user?.username || 'admin');
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [newPasswordConfirm, setNewPasswordConfirm] = useState('');

  const originList = () => [
    ...new Set(
      allowedOrigins
        .split(/[\s,]+/)
        .map((value) => value.trim())
        .filter(Boolean),
    ),
  ];
  const suggestedLanOrigin = data.suggestedOrigins.find(isSecureLanOrigin);

  const saveMutation = useMutation({
    mutationFn: () =>
      apiRequest<{ settings: AppSettings }>('/api/settings', {
        method: 'PATCH',
        body: JSON.stringify({
          organization,
          language,
          authEnabled: lanEnabled ? true : authEnabled,
          lanEnabled,
          allowedOrigins: originList(),
          sessionTtlHours: Number(sessionTtlHours),
          defaultScanProfile,
          defaultExpiryWarningDays: Number(defaultExpiryWarningDays),
          defaultScanIntervalMinutes: Number(defaultScanIntervalMinutes),
        }),
      }),
    onSuccess: async () => {
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: ['settings'] }),
        queryClient.invalidateQueries({ queryKey: ['bootstrap'] }),
      ]);
      onSaved(word(locale, 'Ayarlar kaydedildi.', 'Settings saved.'));
    },
  });

  const passwordMutation = useMutation({
    mutationFn: () =>
      apiRequest('/api/account/password', {
        method: 'POST',
        body: JSON.stringify({ username, currentPassword, newPassword }),
      }),
    onSuccess: () => {
      setCurrentPassword('');
      setNewPassword('');
      setNewPasswordConfirm('');
      onSaved(
        word(
          locale,
          'Yönetici parolası değiştirildi.',
          'Administrator password changed.',
        ),
      );
    },
  });

  const setLan = (enabled: boolean) => {
    setLanEnabled(enabled);
    if (!enabled) return;
    setAuthEnabled(true);
    if (suggestedLanOrigin && !originList().includes(suggestedLanOrigin)) {
      setAllowedOrigins((current) =>
        `${current.trim()}\n${suggestedLanOrigin}`.trim(),
      );
    }
  };

  const settingsValid =
    organization.trim().length > 0 &&
    Number(sessionTtlHours) >= 1 &&
    Number(sessionTtlHours) <= 168 &&
    Number(defaultExpiryWarningDays) >= 1 &&
    Number(defaultExpiryWarningDays) <= 365 &&
    Number(defaultScanIntervalMinutes) >= 15 &&
    Number(defaultScanIntervalMinutes) <= 10080 &&
    originList().every((origin) => Boolean(panelOrigin(origin))) &&
    (!lanEnabled ||
      (originList().some(isSecureLanOrigin) &&
        originList().every(
          (origin) => isLocalPanelOrigin(origin) || isSecureLanOrigin(origin),
        )));
  const passwordValid =
    currentPassword.length > 0 &&
    newPassword.length >= 12 &&
    newPassword === newPasswordConfirm;

  const engineCards = [
    {
      label: word(locale, 'API erişimi', 'API access'),
      value: health?.bind || '—',
      note: word(
        locale,
        'LAN erişimi uygulama ayarlarıyla sınırlandırılır.',
        'LAN access is restricted by application settings.',
      ),
      icon: ServerCog,
      healthy: Boolean(health),
    },
    {
      label: word(locale, 'Native TLS motoru', 'Native TLS engine'),
      value: health?.engines.native.version || '—',
      note: word(
        locale,
        'Sertifika, protokol, cipher ve HTTP header kontrolleri.',
        'Certificate, protocol, cipher, and HTTP header checks.',
      ),
      icon: Gauge,
      healthy: Boolean(health?.engines.native.available),
    },
    {
      label: 'testssl.sh',
      value: health?.engines.testssl.available
        ? `v${health.engines.testssl.version}`
        : word(locale, 'Kullanılamıyor', 'Unavailable'),
      note: health?.engines.testssl.available
        ? word(
            locale,
            'Derin tarama profili hazır.',
            'Deep scan profile is ready.',
          )
        : health?.engines.testssl.error ||
          word(locale, 'PATH içinde bulunamadı.', 'Not found in PATH.'),
      icon: Terminal,
      healthy: Boolean(health?.engines.testssl.available),
    },
    {
      label: word(locale, 'Public DNS resolver', 'Public DNS resolver'),
      value: health?.publicDnsResolver || word(locale, 'Kapalı', 'Disabled'),
      note: word(
        locale,
        'Split-horizon sonuçları için isteğe bağlı çözümleyici.',
        'Optional resolver for split-horizon results.',
      ),
      icon: Network,
      healthy: Boolean(health?.publicDnsResolver),
    },
  ];

  return (
    <div className="space-y-5">
      <div className="grid gap-4 xl:grid-cols-2">
        <Card className="bg-card/82">
          <CardHeader>
            <div className="flex items-center gap-3">
              <span className="grid size-9 place-items-center rounded-lg bg-primary/10 text-primary">
                <Wifi className="size-4" />
              </span>
              <div>
                <CardTitle className="text-sm">
                  {word(
                    locale,
                    'Çalışma alanı ve erişim',
                    'Workspace and access',
                  )}
                </CardTitle>
                <p className="mt-1 text-xs text-muted-foreground">
                  {word(
                    locale,
                    'İlk kurulum seçimlerini buradan değiştirebilirsiniz.',
                    'Change your initial setup choices here.',
                  )}
                </p>
              </div>
            </div>
          </CardHeader>
          <CardContent className="space-y-5">
            <div className="grid gap-4 sm:grid-cols-2">
              <div className="space-y-2">
                <Label htmlFor="settings-organization">
                  {word(locale, 'Ekip veya kurum', 'Team or organization')}
                </Label>
                <Input
                  id="settings-organization"
                  value={organization}
                  onChange={(event) => setOrganization(event.target.value)}
                  disabled={!isAdmin}
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="settings-language">
                  {word(locale, 'Panel dili', 'Interface language')}
                </Label>
                <NativeSelect
                  id="settings-language"
                  value={language}
                  onChange={(event) =>
                    setLanguage(event.target.value as Locale)
                  }
                  disabled={!isAdmin}
                >
                  <NativeSelectOption value="tr">Türkçe</NativeSelectOption>
                  <NativeSelectOption value="en">English</NativeSelectOption>
                </NativeSelect>
              </div>
            </div>

            <div className="flex items-start justify-between gap-4 rounded-xl border border-border p-4">
              <div>
                <div className="flex items-center gap-2 text-sm font-medium">
                  <LockKeyhole className="size-4 text-primary" />{' '}
                  {word(locale, 'Kimlik doğrulama', 'Authentication')}
                </div>
                <p className="mt-1 text-xs leading-5 text-muted-foreground">
                  {word(
                    locale,
                    'Yerel kullanımda da giriş ekranını zorunlu kılar.',
                    'Requires sign-in even for local use.',
                  )}
                </p>
              </div>
              <Switch
                aria-label={word(locale, 'Kimlik doğrulama', 'Authentication')}
                checked={authEnabled || lanEnabled}
                onCheckedChange={setAuthEnabled}
                disabled={lanEnabled || !isAdmin}
              />
            </div>
            <div className="flex items-start justify-between gap-4 rounded-xl border border-border p-4">
              <div>
                <div className="flex items-center gap-2 text-sm font-medium">
                  <Wifi className="size-4 text-primary" />{' '}
                  {word(locale, 'LAN erişimi', 'LAN access')}
                </div>
                <p className="mt-1 text-xs leading-5 text-muted-foreground">
                  {word(
                    locale,
                    'Paneli ağdaki istemcilere açar; HTTPS ve kimlik doğrulama zorunludur.',
                    'Opens the panel to network clients; HTTPS and authentication are required.',
                  )}
                </p>
              </div>
              <Switch
                aria-label={word(locale, 'LAN erişimi', 'LAN access')}
                checked={lanEnabled}
                onCheckedChange={setLan}
                disabled={!isAdmin}
              />
            </div>

            <div className="space-y-2">
              <Label htmlFor="settings-origins">
                {word(
                  locale,
                  'İzinli panel adresleri',
                  'Allowed panel origins',
                )}
              </Label>
              <Textarea
                id="settings-origins"
                value={allowedOrigins}
                onChange={(event) => setAllowedOrigins(event.target.value)}
                disabled={!isAdmin}
                className="min-h-24 font-mono text-xs"
                placeholder="https://192.168.1.20:3443"
              />
              <p className="text-[11px] leading-5 text-muted-foreground">
                {word(
                  locale,
                  'Her satıra protokol ve port dahil bir adres yazın. LAN adresleri HTTPS kullanmalıdır; localhost için HTTP kullanılabilir.',
                  'Enter one address per line, including protocol and port. LAN addresses require HTTPS; localhost may use HTTP.',
                )}
              </p>
            </div>

            {saveMutation.error ? (
              <p className="text-xs text-critical">
                {saveMutation.error.message}
              </p>
            ) : null}
            {isAdmin ? (
              <Button
                onClick={() => saveMutation.mutate()}
                disabled={!settingsValid || saveMutation.isPending}
              >
                {saveMutation.isPending ? (
                  <LoaderCircle
                    className="animate-spin"
                    data-icon="inline-start"
                  />
                ) : (
                  <Check data-icon="inline-start" />
                )}
                {word(locale, 'Ayarları kaydet', 'Save settings')}
              </Button>
            ) : (
              <p className="text-xs text-muted-foreground">
                {word(
                  locale,
                  'Çalışma alanı ayarlarını yalnızca yöneticiler değiştirebilir.',
                  'Only administrators can change workspace settings.',
                )}
              </p>
            )}
          </CardContent>
        </Card>

        <div className="space-y-4">
          <Card className="bg-card/82">
            <CardHeader>
              <CardTitle className="text-sm">
                {word(
                  locale,
                  'Yeni varlık varsayılanları',
                  'New asset defaults',
                )}
              </CardTitle>
            </CardHeader>
            <CardContent className="grid gap-4 sm:grid-cols-2">
              <div className="space-y-2">
                <Label htmlFor="settings-default-profile">
                  {word(locale, 'Tarama profili', 'Scan profile')}
                </Label>
                <NativeSelect
                  id="settings-default-profile"
                  value={defaultScanProfile}
                  disabled={!isAdmin}
                  onChange={(event) =>
                    setDefaultScanProfile(
                      event.target.value as 'native' | 'deep',
                    )
                  }
                >
                  <NativeSelectOption value="native">Native</NativeSelectOption>
                  <NativeSelectOption value="deep">
                    testssl.sh
                  </NativeSelectOption>
                </NativeSelect>
              </div>
              <div className="space-y-2">
                <Label htmlFor="settings-session-ttl">
                  {word(locale, 'Oturum süresi', 'Session lifetime')}
                </Label>
                <NativeSelect
                  id="settings-session-ttl"
                  value={sessionTtlHours}
                  disabled={!isAdmin}
                  onChange={(event) => setSessionTtlHours(event.target.value)}
                >
                  <NativeSelectOption value="4">4h</NativeSelectOption>
                  <NativeSelectOption value="12">12h</NativeSelectOption>
                  <NativeSelectOption value="24">24h</NativeSelectOption>
                  <NativeSelectOption value="168">7d</NativeSelectOption>
                </NativeSelect>
              </div>
              <div className="space-y-2">
                <Label htmlFor="settings-expiry-warning">
                  {word(locale, 'Bitiş uyarısı (gün)', 'Expiry warning (days)')}
                </Label>
                <Input
                  id="settings-expiry-warning"
                  type="number"
                  min="1"
                  max="365"
                  value={defaultExpiryWarningDays}
                  disabled={!isAdmin}
                  onChange={(event) =>
                    setDefaultExpiryWarningDays(event.target.value)
                  }
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="settings-scan-interval">
                  {word(locale, 'Tarama aralığı', 'Scan interval')}
                </Label>
                <NativeSelect
                  id="settings-scan-interval"
                  value={defaultScanIntervalMinutes}
                  disabled={!isAdmin}
                  onChange={(event) =>
                    setDefaultScanIntervalMinutes(event.target.value)
                  }
                >
                  <NativeSelectOption value="360">6h</NativeSelectOption>
                  <NativeSelectOption value="720">12h</NativeSelectOption>
                  <NativeSelectOption value="1440">24h</NativeSelectOption>
                  <NativeSelectOption value="10080">7d</NativeSelectOption>
                </NativeSelect>
              </div>
              <p className="text-[11px] leading-5 text-muted-foreground sm:col-span-2">
                {word(
                  locale,
                  'Bu değerler yalnızca bundan sonra eklenen varlıklara uygulanır.',
                  'These values apply only to assets added from now on.',
                )}
              </p>
            </CardContent>
          </Card>

          <Card className="bg-card/82">
            <CardHeader>
              <div className="flex items-center gap-3">
                <span className="grid size-9 place-items-center rounded-lg bg-primary/10 text-primary">
                  <KeyRound className="size-4" />
                </span>
                <CardTitle className="text-sm">
                  {word(locale, 'Yönetici hesabı', 'Administrator account')}
                </CardTitle>
              </div>
            </CardHeader>
            <CardContent className="space-y-4">
              {!data.user ? (
                <div className="space-y-2">
                  <Label htmlFor="password-username">
                    {word(locale, 'Kullanıcı adı', 'Username')}
                  </Label>
                  <Input
                    id="password-username"
                    value={username}
                    onChange={(event) => setUsername(event.target.value)}
                    autoComplete="username"
                  />
                </div>
              ) : (
                <p className="text-xs text-muted-foreground">
                  {data.user.displayName || data.user.username} · @
                  {data.user.username}
                </p>
              )}
              <div className="grid gap-4 sm:grid-cols-3">
                <div className="space-y-2">
                  <Label htmlFor="password-current">
                    {word(locale, 'Mevcut parola', 'Current password')}
                  </Label>
                  <Input
                    id="password-current"
                    type="password"
                    value={currentPassword}
                    onChange={(event) => setCurrentPassword(event.target.value)}
                    autoComplete="current-password"
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="password-new">
                    {word(locale, 'Yeni parola', 'New password')}
                  </Label>
                  <Input
                    id="password-new"
                    type="password"
                    value={newPassword}
                    onChange={(event) => setNewPassword(event.target.value)}
                    autoComplete="new-password"
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="password-confirm">
                    {word(locale, 'Parola tekrarı', 'Confirm password')}
                  </Label>
                  <Input
                    id="password-confirm"
                    type="password"
                    value={newPasswordConfirm}
                    onChange={(event) =>
                      setNewPasswordConfirm(event.target.value)
                    }
                    autoComplete="new-password"
                  />
                </div>
              </div>
              {newPassword && newPassword.length < 12 ? (
                <p className="text-[11px] text-warning">
                  {word(
                    locale,
                    'Yeni parola en az 12 karakter olmalı.',
                    'The new password must be at least 12 characters.',
                  )}
                </p>
              ) : null}
              {newPasswordConfirm && newPassword !== newPasswordConfirm ? (
                <p className="text-[11px] text-critical">
                  {word(
                    locale,
                    'Parolalar eşleşmiyor.',
                    'Passwords do not match.',
                  )}
                </p>
              ) : null}
              {passwordMutation.error ? (
                <p className="text-xs text-critical">
                  {passwordMutation.error.message}
                </p>
              ) : null}
              <div className="flex flex-wrap gap-2">
                <Button
                  variant="outline"
                  onClick={() => passwordMutation.mutate()}
                  disabled={!passwordValid || passwordMutation.isPending}
                >
                  {passwordMutation.isPending ? (
                    <LoaderCircle
                      className="animate-spin"
                      data-icon="inline-start"
                    />
                  ) : (
                    <KeyRound data-icon="inline-start" />
                  )}
                  {word(locale, 'Parolayı değiştir', 'Change password')}
                </Button>
                {data.user ? (
                  <Button variant="ghost" onClick={onLogout}>
                    <LogOut data-icon="inline-start" />{' '}
                    {word(locale, 'Çıkış yap', 'Sign out')}
                  </Button>
                ) : null}
              </div>
            </CardContent>
          </Card>
        </div>
      </div>

      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        {engineCards.map((item) => (
          <Card key={item.label} className="bg-card/82">
            <CardHeader className="flex-row items-start justify-between">
              <span className="grid size-10 place-items-center rounded-xl bg-muted text-muted-foreground">
                <item.icon className="size-5" />
              </span>
              <Badge
                variant="outline"
                className={item.healthy ? 'text-healthy' : 'text-warning'}
              >
                {item.healthy
                  ? word(locale, 'Hazır', 'Ready')
                  : word(locale, 'Yapılandır', 'Configure')}
              </Badge>
            </CardHeader>
            <CardContent>
              <p className="text-xs text-muted-foreground">{item.label}</p>
              <p className="mt-2 break-all font-mono text-sm font-semibold">
                {item.value}
              </p>
              <p className="mt-3 text-xs leading-5 text-muted-foreground">
                {item.note}
              </p>
            </CardContent>
          </Card>
        ))}
      </div>

      <Alert className="border-primary/20 bg-primary/5">
        <ShieldAlert />
        <AlertTitle>
          {word(locale, 'Güvenli LAN kullanımı', 'Secure LAN usage')}
        </AlertTitle>
        <AlertDescription>
          {word(
            locale,
            'LAN erişimi açıldığında kimlik doğrulama kapatılamaz. Parola yalnızca scrypt özeti olarak tutulur, oturum belirteçlerinin yalnızca SHA-256 özeti SQLite’a yazılır. Güvenilmeyen ağlarda TLS sağlayan bir ters proxy kullanın.',
            'Authentication cannot be disabled while LAN access is enabled. Passwords are stored only as scrypt hashes, and only SHA-256 hashes of session tokens are written to SQLite. Use a TLS-terminating reverse proxy on untrusted networks.',
          )}
        </AlertDescription>
      </Alert>

      {isAdmin ? <AdminPanel locale={locale} onSaved={onSaved} /> : null}
    </div>
  );
}

export function SettingsPanel({
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
  const settingsQuery = useQuery({
    queryKey: ['settings'],
    queryFn: () => apiRequest<SettingsResponse>('/api/settings'),
    staleTime: 15_000,
  });

  if (settingsQuery.isPending) {
    return (
      <div className="grid min-h-52 place-items-center">
        <LoaderCircle className="size-6 animate-spin text-primary" />
      </div>
    );
  }
  if (settingsQuery.error || !settingsQuery.data) {
    return (
      <Alert variant="destructive">
        <AlertCircle />
        <AlertTitle>
          {word(locale, 'Ayarlar yüklenemedi', 'Could not load settings')}
        </AlertTitle>
        <AlertDescription>{settingsQuery.error?.message}</AlertDescription>
      </Alert>
    );
  }
  return (
    <SettingsEditor
      key={settingsQuery.data.settings.updatedAt}
      data={settingsQuery.data}
      health={health}
      locale={locale}
      onLogout={onLogout}
      onSaved={onSaved}
    />
  );
}
