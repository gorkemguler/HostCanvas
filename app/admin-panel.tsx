'use client';

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import {
  BellRing,
  CheckCircle2,
  DatabaseBackup,
  Download,
  History,
  KeyRound,
  LoaderCircle,
  Play,
  Plus,
  Send,
  ShieldCheck,
  Trash2,
  Users,
  XCircle,
} from 'lucide-react';
import { useState } from 'react';

import { apiEndpoint, apiRequest } from '@/app/client-api';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { Badge } from '@/components/ui/badge';
import { Button, buttonVariants } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
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
import { Switch } from '@/components/ui/switch';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';

type Locale = 'tr' | 'en';
type Role = 'admin' | 'operator' | 'viewer';
type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

type User = {
  id: string;
  username: string;
  displayName: string;
  role: Role;
  enabled: boolean;
  createdAt: string;
  updatedAt: string;
};

type NotificationChannel = {
  id: string;
  name: string;
  kind: 'generic' | 'slack';
  endpoint: string;
  minSeverity: Severity;
  enabled: boolean;
  createdAt: string;
  updatedAt: string;
};

type Delivery = {
  id: string;
  channelName: string;
  eventType: string;
  status: 'succeeded' | 'failed';
  responseCode: number | null;
  errorMessage: string | null;
  createdAt: string;
};

type AuditEvent = {
  id: string;
  actor: string;
  action: string;
  targetType: string;
  targetId: string | null;
  summary: string;
  sourceIp: string | null;
  createdAt: string;
};

type MaintenanceSettings = {
  scanRetentionDays: number;
  artifactRetentionDays: number;
  backupRetentionCount: number;
  backupIntervalHours: number;
  updatedAt: string;
};

type Backup = { name: string; size: number; createdAt: string };

function word(locale: Locale, turkish: string, english: string) {
  return locale === 'en' ? english : turkish;
}

function timestamp(locale: Locale, value: string) {
  return new Intl.DateTimeFormat(locale === 'en' ? 'en-GB' : 'tr-TR', {
    dateStyle: 'short',
    timeStyle: 'short',
  }).format(new Date(value));
}

function byteSize(value: number) {
  if (value < 1024) return `${value} B`;
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KB`;
  return `${(value / 1024 / 1024).toFixed(1)} MB`;
}

function ErrorText({ error }: { error: Error | null }) {
  return error ? (
    <p className="text-xs text-critical">{error.message}</p>
  ) : null;
}

function TeamTab({
  locale,
  onSaved,
}: {
  locale: Locale;
  onSaved: (message: string) => void;
}) {
  const queryClient = useQueryClient();
  const [username, setUsername] = useState('');
  const [displayName, setDisplayName] = useState('');
  const [password, setPassword] = useState('');
  const [role, setRole] = useState<Role>('viewer');
  const [resetUser, setResetUser] = useState<User | null>(null);
  const [resetPassword, setResetPassword] = useState('');
  const usersQuery = useQuery({
    queryKey: ['admin-users'],
    queryFn: () => apiRequest<{ users: User[] }>('/api/users'),
  });

  const updateMutation = useMutation({
    mutationFn: ({
      id,
      input,
    }: {
      id: string;
      input: Partial<Pick<User, 'role' | 'enabled' | 'displayName'>>;
    }) =>
      apiRequest(`/api/users/${id}`, {
        method: 'PATCH',
        body: JSON.stringify(input),
      }),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ['admin-users'] });
      onSaved(
        word(locale, 'Kullanıcı yetkisi güncellendi.', 'User access updated.'),
      );
    },
  });

  const createMutation = useMutation({
    mutationFn: () =>
      apiRequest('/api/users', {
        method: 'POST',
        body: JSON.stringify({ username, displayName, password, role }),
      }),
    onSuccess: async () => {
      setUsername('');
      setDisplayName('');
      setPassword('');
      setRole('viewer');
      await queryClient.invalidateQueries({ queryKey: ['admin-users'] });
      onSaved(word(locale, 'Kullanıcı oluşturuldu.', 'User created.'));
    },
  });

  const resetMutation = useMutation({
    mutationFn: () =>
      apiRequest(`/api/users/${resetUser?.id}/password`, {
        method: 'POST',
        body: JSON.stringify({ password: resetPassword }),
      }),
    onSuccess: () => {
      setResetUser(null);
      setResetPassword('');
      onSaved(
        word(locale, 'Kullanıcı parolası sıfırlandı.', 'User password reset.'),
      );
    },
  });

  return (
    <div className="space-y-4">
      <Card className="bg-card/82">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-sm">
            <Users className="size-4 text-primary" />
            {word(locale, 'Ekip erişimi', 'Team access')}
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid gap-3 md:grid-cols-[1fr_1fr_1fr_140px_auto]">
            <Input
              aria-label={word(locale, 'Kullanıcı adı', 'Username')}
              placeholder={word(locale, 'Kullanıcı adı', 'Username')}
              value={username}
              onChange={(event) => setUsername(event.target.value)}
            />
            <Input
              aria-label={word(locale, 'Görünen ad', 'Display name')}
              placeholder={word(locale, 'Görünen ad', 'Display name')}
              value={displayName}
              onChange={(event) => setDisplayName(event.target.value)}
            />
            <Input
              aria-label={word(locale, 'Geçici parola', 'Temporary password')}
              type="password"
              placeholder={word(
                locale,
                'Geçici parola (12+)',
                'Temporary password (12+)',
              )}
              value={password}
              onChange={(event) => setPassword(event.target.value)}
            />
            <NativeSelect
              aria-label={word(locale, 'Rol', 'Role')}
              value={role}
              onChange={(event) => setRole(event.target.value as Role)}
            >
              <NativeSelectOption value="viewer">Viewer</NativeSelectOption>
              <NativeSelectOption value="operator">Operator</NativeSelectOption>
              <NativeSelectOption value="admin">Admin</NativeSelectOption>
            </NativeSelect>
            <Button
              onClick={() => createMutation.mutate()}
              disabled={
                username.length < 3 ||
                password.length < 12 ||
                createMutation.isPending
              }
            >
              {createMutation.isPending ? (
                <LoaderCircle className="animate-spin" />
              ) : (
                <Plus />
              )}{' '}
              {word(locale, 'Ekle', 'Add')}
            </Button>
          </div>
          <ErrorText
            error={
              usersQuery.error || createMutation.error || updateMutation.error
            }
          />
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>{word(locale, 'Kullanıcı', 'User')}</TableHead>
                <TableHead>{word(locale, 'Rol', 'Role')}</TableHead>
                <TableHead>{word(locale, 'Durum', 'Status')}</TableHead>
                <TableHead className="text-right">
                  {word(locale, 'İşlem', 'Action')}
                </TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {usersQuery.data?.users.map((user) => (
                <TableRow key={user.id}>
                  <TableCell>
                    <p className="font-medium">
                      {user.displayName || user.username}
                    </p>
                    <p className="text-xs text-muted-foreground">
                      @{user.username}
                    </p>
                  </TableCell>
                  <TableCell>
                    <NativeSelect
                      aria-label={`${user.username} ${word(locale, 'rolü', 'role')}`}
                      className="w-32"
                      value={user.role}
                      disabled={updateMutation.isPending}
                      onChange={(event) =>
                        updateMutation.mutate({
                          id: user.id,
                          input: { role: event.target.value as Role },
                        })
                      }
                    >
                      <NativeSelectOption value="admin">
                        Admin
                      </NativeSelectOption>
                      <NativeSelectOption value="operator">
                        Operator
                      </NativeSelectOption>
                      <NativeSelectOption value="viewer">
                        Viewer
                      </NativeSelectOption>
                    </NativeSelect>
                  </TableCell>
                  <TableCell>
                    <div className="flex items-center gap-2">
                      <Switch
                        aria-label={`${user.username} ${word(locale, 'hesap durumu', 'account status')}`}
                        checked={user.enabled}
                        disabled={updateMutation.isPending}
                        onCheckedChange={(enabled) =>
                          updateMutation.mutate({
                            id: user.id,
                            input: { enabled },
                          })
                        }
                      />
                      <span className="text-xs text-muted-foreground">
                        {user.enabled
                          ? word(locale, 'Etkin', 'Enabled')
                          : word(locale, 'Kapalı', 'Disabled')}
                      </span>
                    </div>
                  </TableCell>
                  <TableCell className="text-right">
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={() => setResetUser(user)}
                    >
                      <KeyRound />
                      {word(locale, 'Parola', 'Password')}
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
          {usersQuery.isPending ? (
            <LoaderCircle className="mx-auto animate-spin text-primary" />
          ) : null}
          <p className="text-xs text-muted-foreground">
            {word(
              locale,
              'Admin tüm ayarları yönetir; operator tarama ve incident işlemlerini yapar; viewer yalnızca görüntüler.',
              'Admins manage all settings; operators handle scans and incidents; viewers have read-only access.',
            )}
          </p>
        </CardContent>
      </Card>

      <Dialog
        open={Boolean(resetUser)}
        onOpenChange={(open) => {
          if (!open) {
            setResetUser(null);
            setResetPassword('');
          }
        }}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle>
              {word(locale, 'Parolayı sıfırla', 'Reset password')}
            </DialogTitle>
            <DialogDescription>
              @{resetUser?.username} ·{' '}
              {word(
                locale,
                'Mevcut oturumları sonlandırır.',
                'Ends existing sessions.',
              )}
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-2">
            <Label htmlFor="reset-password">
              {word(locale, 'Yeni parola', 'New password')}
            </Label>
            <Input
              id="reset-password"
              type="password"
              value={resetPassword}
              onChange={(event) => setResetPassword(event.target.value)}
              autoComplete="new-password"
            />
          </div>
          <ErrorText error={resetMutation.error} />
          <DialogFooter>
            <Button
              onClick={() => resetMutation.mutate()}
              disabled={resetPassword.length < 12 || resetMutation.isPending}
            >
              {resetMutation.isPending ? (
                <LoaderCircle className="animate-spin" />
              ) : (
                <KeyRound />
              )}
              {word(locale, 'Sıfırla', 'Reset')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

function NotificationsTab({
  locale,
  onSaved,
}: {
  locale: Locale;
  onSaved: (message: string) => void;
}) {
  const queryClient = useQueryClient();
  const [name, setName] = useState('');
  const [kind, setKind] = useState<'generic' | 'slack'>('generic');
  const [webhookUrl, setWebhookUrl] = useState('');
  const [minSeverity, setMinSeverity] = useState<Severity>('high');
  const channelsQuery = useQuery({
    queryKey: ['admin-notifications'],
    queryFn: () =>
      apiRequest<{ channels: NotificationChannel[]; deliveries: Delivery[] }>(
        '/api/notifications/channels',
      ),
  });
  const refresh = () =>
    queryClient.invalidateQueries({ queryKey: ['admin-notifications'] });
  const createMutation = useMutation({
    mutationFn: () =>
      apiRequest('/api/notifications/channels', {
        method: 'POST',
        body: JSON.stringify({ name, kind, webhookUrl, minSeverity }),
      }),
    onSuccess: async () => {
      setName('');
      setWebhookUrl('');
      await refresh();
      onSaved(
        word(locale, 'Bildirim kanalı eklendi.', 'Notification channel added.'),
      );
    },
  });
  const updateMutation = useMutation({
    mutationFn: ({
      id,
      input,
    }: {
      id: string;
      input: Partial<NotificationChannel>;
    }) =>
      apiRequest(`/api/notifications/channels/${id}`, {
        method: 'PATCH',
        body: JSON.stringify(input),
      }),
    onSuccess: refresh,
  });
  const deleteMutation = useMutation({
    mutationFn: (id: string) =>
      apiRequest(`/api/notifications/channels/${id}`, { method: 'DELETE' }),
    onSuccess: refresh,
  });
  const testMutation = useMutation({
    mutationFn: (id: string) =>
      apiRequest(`/api/notifications/channels/${id}/test`, {
        method: 'POST',
        body: '{}',
      }),
    onSuccess: () =>
      onSaved(
        word(locale, 'Test bildirimi gönderildi.', 'Test notification sent.'),
      ),
    onSettled: refresh,
  });
  const mutationError =
    channelsQuery.error ||
    createMutation.error ||
    updateMutation.error ||
    deleteMutation.error ||
    testMutation.error;

  return (
    <div className="space-y-4">
      <Card className="bg-card/82">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-sm">
            <BellRing className="size-4 text-primary" />
            {word(locale, 'Webhook bildirimleri', 'Webhook notifications')}
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid gap-3 md:grid-cols-[1fr_140px_2fr_140px_auto]">
            <Input
              aria-label={word(locale, 'Kanal adı', 'Channel name')}
              placeholder={word(locale, 'Kanal adı', 'Channel name')}
              value={name}
              onChange={(event) => setName(event.target.value)}
            />
            <NativeSelect
              aria-label={word(locale, 'Tür', 'Kind')}
              value={kind}
              onChange={(event) =>
                setKind(event.target.value as 'generic' | 'slack')
              }
            >
              <NativeSelectOption value="generic">Generic</NativeSelectOption>
              <NativeSelectOption value="slack">Slack</NativeSelectOption>
            </NativeSelect>
            <Input
              aria-label="Webhook URL"
              type="url"
              placeholder="https://…"
              value={webhookUrl}
              onChange={(event) => setWebhookUrl(event.target.value)}
            />
            <NativeSelect
              aria-label={word(locale, 'Asgari önem', 'Minimum severity')}
              value={minSeverity}
              onChange={(event) =>
                setMinSeverity(event.target.value as Severity)
              }
            >
              <NativeSelectOption value="critical">Critical</NativeSelectOption>
              <NativeSelectOption value="high">High</NativeSelectOption>
              <NativeSelectOption value="medium">Medium</NativeSelectOption>
              <NativeSelectOption value="low">Low</NativeSelectOption>
              <NativeSelectOption value="info">Info</NativeSelectOption>
            </NativeSelect>
            <Button
              onClick={() => createMutation.mutate()}
              disabled={
                !name.trim() || !webhookUrl.trim() || createMutation.isPending
              }
            >
              {createMutation.isPending ? (
                <LoaderCircle className="animate-spin" />
              ) : (
                <Plus />
              )}
              {word(locale, 'Ekle', 'Add')}
            </Button>
          </div>
          <p className="text-xs text-muted-foreground">
            {word(
              locale,
              'Webhook adresi şifreli saklanır; yalnızca HTTPS/443 ve public hedeflere izin verilir.',
              'Webhook URLs are encrypted at rest; only HTTPS/443 public targets are allowed.',
            )}
          </p>
          <ErrorText error={mutationError} />
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>{word(locale, 'Kanal', 'Channel')}</TableHead>
                <TableHead>{word(locale, 'Eşik', 'Threshold')}</TableHead>
                <TableHead>{word(locale, 'Etkin', 'Enabled')}</TableHead>
                <TableHead className="text-right">
                  {word(locale, 'İşlem', 'Action')}
                </TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {channelsQuery.data?.channels.map((channel) => (
                <TableRow key={channel.id}>
                  <TableCell>
                    <p className="font-medium">{channel.name}</p>
                    <p className="text-xs text-muted-foreground">
                      {channel.kind} · {channel.endpoint}
                    </p>
                  </TableCell>
                  <TableCell>
                    <NativeSelect
                      aria-label={`${channel.name} ${word(locale, 'önem eşiği', 'severity threshold')}`}
                      className="w-32"
                      value={channel.minSeverity}
                      onChange={(event) =>
                        updateMutation.mutate({
                          id: channel.id,
                          input: {
                            minSeverity: event.target.value as Severity,
                          },
                        })
                      }
                    >
                      <NativeSelectOption value="critical">
                        Critical
                      </NativeSelectOption>
                      <NativeSelectOption value="high">High</NativeSelectOption>
                      <NativeSelectOption value="medium">
                        Medium
                      </NativeSelectOption>
                      <NativeSelectOption value="low">Low</NativeSelectOption>
                      <NativeSelectOption value="info">Info</NativeSelectOption>
                    </NativeSelect>
                  </TableCell>
                  <TableCell>
                    <Switch
                      aria-label={`${channel.name} ${word(locale, 'bildirim durumu', 'notification status')}`}
                      checked={channel.enabled}
                      onCheckedChange={(enabled) =>
                        updateMutation.mutate({
                          id: channel.id,
                          input: { enabled },
                        })
                      }
                    />
                  </TableCell>
                  <TableCell>
                    <div className="flex justify-end gap-2">
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={() => testMutation.mutate(channel.id)}
                        disabled={testMutation.isPending}
                      >
                        <Send />
                        {word(locale, 'Test', 'Test')}
                      </Button>
                      <Button
                        size="icon-sm"
                        variant="ghost"
                        aria-label={word(locale, 'Sil', 'Delete')}
                        onClick={() => {
                          if (
                            window.confirm(
                              word(
                                locale,
                                `${channel.name} kanalı silinsin mi?`,
                                `Delete ${channel.name}?`,
                              ),
                            )
                          )
                            deleteMutation.mutate(channel.id);
                        }}
                      >
                        <Trash2 />
                      </Button>
                    </div>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      <Card className="bg-card/82">
        <CardHeader>
          <CardTitle className="text-sm">
            {word(locale, 'Son teslimatlar', 'Recent deliveries')}
          </CardTitle>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>{word(locale, 'Kanal', 'Channel')}</TableHead>
                <TableHead>{word(locale, 'Olay', 'Event')}</TableHead>
                <TableHead>{word(locale, 'Sonuç', 'Result')}</TableHead>
                <TableHead>{word(locale, 'Zaman', 'Time')}</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {channelsQuery.data?.deliveries.map((delivery) => (
                <TableRow key={delivery.id}>
                  <TableCell>{delivery.channelName}</TableCell>
                  <TableCell className="font-mono text-xs">
                    {delivery.eventType}
                  </TableCell>
                  <TableCell>
                    <Badge
                      variant="outline"
                      className={
                        delivery.status === 'succeeded'
                          ? 'text-healthy'
                          : 'text-critical'
                      }
                    >
                      {delivery.status === 'succeeded' ? (
                        <CheckCircle2 />
                      ) : (
                        <XCircle />
                      )}
                      {delivery.status}
                      {delivery.responseCode
                        ? ` · ${delivery.responseCode}`
                        : ''}
                    </Badge>
                    {delivery.errorMessage ? (
                      <p
                        className="mt-1 max-w-80 truncate text-xs text-muted-foreground"
                        title={delivery.errorMessage}
                      >
                        {delivery.errorMessage}
                      </p>
                    ) : null}
                  </TableCell>
                  <TableCell className="text-xs text-muted-foreground">
                    {timestamp(locale, delivery.createdAt)}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  );
}

function AuditTab({ locale }: { locale: Locale }) {
  const auditQuery = useQuery({
    queryKey: ['admin-audit'],
    queryFn: () =>
      apiRequest<{ events: AuditEvent[]; total: number }>(
        '/api/audit?limit=100',
      ),
    refetchInterval: 30_000,
  });
  return (
    <Card className="bg-card/82">
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-sm">
          <History className="size-4 text-primary" />
          {word(locale, 'Denetim kaydı', 'Audit log')}{' '}
          {auditQuery.data ? (
            <Badge variant="outline">{auditQuery.data.total}</Badge>
          ) : null}
        </CardTitle>
      </CardHeader>
      <CardContent>
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>{word(locale, 'Zaman', 'Time')}</TableHead>
              <TableHead>{word(locale, 'Aktör', 'Actor')}</TableHead>
              <TableHead>{word(locale, 'Eylem', 'Action')}</TableHead>
              <TableHead>{word(locale, 'Açıklama', 'Summary')}</TableHead>
              <TableHead>IP</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {auditQuery.data?.events.map((event) => (
              <TableRow key={event.id}>
                <TableCell className="text-xs text-muted-foreground">
                  {timestamp(locale, event.createdAt)}
                </TableCell>
                <TableCell>{event.actor}</TableCell>
                <TableCell className="font-mono text-xs">
                  {event.action}
                </TableCell>
                <TableCell>
                  <p className="max-w-lg whitespace-normal">{event.summary}</p>
                </TableCell>
                <TableCell className="font-mono text-xs text-muted-foreground">
                  {event.sourceIp || '—'}
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
        {auditQuery.isPending ? (
          <LoaderCircle className="mx-auto mt-5 animate-spin text-primary" />
        ) : null}
        <ErrorText error={auditQuery.error} />
      </CardContent>
    </Card>
  );
}

function MaintenanceTab({
  locale,
  onSaved,
}: {
  locale: Locale;
  onSaved: (message: string) => void;
}) {
  const queryClient = useQueryClient();
  const maintenanceQuery = useQuery({
    queryKey: ['admin-maintenance'],
    queryFn: () =>
      apiRequest<{ settings: MaintenanceSettings; backups: Backup[] }>(
        '/api/maintenance',
      ),
  });
  const [draft, setDraft] = useState<MaintenanceSettings | null>(null);
  const values = draft || maintenanceQuery.data?.settings;
  const refresh = () =>
    queryClient.invalidateQueries({ queryKey: ['admin-maintenance'] });
  const saveMutation = useMutation({
    mutationFn: () =>
      apiRequest('/api/maintenance', {
        method: 'PATCH',
        body: JSON.stringify(values),
      }),
    onSuccess: async () => {
      setDraft(null);
      await refresh();
      onSaved(
        word(
          locale,
          'Saklama ayarları kaydedildi.',
          'Retention settings saved.',
        ),
      );
    },
  });
  const runMutation = useMutation({
    mutationFn: () =>
      apiRequest('/api/maintenance/run', { method: 'POST', body: '{}' }),
    onSuccess: async () => {
      await refresh();
      onSaved(word(locale, 'Bakım tamamlandı.', 'Maintenance completed.'));
    },
  });
  const backupMutation = useMutation({
    mutationFn: () =>
      apiRequest('/api/backups', { method: 'POST', body: '{}' }),
    onSuccess: async () => {
      await refresh();
      onSaved(
        word(
          locale,
          'Doğrulanmış yedek oluşturuldu.',
          'Verified backup created.',
        ),
      );
    },
  });
  const set = (key: keyof MaintenanceSettings, value: string) =>
    values && setDraft({ ...values, [key]: Number(value) });
  const mutationError =
    maintenanceQuery.error ||
    saveMutation.error ||
    runMutation.error ||
    backupMutation.error;

  return (
    <div className="space-y-4">
      <Card className="bg-card/82">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-sm">
            <DatabaseBackup className="size-4 text-primary" />
            {word(locale, 'Saklama ve bakım', 'Retention and maintenance')}
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          {values ? (
            <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
              <div className="space-y-2">
                <Label htmlFor="maintenance-scan-retention">
                  {word(locale, 'Tarama geçmişi (gün)', 'Scan history (days)')}
                </Label>
                <Input
                  id="maintenance-scan-retention"
                  type="number"
                  min="7"
                  max="3650"
                  value={values.scanRetentionDays}
                  onChange={(event) =>
                    set('scanRetentionDays', event.target.value)
                  }
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="maintenance-artifact-retention">
                  {word(
                    locale,
                    'Artifact saklama (gün)',
                    'Artifact retention (days)',
                  )}
                </Label>
                <Input
                  id="maintenance-artifact-retention"
                  type="number"
                  min="1"
                  max="3650"
                  value={values.artifactRetentionDays}
                  onChange={(event) =>
                    set('artifactRetentionDays', event.target.value)
                  }
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="maintenance-backup-count">
                  {word(locale, 'Saklanan yedek', 'Backups retained')}
                </Label>
                <Input
                  id="maintenance-backup-count"
                  type="number"
                  min="1"
                  max="100"
                  value={values.backupRetentionCount}
                  onChange={(event) =>
                    set('backupRetentionCount', event.target.value)
                  }
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="maintenance-backup-interval">
                  {word(
                    locale,
                    'Yedekleme aralığı (saat)',
                    'Backup interval (hours)',
                  )}
                </Label>
                <Input
                  id="maintenance-backup-interval"
                  type="number"
                  min="1"
                  max="168"
                  value={values.backupIntervalHours}
                  onChange={(event) =>
                    set('backupIntervalHours', event.target.value)
                  }
                />
              </div>
            </div>
          ) : (
            <LoaderCircle className="animate-spin text-primary" />
          )}
          <div className="flex flex-wrap gap-2">
            <Button
              onClick={() => saveMutation.mutate()}
              disabled={!draft || saveMutation.isPending}
            >
              {saveMutation.isPending ? (
                <LoaderCircle className="animate-spin" />
              ) : (
                <ShieldCheck />
              )}
              {word(locale, 'Ayarları kaydet', 'Save settings')}
            </Button>
            <Button
              variant="outline"
              onClick={() => runMutation.mutate()}
              disabled={runMutation.isPending}
            >
              {runMutation.isPending ? (
                <LoaderCircle className="animate-spin" />
              ) : (
                <Play />
              )}
              {word(locale, 'Bakımı çalıştır', 'Run maintenance')}
            </Button>
            <Button
              variant="outline"
              onClick={() => backupMutation.mutate()}
              disabled={backupMutation.isPending}
            >
              {backupMutation.isPending ? (
                <LoaderCircle className="animate-spin" />
              ) : (
                <DatabaseBackup />
              )}
              {word(locale, 'Şimdi yedekle', 'Back up now')}
            </Button>
          </div>
          <ErrorText error={mutationError} />
        </CardContent>
      </Card>
      <Card className="bg-card/82">
        <CardHeader>
          <CardTitle className="text-sm">
            {word(locale, 'Veritabanı yedekleri', 'Database backups')}
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>{word(locale, 'Dosya', 'File')}</TableHead>
                <TableHead>{word(locale, 'Boyut', 'Size')}</TableHead>
                <TableHead>{word(locale, 'Oluşturulma', 'Created')}</TableHead>
                <TableHead className="text-right">
                  {word(locale, 'İndir', 'Download')}
                </TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {maintenanceQuery.data?.backups.map((backup) => (
                <TableRow key={backup.name}>
                  <TableCell className="font-mono text-xs">
                    {backup.name}
                  </TableCell>
                  <TableCell>{byteSize(backup.size)}</TableCell>
                  <TableCell className="text-xs text-muted-foreground">
                    {timestamp(locale, backup.createdAt)}
                  </TableCell>
                  <TableCell className="text-right">
                    <a
                      href={apiEndpoint(`/api/backups/${backup.name}`)}
                      download={backup.name}
                      aria-label={word(
                        locale,
                        'Yedeği indir',
                        'Download backup',
                      )}
                      className={buttonVariants({
                        variant: 'ghost',
                        size: 'icon-sm',
                      })}
                    >
                      <Download />
                      <span className="sr-only">
                        {word(locale, 'Yedeği indir', 'Download backup')}
                      </span>
                    </a>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
          <Alert>
            <DatabaseBackup />
            <AlertTitle>{word(locale, 'Geri yükleme', 'Restore')}</AlertTitle>
            <AlertDescription>
              {word(
                locale,
                'Uygulamayı durdurduktan sonra `npm run restore -- /yedek/dosyası.db --confirm` komutunu kullanın. Komut mevcut veritabanını ayrıca acil durum yedeğine alır.',
                'After stopping the app, run `npm run restore -- /path/to/backup.db --confirm`. The command also creates an emergency copy of the current database.',
              )}
            </AlertDescription>
          </Alert>
        </CardContent>
      </Card>
    </div>
  );
}

export function AdminPanel({
  locale,
  onSaved,
}: {
  locale: Locale;
  onSaved: (message: string) => void;
}) {
  return (
    <Card className="border-primary/15 bg-card/82">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <ShieldCheck className="size-5 text-primary" />
          {word(locale, 'Yönetim merkezi', 'Administration')}
        </CardTitle>
      </CardHeader>
      <CardContent>
        <Tabs defaultValue="team">
          <TabsList className="mb-4 max-w-full overflow-x-auto" variant="line">
            <TabsTrigger value="team">
              <Users />
              {word(locale, 'Ekip', 'Team')}
            </TabsTrigger>
            <TabsTrigger value="notifications">
              <BellRing />
              {word(locale, 'Bildirimler', 'Notifications')}
            </TabsTrigger>
            <TabsTrigger value="audit">
              <History />
              Audit
            </TabsTrigger>
            <TabsTrigger value="data">
              <DatabaseBackup />
              {word(locale, 'Veri', 'Data')}
            </TabsTrigger>
          </TabsList>
          <TabsContent value="team">
            <TeamTab locale={locale} onSaved={onSaved} />
          </TabsContent>
          <TabsContent value="notifications">
            <NotificationsTab locale={locale} onSaved={onSaved} />
          </TabsContent>
          <TabsContent value="audit">
            <AuditTab locale={locale} />
          </TabsContent>
          <TabsContent value="data">
            <MaintenanceTab locale={locale} onSaved={onSaved} />
          </TabsContent>
        </Tabs>
      </CardContent>
    </Card>
  );
}
