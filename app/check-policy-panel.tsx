'use client';

import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { LoaderCircle, ShieldCheck } from 'lucide-react';
import { apiRequest } from '@/app/client-api';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { Switch } from '@/components/ui/switch';
import { Button } from '@/components/ui/button';

type Policy = {
  hstsMinMaxAgeSeconds: number;
  hstsRequireSubdomains: boolean;
  cookieSecureRequired: boolean;
  sessionCookieNames: string[];
  caaRequired: boolean;
  caaAllowedIssuers: string[];
  scanHealthEnabled: boolean;
  scanFailureThreshold: number;
};
type PolicyResponse = {
  policy: Policy;
  updatedAt: string | null;
  dnssecResolver: string | null;
  publicDnsResolver: string | null;
};
type Props = {
  locale: 'tr' | 'en';
  isAdmin: boolean;
  onSaved: (message: string) => void;
};

function PolicyEditor({
  data,
  locale,
  isAdmin,
  onSaved,
}: Props & { data: PolicyResponse }) {
  const word = (tr: string, en: string) => (locale === 'en' ? en : tr);
  const [policy, setPolicy] = useState(data.policy);
  const [names, setNames] = useState(data.policy.sessionCookieNames.join('\n'));
  const [issuers, setIssuers] = useState(
    data.policy.caaAllowedIssuers.join('\n'),
  );
  const client = useQueryClient();
  const list = (value: string) => value.split(/[\s,]+/).filter(Boolean);
  const save = useMutation({
    mutationFn: () =>
      apiRequest<PolicyResponse>('/api/check-policy', {
        method: 'PATCH',
        body: JSON.stringify({
          ...policy,
          sessionCookieNames: list(names),
          caaAllowedIssuers: list(issuers),
        }),
      }),
    onSuccess: async () => {
      await Promise.all([
        client.invalidateQueries({ queryKey: ['check-policy'] }),
        client.invalidateQueries({ queryKey: ['checks'] }),
      ]);
      onSaved(
        word(
          'Kontrol politikası kaydedildi; sonraki taramada uygulanır.',
          'Check policy saved; applies on the next scan.',
        ),
      );
    },
  });
  const switches: {
    key:
      | 'hstsRequireSubdomains'
      | 'cookieSecureRequired'
      | 'caaRequired'
      | 'scanHealthEnabled';
    label: string;
    note: string;
  }[] = [
    {
      key: 'hstsRequireSubdomains',
      label: word(
        'HSTS includeSubDomains zorunlu',
        'Require HSTS includeSubDomains',
      ),
      note: word(
        'Yalnızca tüm alt domain’ler HTTPS kullanıyorsa etkinleştirin.',
        'Enable only if every subdomain is intended to use HTTPS.',
      ),
    },
    {
      key: 'cookieSecureRequired',
      label: word('Cookie Secure kontrolü', 'Check cookie Secure flag'),
      note: word(
        'Yalnızca gözlemlenen cookie adları saklanır; değerleri tutulmaz.',
        'Only observed cookie names are recorded, never their values.',
      ),
    },
    {
      key: 'caaRequired',
      label: word(
        'CAA issuance politikası zorunlu',
        'Require a CAA issuance policy',
      ),
      note: word(
        'Varsayılan kapalıdır; CAA eksikliği tek başına kritik zafiyet değildir.',
        'Off by default; missing CAA alone is not a critical vulnerability.',
      ),
    },
    {
      key: 'scanHealthEnabled',
      label: word('Tarama sağlığı incident’ı', 'Scan health incident'),
      note: word(
        'Art arda failed/partial sonuçlarda açılır; tam başarılı taramada çözülür.',
        'Opens after consecutive failed/partial results; a complete scan resolves it.',
      ),
    },
  ];
  const valid =
    Number.isSafeInteger(policy.hstsMinMaxAgeSeconds) &&
    policy.hstsMinMaxAgeSeconds >= 0 &&
    policy.hstsMinMaxAgeSeconds <= 63072000 &&
    Number.isSafeInteger(policy.scanFailureThreshold) &&
    policy.scanFailureThreshold >= 1 &&
    policy.scanFailureThreshold <= 20 &&
    list(names).length <= 20 &&
    list(issuers).length <= 20;
  return (
    <Card className="bg-card/82">
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-sm">
          <ShieldCheck className="size-4 text-primary" />
          {word('Incident kontrol politikası', 'Incident check policy')}
        </CardTitle>
        <p className="text-xs leading-5 text-muted-foreground">
          {word(
            'Tüm varlıklara sonraki taramada uygulanır. Bir kontrolü kapatmak eski incident’ları otomatik çözmez.',
            'Applies to all assets on their next scan. Disabling a check does not automatically resolve old incidents.',
          )}
        </p>
      </CardHeader>
      <CardContent className="space-y-5">
        <div className="grid gap-5 lg:grid-cols-2">
          <div className="space-y-4">
            {switches.map(({ key, label, note }) => (
              <div
                key={key}
                className="flex items-start justify-between gap-4 rounded-xl border p-3"
              >
                <div>
                  <Label htmlFor={`policy-${key}`}>{label}</Label>
                  <p className="mt-1 text-xs leading-5 text-muted-foreground">
                    {note}
                  </p>
                </div>
                <Switch
                  id={`policy-${key}`}
                  aria-label={label}
                  checked={policy[key]}
                  disabled={!isAdmin || save.isPending}
                  onCheckedChange={(checked) =>
                    setPolicy({ ...policy, [key]: checked })
                  }
                />
              </div>
            ))}
          </div>
          <div className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="policy-hsts-age">
                {word(
                  'Minimum HSTS max-age (saniye)',
                  'Minimum HSTS max-age (seconds)',
                )}
              </Label>
              <Input
                id="policy-hsts-age"
                type="number"
                min={0}
                max={63072000}
                step={1}
                disabled={!isAdmin || save.isPending}
                value={
                  Number.isNaN(policy.hstsMinMaxAgeSeconds)
                    ? ''
                    : policy.hstsMinMaxAgeSeconds
                }
                onChange={(event) =>
                  setPolicy({
                    ...policy,
                    hstsMinMaxAgeSeconds: event.target.valueAsNumber,
                  })
                }
              />
              <p className="text-xs text-muted-foreground">
                {word(
                  '15552000 = 180 gün. Eşik 0 olsa da max-age=0 etkisiz politika sayılır.',
                  '15552000 = 180 days. max-age=0 is ineffective even if this threshold is 0.',
                )}
              </p>
            </div>
            <div className="space-y-2">
              <Label htmlFor="policy-session-cookies">
                {word(
                  'HttpOnly gerektiren oturum cookie adları',
                  'Session cookie names requiring HttpOnly',
                )}
              </Label>
              <Textarea
                id="policy-session-cookies"
                value={names}
                onChange={(event) => setNames(event.target.value)}
                placeholder={'session\nconnect.sid'}
                disabled={!isAdmin || save.isPending}
              />
              <p className="text-xs text-muted-foreground">
                {word(
                  'Her satırda bir tam ad; büyük/küçük harf duyarlı. Boş liste kontrolü kapatır. Gözlemlenmeyen cookie sağlıklı sayılmaz.',
                  'One exact, case-sensitive name per line. Empty disables this check. Unobserved cookies are not treated as healthy.',
                )}
              </p>
            </div>
            <div className="space-y-2">
              <Label htmlFor="policy-caa-issuers">
                {word(
                  'İzinli CAA issuer domain’leri',
                  'Allowed CAA issuer domains',
                )}
              </Label>
              <Textarea
                id="policy-caa-issuers"
                value={issuers}
                onChange={(event) => setIssuers(event.target.value)}
                placeholder="letsencrypt.org"
                disabled={!isAdmin || save.isPending}
              />
              <p className="text-xs text-muted-foreground">
                {word(
                  'Boşsa issuer kısıtı yoktur. Dolu liste issuance politikası da gerektirir; sertifika issuer CN alanıyla kıyaslanmaz.',
                  'Empty means no issuer restriction. A populated list also requires issuance policy; it is not compared to certificate issuer CN.',
                )}
              </p>
            </div>
            <div className="space-y-2">
              <Label htmlFor="policy-failure-threshold">
                {word(
                  'Ardışık başarısız/kısmi tarama eşiği',
                  'Consecutive failed/partial scan threshold',
                )}
              </Label>
              <Input
                id="policy-failure-threshold"
                type="number"
                min={1}
                max={20}
                step={1}
                value={
                  Number.isNaN(policy.scanFailureThreshold)
                    ? ''
                    : policy.scanFailureThreshold
                }
                disabled={!isAdmin || save.isPending}
                onChange={(event) =>
                  setPolicy({
                    ...policy,
                    scanFailureThreshold: event.target.valueAsNumber,
                  })
                }
              />
            </div>
          </div>
        </div>
        <div className="rounded-xl border bg-muted/30 p-3 text-xs leading-6">
          <p>
            {word('Public DNS / CAA:', 'Public DNS / CAA:')}{' '}
            <span className="font-mono">
              {data.publicDnsResolver ||
                word('Yapılandırılmadı', 'Not configured')}
            </span>
          </p>
          <p>
            DNSSEC (DNS-over-TLS):{' '}
            <span className="font-mono">
              {data.dnssecResolver ||
                word('Yapılandırılmadı', 'Not configured')}
            </span>
          </p>
          <p className="mt-1 text-muted-foreground">
            {word(
              'DNSSEC için sunucuda TLS_SENTINEL_DNSSEC_RESOLVER ayarlayın. Sorgu adları seçilen harici resolver’a gönderilir; sonuç onun doğrulama raporudur, yerel kriptografik zincir doğrulaması değildir.',
              'Set TLS_SENTINEL_DNSSEC_RESOLVER on the server for DNSSEC. Query names are sent to that external resolver; results are its validation report, not local cryptographic chain validation.',
            )}
          </p>
        </div>
        {save.error && (
          <p role="alert" className="text-sm text-critical">
            {save.error.message}
          </p>
        )}
        {isAdmin ? (
          <Button
            onClick={() => save.mutate()}
            disabled={!valid || save.isPending}
          >
            {save.isPending && <LoaderCircle className="size-4 animate-spin" />}
            {word('Kontrol politikasını kaydet', 'Save check policy')}
          </Button>
        ) : (
          <p className="text-xs text-muted-foreground">
            {word(
              'Yalnızca yöneticiler değiştirebilir.',
              'Only administrators can make changes.',
            )}
          </p>
        )}
      </CardContent>
    </Card>
  );
}

export function CheckPolicyPanel(props: Props) {
  const query = useQuery({
    queryKey: ['check-policy'],
    queryFn: () => apiRequest<PolicyResponse>('/api/check-policy'),
  });
  if (query.isPending)
    return (
      <output className="text-sm text-muted-foreground">
        {props.locale === 'en'
          ? 'Loading check policy…'
          : 'Kontrol politikası yükleniyor…'}
      </output>
    );
  if (query.error)
    return (
      <p role="alert" className="text-sm text-critical">
        {query.error.message}
      </p>
    );
  return (
    <PolicyEditor
      key={query.data.updatedAt || 'defaults'}
      {...props}
      data={query.data}
    />
  );
}
