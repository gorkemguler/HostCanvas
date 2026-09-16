# Yeni kontrol ekleme

HostCanvas’ta ağdan veri toplama ve alarm üretme birbirinden ayrıdır:

```text
Probe.collect(endpoint) → sürümlü observation
Rule.evaluate(observation, policy) → pass | fail | unknown
```

Bu ayrım sayesinde aynı TLS/DNS/HTTP gözlemi birçok rule tarafından yeniden kullanılabilir ve bir kuralın kullanıcı girdisiyle ağ erişimi başlatması engellenir.

## 1. Observation şemasını belirleyin

Yeni kontrol mevcut gözlemdeki alanlarla çalışabiliyorsa yeni probe yazmayın. Örneğin sertifika bitiş tarihi `observations.tls.certificate.validTo` altında zaten vardır.

Yeni veri gerekiyorsa `server/probes/` altında dar kapsamlı bir modül oluşturun. Probe:

- yalnızca scanner tarafından doğrulanıp sabitlenmiş hedefi kabul etmeli,
- timeout uygulamalı,
- kullanıcı kontrollü shell/flag/path çalıştırmamalı,
- sonucu JSON-serileştirilebilir, sürümlü ve boyutu sınırlı bir nesneye dönüştürmeli,
- başarısızlığı `unknown` üretebilecek şekilde açıklamalıdır.

## 2. Kuralı kataloğa ekleyin

`server/rules/index.mjs` içindeki `ruleCatalog` listesine stabil bir anahtar ekleyin:

```js
{
  key: 'dns.dangling_cname',
  title: 'Dangling CNAME tespit edildi',
  category: 'DNS',
  severity: 'high',
  source: 'Public DNS',
  enabled: true,
}
```

Kural anahtarı yayınlandıktan sonra yeniden adlandırılmamalıdır; incident kimliği bu anahtarı kullanır.

## 3. Değerlendirme üretin

Kural üç güvenilir durumdan birini dönmelidir:

- `pass`: Kontrol eksiksiz çalıştı ve risk yok. Mevcut incident kapanabilir.
- `fail`: Risk doğrulandı. Incident açılır veya aynı incident güncellenir.
- `unknown`: Probe eksik, timeout, parser uyumsuz veya kanıt yetersiz. Mevcut incident korunur.

Fail örneği:

```js
{
  ruleKey: 'dns.dangling_cname',
  status: 'fail',
  discriminator: 'target.example.net',
  severity: 'high',
  title: 'Dangling CNAME tespit edildi',
  description: 'CNAME hedefi public DNS üzerinde çözümlenemiyor.',
  evidence: {
    cname: 'target.example.net',
    resolver: '1.1.1.1',
  },
}
```

`discriminator`, aynı endpoint’te aynı kuralın birden çok bağımsız incident üretmesi gerektiğinde kullanılır. Sertifika bitiş eşiği gibi tek operasyonel sorunlarda discriminator kullanmayın; sertifika rotasyonu incident geçmişini parçalamamalıdır.

## 4. Reconciliation kurallarını koruyun

- Timeout veya `unknown` mevcut incident’ı çözmemeli.
- Dinamik scanner bulguları yalnızca ilgili scan bölümü eksiksizse “artık görünmüyor” diye kapatılmalı.
- Kanıt UI’ya HTML olarak basılmamalı; JSON/metin olarak escape edilmelidir.
- Severity değişimi aynı incident üzerinde güncellenmelidir.

## 5. Test ekleyin

En az şu senaryoları `tests/` altında doğrulayın:

1. Riskli gözlem `fail` üretir.
2. Sağlıklı, eksiksiz gözlem `pass` üretir.
3. Eksik/timeout gözlemi `unknown` üretir.
4. `fail → unknown` incident’ı açık tutar.
5. `fail → pass` incident’ı çözer.
6. `resolved → fail` aynı incident’ı yeniden açar.

Güvenlik hassas bir probe ekleniyorsa IDNA, private IP, IPv4-mapped IPv6, DNS rebinding, output limit ve subprocess timeout testlerini de ekleyin.
