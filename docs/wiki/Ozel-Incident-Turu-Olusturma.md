# Kendi incident türünü oluşturma

[English](https://github.com/gorkemguler/HostCanvas/wiki/Custom-Incident-Types) · [Wiki ana sayfa](https://github.com/gorkemguler/HostCanvas/wiki)

## Bugün nasıl çalışıyor?

HostCanvas’ta incident türü, **kodla tanımlanan bir kontrol kuralıdır**. Şu anda panelden kural yazma, YAML/JSON template yükleme veya otomatik plugin yükleme özelliği yoktur. Kontroller ekranı kataloğu gösterir; kullanıcının gönderdiği kodu çalıştırmaz. Kataloğa satır eklemek tek başına yeni kontrolü etkinleştirmez.

İzlenecek yol:

1. Mevcut tarama gözlemlerini kullanın; gerekli veri yoksa dar kapsamlı bir probe ekleyin.
2. `pass`, `fail` veya `unknown` döndüren saf bir değerlendirme fonksiyonu yazın.
3. `server/rules/index.mjs` içinde hem katalog kaydını ekleyin hem fonksiyonu çağırın.
4. Kural sonucunu ve incident yaşam döngüsünü test edin.
5. API’yi yeniden başlatın; Docker kullanıyorsanız image’ı yeniden derleyin. Yetkili bir test varlığında doğrulayın.

Aşağıdaki örneğin çalışır kodu ve testleri depoda bulunur. Örnek, uygulamada varsayılan olarak etkin değildir.

## Mimari ve değişiklik yapılacak yerler

```text
hostname doğrulama → DNS/IP politikası → IP sabitleme → probe
                                                       ↓
                                                   observation
                                                       ↓
                                        evaluateObservations(gözlem, asset)
                                                       ↓
                                      pass / fail / unknown → reconciliation
                                                       ↓
                                       incident geçmişi + açılma/yeniden açılma
```

| Dosya | Sorumluluk |
| --- | --- |
| `server/security/targets.mjs` | Hostname normalizasyonu, DNS adreslerini sınıflandırma ve hedef IP’yi sabitleme |
| `server/probes/` | Ağdan sınırlı boyutta, süre sınırı olan gözlem toplama |
| `server/scanner.mjs` | Probe’ları çalıştırma, gözlemi değerlendirme, taramayı kaydetme, incident ve bildirim akışı |
| `server/rules/index.mjs` | Kontrol kataloğu ve değerlendirme çağrıları |
| `server/db.mjs` | Incident kimliği, geçmiş, otomatik çözülme ve yeniden açılma |
| `server/notifications.mjs` | Açılan/yeniden açılan incident için generic/Slack bildirimi |

Gözlem kapsayıcısı `schemaVersion: 1` taşır. Kullanılabilecek alanlara `tls.certificate`, `http.headers`, `http.cookies`, `publicDns` ve `testssl.findings` örnek verilebilir. Alanlara güvenmeden önce ilgili probe’u okuyun: HTTP isteğinin başarısız olması ile bir başlığın gerçekten bulunmaması farklı durumlardır.

`evaluateObservations` fonksiyonuna verilen `policy`, mevcut asset nesnesidir; kullanıcı tarafından yüklenmiş serbest bir politika belgesi değildir. Örneğin `expiryWarningDays` hazır bir alandır. Kodda `policy.benimEsigim` yazmak kendiliğinden panel ayarı veya veritabanı alanı oluşturmaz.

## Uçtan uca örnek: sertifikanın toplam geçerlilik süresi

İhtiyaç: kurum politikasının izin verdiğinden daha uzun ömürlü sertifikalar için incident açılsın. Bu kontrol **toplam geçerlilik süresini** ölçer. Hazır yenileme alarmı ise **sona ermeye kalan süreyi** ölçer; ikisi farklıdır.

Örnekteki 90 gün yalnızca örnek bir kurum politikasıdır. CA/Browser Forum zorunluluğu veya evrensel bir güvenlik açığı eşiği iddiası değildir. Eşiği ve önem derecesini kendi politikanıza göre belirleyin.

### 1. Test edilmiş fonksiyonu alın

Tam kod: [examples/custom-check/certificate-validity.mjs](https://github.com/gorkemguler/HostCanvas/blob/main/examples/custom-check/certificate-validity.mjs)

Testler: [tests/custom-check-example.test.mjs](https://github.com/gorkemguler/HostCanvas/blob/main/tests/custom-check-example.test.mjs)

Proje kökünde bir kez kopyalayın; mevcut özelleştirmenizin üzerine yazmayın:

```bash
cp -n examples/custom-check/certificate-validity.mjs server/rules/certificate-validity.mjs
node --test tests/custom-check-example.test.mjs
```

Kullanım:

```js
evaluateCertificateValidity(observations, { maxDays: 90 });
```

Fonksiyon politikayı doğrular, iki tarihin varlığını ve parse edilebilirliğini kontrol eder, ters/sıfır uzunluklu tarih aralığını reddeder ve kesin süreyi karşılaştırır. Eksik kanıt veya geçersiz politika `unknown` üretir. Ağ isteği yapmaz, veritabanına erişmez, ortam değişkeni okumaz.

Örnek `fail` çıktısı:

```js
{
  ruleKey: 'custom.cert_validity_too_long',
  status: 'fail',
  severity: 'low',
  title: 'Certificate lifetime exceeds organization policy',
  description: 'The certificate validity period exceeds the configured 90-day policy. Review issuance and renewal settings.',
  evidence: {
    validFrom: '2026-01-01T00:00:00.000Z',
    validTo: '2026-04-02T00:00:00.000Z',
    lifetimeDays: 91,
    maxDays: 90,
  },
}
```

### 2. Import ve katalog kaydını ekleyin

`server/rules/index.mjs` dosyasının başına:

```js
import { evaluateCertificateValidity } from './certificate-validity.mjs';
```

Mevcut `ruleCatalog` dizisine:

```js
{
  key: 'custom.cert_validity_too_long',
  title: 'Sertifika ömrü kurum politikasını aşıyor',
  category: 'Sertifika politikası',
  severity: 'low',
  source: 'Native TLS',
  enabled: true,
  recommendedCadence: 'daily',
},
```

Buradaki `enabled`, katalog bilgisidir; bütün kurallar için çalışan genel bir aç/kapat anahtarı değildir. `recommendedCadence` ise gösterim amaçlı öneridir; bağımsız bir kural zamanlayıcısı oluşturmaz. Gerçek tarama sıklığı asset’in tarama aralığıdır. Doğrudan çağrılan fonksiyon, yalnızca katalogda `enabled: false` yapıldığı için durmaz.

### 3. Fonksiyonu değerlendirme akışına bağlayın

Aynı dosyadaki `evaluateObservations(observations, policy, checkPolicy)` fonksiyonunun sonundaki `return results;` satırından hemen önce:

```js
results.push(evaluateCertificateValidity(observations, { maxDays: 90 }));
```

`policy`, asset politikasıdır; isteğe bağlı üçüncü `checkPolicy` argümanı kaydedilen global HSTS/cookie/CAA politikasıdır. İki argümanlı mevcut çağrılar global varsayılanları kullanır. Bu örnek kendi sabit `maxDays` ayarını kullanır. Düzenlenebilir özel ayar için doğrulama, saklama ve admin UI genişletilmelidir; `/api/check-policy` adresine rastgele alan göndermek yetmez (bilinmeyen alanlar reddedilir). Bkz. [Kontrol politikaları](https://github.com/gorkemguler/HostCanvas/wiki/Kontrol-Politikalari).

Bu çağrıyı DNS/HTTP/deep kontrolüne ait koşullu blokların içine koymayın. Örnek mevcut TLS verisini kullanır; yeni probe, `server/scanner.mjs` değişikliği veya veritabanı migration’ı gerekmez. Native TLS verisi iki profilde de toplandığı için hem native hem deep taramada değerlendirilir.

Eşik burada kod sabitidir. Panelden veya asset bazında değiştirilebilir yapmak isterseniz API doğrulaması, kalıcı alan/varsayılanlar, UI, yetki kontrolleri ve eski kurulumlarla uyumluluk testleri ayrıca geliştirilmelidir.

### 4. Entegrasyonu da test edin

Kopyalama sonrasında örnek testlerin import’unu üretimdeki yeni modüle uyarlayın. Ayrıca `evaluateObservations(...)` sonucunda yeni anahtarın gerçekten bulunduğunu doğrulayın; sadece saf fonksiyonun testi, çağrının unutulmasını yakalamaz.

```js
import assert from 'node:assert/strict';
import { evaluateObservations, ruleCatalog } from '../server/rules/index.mjs';

const key = 'custom.cert_validity_too_long';
const results = evaluateObservations({}, { expiryWarningDays: 30 });
assert.equal(results.find((item) => item.ruleKey === key)?.status, 'unknown');
assert.ok(ruleCatalog.some((item) => item.key === key));
```

Bu assertion, kuralı etkinleştirmeden önce bilerek başarısız olur; örnek varsayılan kontrol değildir. Entegre fonksiyondan tam riskli ve sağlıklı gözlemleri de geçirin.

```bash
npm test
npm run lint
npx tsc --noEmit
npm run build
npm run test:web
```

Üretimde API’yi yeniden başlatın. Compose için `docker compose up --build -d app` kullanın. Taramaya yetkili olduğunuz bir test hostname’inde tarama başlatın; tarama değerlendirmelerini ve Kontroller/Incident ekranlarını inceleyin. İkinci taramada yeni bir mükerrer incident yerine mevcut kaydın güncellendiğini doğrulayın. Depodaki örnek testler yapay gözlem ve geçici veritabanı kullanır; üçüncü taraf domain taramaz.

## Değerlendirme sözleşmesi

| Alan | Açıklama |
| --- | --- |
| `ruleKey` | Sabit, isim alanı olan anahtar; katalogdaki `key` ile eşleşir |
| `status` | Yalnızca `pass`, `fail`, `unknown` |
| `severity` | Fail için gerekli: `critical`, `high`, `medium`, `low` |
| `title`, `description` | Fail için gerekli; anlaşılır bulgu ve aksiyon açıklaması |
| `evidence` | Küçük, JSON’a çevrilebilir, sonucu açıklayan kanıt |
| `discriminator` | Aynı asset/kural altında farklı bağımsız bulguları ayırmak için opsiyonel sabit kimlik |
| `reason` | Kendi testleriniz için opsiyonel tanı bilgisi; UI’da gösterilmesi garanti değildir |

Kanıta token, parola, tam cookie değeri veya sınırsız ham yanıt koymayın. Kanıt, tarama/incident ile saklanır ve yedeklere girer. UI’da bulgu metni güvenli şekilde escape edilmelidir; ham HTML olarak basılmamalıdır.

Özel kural başlıkları verdiğiniz metinle gösterilir. Kataloğa başlık eklemek otomatik Türkçe/İngilizce çeviri üretmez. İki dil gerekiyorsa yerelleştirmeyi ayrıca tasarlayın.

## Incident kimliği ve yaşam döngüsü

```text
assetId : ruleKey : (discriminator || "default")
```

Yayınlanan anahtarı sabit tutun. Anahtarı değiştirmek yeni bir incident ailesi oluşturur; kuralı koddan silmek eski incident’ları otomatik çözmez. Aynı operasyonel sorun için timestamp, scan ID, değişen sertifika bitiş tarihi veya fingerprint kullanmayın; geçmiş parçalanır.

| Sonuç / önceki durum | İşlem | Otomatik webhook |
| --- | --- | --- |
| `fail`, kayıt yok | `open` açılır, tekrar sayısı 1 | `incident.opened` |
| `fail`, open/acknowledged | Kanıt, önem, son görülme ve sayaç güncellenir; durum korunur | Yok |
| `unknown` | Önceki incident korunur | Yok |
| `pass`, aynı kural aktif | Çözülür, geçmişe olay eklenir | Yok |
| `fail`, resolved | Aynı ID yeniden açılır, sayaç artar | `incident.reopened` |

Elle seçilebilir durumlar `open`, `acknowledged`, `resolved` şeklindedir. Elle çözmek kalıcı susturma değildir; sonraki başarısız değerlendirme incident’ı yeniden açar. Acknowledge etmek de kuralı kapatmaz.

### Birden fazla bulgu için önemli sınır

Mevcut uygulamada `pass`, **aynı asset ve ruleKey altındaki bütün aktif incident’ları**, discriminator’a bakmadan çözer. Aynı kural için bazı alt öğelere `fail`, bazılarına `pass` döndürmeyin; sonuç sırası gerçek bir bulgunun yanlış kapanmasına yol açabilir.

Basit yaklaşım: doğrulanmış riskli öğelere `fail` üretin; ancak bütün küme başarıyla incelendiyse ve hiç risk kalmadıysa tek bir toplu `pass` döndürün. Bu temkinli yaklaşımda bir alt bulgu düzelmiş olsa bile kardeş bulgu sürerken eski kayıt açık kalabilir.

Dinamik kümelerde hassas kapatma için `reconcileIncidents`, `completePrefixes` destekler. Mevcut scanner bunu yalnızca **eksiksiz** deep taramada `testssl.` için kullanır. Özel adaptör kendi dar isim alanını ancak tam kapsamı kanıtlandıktan sonra bildirmelidir. `cert.`/`http.` gibi geniş alanları kullanmayın. Prefix, SQL `LIKE` sorgusuna girdiği için `%` ve `_` joker karakterlerini kullanmayın. Timeout, eksik motor, parse hatası ve kısmi tarama asla “tamamlandı” sayılmamalıdır. Örnekteki tek-sonuçlu kural için bu ileri mekanizma gerekmez.

## Yeni ağ verisi gerekiyorsa

Kural ağ isteği yapmamalıdır. Önce `server/probes/` altında probe oluşturup sınırlı sonucunu `server/scanner.mjs` gözlemlerine ekleyin. Mevcut IP doğrulama/sabitleme modelini kullanın; kullanıcı girdisini doğrudan `fetch`’e veya shell komutuna vermeyin. Başka hostname’e/redirect’e gidilecekse o hedefi de yeniden doğrulayıp sabitleyin.

Şema/sürüm, timeout, yanıt sınırı, parse hatası ve tam/kısmi sonuç anlamını belirleyin. Alt süreçte sabit komut/argüman, sınırlandırılmış ortam değişkenleri, çıktı/dosya limitleri ve process-group temizliği uygulayın. İlgili olduğunda private IP, mapped IPv6, DNS rebinding, bozuk çıktı, timeout ve kaynak sınırı testleri ekleyin.

Çözümlenmeyen CNAME veya beklenmeyen bir başlık tek başına takeover/exploit kanıtı değildir. Bulgu adını kanıtınızın gerçekten gösterdiği duruma göre seçin.

## Bildirim ve skor

Kendi kuralınızdan webhook göndermeyin; mevcut incident/bildirim akışı yeterlidir. Etkin kanallar minimum önem eşiğini açılma/yeniden açılma olaylarına uygular. Örnekteki `low` bulgu, yalnızca `high` veya `critical` alan kanala gitmez. Tekrarlayan fail ve otomatik çözülme şu anda webhook üretmez.

Skor: critical → F, high → C, medium → B, low → A-, fail yok → A. SSL Labs notu değildir. `unknown` kontroller varken A görülebilir; kapsam ve tarama durumunu ayrıca inceleyin.

## Sık sorunlar

- Kontrollerde var, değerlendirmede yok: katalog dışında fonksiyon çağrısını da eklediğinizi kontrol edin.
- Unit test çalışıyor, uygulama çalışmıyor: API’yi yeniden başlatın/image’ı yeniden derleyin; gerçek gözlem alanlarını kontrol edin.
- Eksik taramada incident kapanıyor: eksik kanıtın `unknown` döndürdüğünü ve geniş completeness prefix kullanılmadığını doğrulayın.
- Mükerrer kayıt oluşuyor: anahtar/discriminator değişiyor mu bakın; scan ID veya fingerprint kullanmayın.
- Bildirim gelmiyor: eşik, kanal etkinliği, teslimat geçmişi ve olayın yalnızca tekrar fail olup olmadığını kontrol edin.
- Politika değişikliği hemen yansımıyor: yeni tarama başlatın; incident kod düzenlenince değil, değerlendirme yapıldığında güncellenir.

Yayına almadan önce veritabanını ve şifreleme anahtarını yedekleyin, fixture ve yetkili varlıklarla test edin, diff’i inceleyin; kuralın sorumlusunu, kanıt koşullarını ve düzeltme prosedürünü kaydedin.
