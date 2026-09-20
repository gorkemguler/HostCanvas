# Incident kontrol politikaları

[English](https://github.com/gorkemguler/HostCanvas/wiki/Check-Policies) · [Ana sayfa](https://github.com/gorkemguler/HostCanvas/wiki)

## Çalışma alanını yapılandırma

Yönetici hesabıyla **Ayarlar → Incident kontrol politikası** bölümünü açın. Operator ve viewer politikayı okuyabilir ama değiştiremez. Ayarlar çalışma alanındaki tüm asset’lere uygulanır; asset bazlı istisna değildir. Kaydetme audit’e yazılır ve sonrasında başlayan taramaları etkiler; otomatik yeniden tarama başlatmaz veya eski kanıtı değiştirmez. Resolver ayarları ortam değişkenidir ve API yeniden başlatılmalıdır.

| Alan | Varsayılan | Kabul edilen değer / etkisi |
| --- | --- | --- |
| `hstsMinMaxAgeSeconds` | `15552000` (180 gün) | `0–63072000` tam sayı; sıfır yalnızca minimum süre şartını kaldırır, bozuk sözdizimi/sıfır max-age kontrolünü kaldırmaz |
| `hstsRequireSubdomains` | `false` | Gözlemlenen HSTS başlığında `includeSubDomains` ister |
| `cookieSecureRequired` | `true` | HTTPS yanıtında görülen cookie’lerde Secure kontrolü |
| `sessionCookieNames` | `[]` | Büyük/küçük harfe duyarlı, en fazla 20 tam cookie adı; her biri en fazla 100 karakter |
| `caaRequired` | `false` | Etkin CAA `issue` politikası ister |
| `caaAllowedIssuers` | `[]` | En fazla 20 issuer domain’i; doluysa ayrıca `issue` politikası ister |
| `scanHealthEnabled` | `true` | Ardışık eksik tarama incident’ı üretir |
| `scanFailureThreshold` | `3` | `1–20` tam sayı |

Bilinmeyen alanlar ve yanlış tipler reddedilir; sessiz tip dönüşümü yapılmaz. UI listelerinde her satıra bir kayıt veya virgülle ayrılmış kayıtlar girilebilir. Cookie adları `session` gibi kelimelerden tahmin edilmez; uygulamalarınızın kullandığı adları açıkça belirtin. Global listelerin çalışma alanındaki tüm asset’lere uygun olması gerekir.

## HSTS ve cookie’ler

- `http.hsts_weak_policy` (orta): HSTS başlığında bozuk/tekrarlı direktif, sıfır `max-age`, yetersiz süre veya zorunlu `includeSubDomains` eksikliği. Başlık hiç yoksa mevcut `http.hsts_missing` kuralı çalışır; aynı eksiklik için iki bulgu üretilmez.
- `http.cookie_secure_missing` (düşük): gözlemlenen en az bir cookie’de Secure yoktur. Cookie görülmemesi `unknown` demektir; uygulamanın güvensiz cookie üretmediğini kanıtlamaz.
- `http.session_cookie_httponly_missing` (orta): tanımlı bir oturum cookie’si HttpOnly olmadan görülmüştür. `pass` için tanımlanan bütün adların HttpOnly ile görülmesi gerekir; eksik adlar `unknown` kalır. Boş liste kontrolü devre dışı bırakır.

Örneğin `max-age=86400` varsayılan HSTS süresini karşılamaz; `max-age=31536000`, ek subdomain şartı yoksa geçer. `session=…; Secure` yalnızca `session` adı tanımlıysa HttpOnly bulgusu üretir. Cookie adları ve boolean nitelikleri tutulur; değerler saklanmaz. Kontroller tek bir anonim HTTPS yanıtını gözlemler; oturum açma akışlarını gezmez ve her rotanın korunduğunu kanıtlamaz. HTTPS geçişiniz hazır olmadan subdomain HSTS şartını açmayın.

## CAA politikası

CAA toplamak için `TLS_SENTINEL_PUBLIC_DNS_RESOLVER` tanımlayın. `dns.caa_policy` düşük önem seviyeli politika bulgusudur; hatalı sertifika üretildiği iddiası değildir. Varsayılanda CAA yokluğu tek başına bulgu değildir; görülen bozuk kayıtlar veya desteklenmeyen kritik özellikler yine işaretlenebilir.

Probe alias ve üst domain’lerde etkin CAA kümesini arar; ilk dolu RRset’te durur. Sorgu hatası veya güvenlik limitleri `unknown` üretir, boş politika sayılmaz. Tag karşılaştırması harf duyarsızdır; boş `issue` issuer’ı bilinçli üretim yasağıdır. Bu davranışın standardı [RFC 8659](https://www.rfc-editor.org/rfc/rfc8659.html) belgesidir.

Uygulamadaki örnekler:

- `caaRequired: true`, etkin kayıt yok → `issuance_policy_missing`.
- İzin verilen issuer `letsencrypt.org`, etkin `issue "other.example"` → `issuer_not_allowed`.
- Etkin `issue ";"` → eksik politika bulgusu yok.
- Yalnızca `issuewild` → normal hostname için zorunlu `issue` şartını karşılamaz.

İzin listesi `issue` ve `issuewild` kayıtlarındaki issuer domain’lerini karşılaştırır; mevcut sertifikanın issuer görünen adı/CN’iyle karşılaştırma yapmaz. Her CA’ya özel parametreyi yorumlamaz ve CA’nın gerçek üretim kararını kanıtlamaz. Probe en fazla 16 domain seviyesi ve 64 kayıtla sınırlıdır.

## DNSSEC: ayrı ve açık onay

Eski Node `resolve(..., 'DNSKEY'/'DS')` yaklaşımı değiştirildi: bu kayıt tipleri ilgili API’de desteklenmez. Yalnızca `TLS_SENTINEL_PUBLIC_DNS_RESOLVER` artık DNSSEC’i açmaz. Public IP’ye çözümlenen hostname’i olan, güvendiğiniz doğrulayıcı DNS-over-TLS sağlayıcısını seçin ve TCP 853 çıkışına izin verin. **Otomatik açılmayan** örnek ayar:

```dotenv
TLS_SENTINEL_DNSSEC_RESOLVER=cloudflare-dns.com
```

API’yi yeniden başlatın, Ayarlar’da resolver’ı doğrulayın ve yetkili asset’i tarayın. Sağlayıcı her sorgulanan asset hostname’ini (A sorgusu) ve kök DNSKEY yetenek sorgusunu alır. Paylaşmaya yetkili olmadığınız adlar için etkinleştirmeyin. Resolver hostname’i çözülür, public IP doğrulaması yapılır ve bağlantı o IP’ye sabitlenir. TLS özgün hostname/sertifikayı doğrular; düz metin veya doğrulanmayan TLS’e geri dönüş yoktur.

| Gözlem | Sonuç |
| --- | --- |
| Authenticated-data işaretli adres/CNAME yanıtı | `present`; eksik/bogus kuralları pass |
| İmzasız yanıt ve olumlu kök doğrulama yeteneği | `missing`; `dns.dnssec_missing` fail (orta) |
| SERVFAIL ve resolver’ın bildirdiği DNSSEC EDE kodu 6–12 | `bogus`; `dns.dnssec_bogus` fail (yüksek) |
| Timeout, TLS hatası, doğrulanmamış yetenek, bozuk/eski/hatalı yanıt, NXDOMAIN veya A/CNAME kanıtı yok | `unknown`; mevcut DNSSEC incident’ları korunur |
| Resolver tanımlı değil | `disabled`; yeni DNSSEC bulgusu yok |

Bu yöntem kimliği doğrulanmış resolver’ın raporuna güvenir; **tüm imza zincirini yerelde kriptografik olarak doğrulamaz**. EDE anlamları [RFC 8914](https://www.rfc-editor.org/rfc/rfc8914.html) belgesinde tanımlıdır. Tek başına genel SERVFAIL, bogus sayılmaz. İlk sorgu A kullandığından yalnızca IPv6 kullanan, A/CNAME kanıtı olmayan cevaplar unknown kalabilir. Diğer probe’lar başarılı olsa da DNSSEC belirsizliği taramayı partial yapar. Önceki DNSSEC eksik incident’ı, yeni sonuç bogus veya unknown diye kapanmaz.

## Tarama sağlığı incident’ı

`monitor.scan_unhealthy` (orta), art arda belirtilen sayıda tamamlanmış `failed`/`partial` tarama sonrası açılır. Eksik deep motoru, gerekli HTTP/DNS kapsamının tamamlanamaması ve bağlantı hataları sayaca dahil olabilir. Güvenlik bulguları olan tarama yine sağlıklı olabilir: burada sağlık, temiz güvenlik notu değil **veri toplama kapsamı** demektir.

Asset bazlı sayaç yeniden başlatma ve eski tarama kayıtlarının temizlenmesi sonrasında korunur. Tekrarlayan hatalar aynı incident’ı günceller; acknowledged durumu korunur. `succeeded` tarama sayacı sıfırlar ve yalnızca sağlık incident’ını çözer. Native tarama sağlık durumunu düzeltebilir ama eski `testssl.*` bulgularını kapatmaz; onlar eksiksiz deep kanıtı gerektirir. Kapalı/arşivli asset için yeni sağlık incident’ı üretilmez.

Bu, gecikmiş tarama/watchdog alarmı değildir: zamanlayıcı durursa tamamlanan tarama olmadığı için sayaç artmaz. Sağlık politikası tarama takvimini değiştirmez. Kapatılması incident değerlendirmesini durdurur, tamamlanan tarama sonuçları yine izlenir. Yeniden açılması sonraki tamamlanan taramada uygulanır. Diğer kontrolleri kapatmak da eski bulguları çözmez; yeterli pass kanıtı veya bilinçli manuel karar gerekir.

## API, saklama ve doğrulama

Oturumla `GET /api/check-policy`, `{ policy, updatedAt, publicDnsResolver, dnssecResolver }` döndürür. Yalnızca admin’in kullanabildiği `PATCH /api/check-policy`, gönderilen alanları birleştirir ve kaydedilen politikayı döndürür. Mevcut oturum, origin, Host ve LAN kısıtları geçerlidir. Örnek istek gövdesi:

```json
{
  "hstsMinMaxAgeSeconds": 15552000,
  "hstsRequireSubdomains": false,
  "sessionCookieNames": ["session", "__Host-session"],
  "caaRequired": true,
  "caaAllowedIssuers": ["letsencrypt.org"],
  "scanHealthEnabled": true,
  "scanFailureThreshold": 3
}
```

`check_policy` ve `scan_health_state` SQLite tabloları normal veritabanı yedeklerine dahildir; ayrı politika dosyası veya secret gerektirmez. Eklemeli şema başlangıcı mevcut asset ve incident’ları korur. Eski yedek bu sürümle açıldığında varsayılan politika ve boş sağlık sayacı oluşur.

`tests/security-policy.test.mjs`, `tests/dnssec.test.mjs`, `tests/dns.test.mjs`, `tests/probe-integration.test.mjs` ve `tests/api-auth.test.mjs`; doğrulamayı, yaşam döngüsünü, rol sınırlarını, etkin CAA aramasını ve gerçek yerel TLS üzerinden DNS çerçevelerini test eder. Harici DNS sağlayıcısı gerekmez. Bu kuralları ayarlamak yerine yeni bir incident ailesi eklemek için [Kendi incident türünü oluşturma](https://github.com/gorkemguler/HostCanvas/wiki/Ozel-Incident-Turu-Olusturma) rehberini kullanın.
