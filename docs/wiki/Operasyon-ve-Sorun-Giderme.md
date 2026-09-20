# Operasyon ve sorun giderme

[English](https://github.com/gorkemguler/HostCanvas/wiki/Operations-and-Troubleshooting) · [Ana sayfa](https://github.com/gorkemguler/HostCanvas/wiki)

## Roller ve günlük işletim

| Rol | Yetki |
| --- | --- |
| Admin | Çalışma alanı/erişim ayarları, kullanıcılar, bildirim, audit, saklama/yedek ve bütün operasyonlar |
| Operator | Asset ekleme/düzenleme/arşivleme/tarama ve incident durum yönetimi |
| Viewer | Dashboard, asset, tarama, kontrol ve incident okuma |

Kullanıcıları Ayarlar → Yönetim merkezi altında yönetin. İki etkin admin bulundurun, günlük işlerde en az yetkiyle çalışın. Son yönetici koruması normal yetki yönetiminde son etkin admin’in kaldırılmasını engeller. Devre dışı bırakılan kullanıcının oturumları geçersizleşir. Sunucu, yedek ve log erişimini güvenilir yöneticilerle sınırlayın.

Günlük olarak başarısız/kısmi taramaları, geciken asset’leri, kuyruk büyümesini, bildirim hatalarını, son yedek zamanını, beklenmeyen audit olaylarını ve boş disk alanını inceleyin. Canlılık endpoint’inin yeşil olması tarama/yedek başarısını kanıtlamaz.

## Webhook kanalları

Generic veya Slack kanalı oluşturun, etkinleştirin, minimum önem derecesini seçin ve test bildirimi gönderin. Tam webhook URL’leri diskte şifrelidir; API tam URL’yi geri döndürmez. Şifreleme anahtarını yedekleme planında koruyun.

Hedef public HTTPS ve port 443 olmalıdır. DNS doğrulanır, bağlantı izin verilen IP’ye sabitlenir. İç ağ veya farklı porttaki webhook’lar bilinçli olarak reddedilir; iç ağ tarama izni webhook politikasını gevşetmez.

Generic payload örneği:

```json
{
  "event": "incident.opened",
  "sentAt": "2026-01-01T00:00:00.000Z",
  "message": "Okunabilir incident özeti",
  "incident": {
    "id": "incident-id",
    "severity": "high",
    "status": "open",
    "title": "Bulgu başlığı",
    "description": "Bulgu açıklaması",
    "hostname": "api.example.com",
    "port": 443,
    "owner": "Platform",
    "ruleKey": "cert.hostname_mismatch",
    "firstSeenAt": "2026-01-01T00:00:00.000Z",
    "lastSeenAt": "2026-01-01T00:00:00.000Z"
  }
}
```

Olaylar `incident.opened`, `incident.reopened` ve elle test için `incident.test` şeklindedir; testte incident null’dır. Slack `text` payload kullanır. Generic bildirim ham evidence içermez. Otomatik çözülme veya her tekrar fail için bildirim henüz yoktur.

Her denemede DNS dahil toplam 8 saniye sınırı ve geçici hatalarda en fazla 3 deneme vardır. Yanıt gövdesi 64 KiB, aktif teslimat 4, bekleyen teslimat 256 ile sınırlıdır. Tarama teslimatı beklemez. Teslimat geçmişi kalıcı, bekleyen kuyruk **bellektedir**; restart sonrası yarıda kalan bildirimler otomatik tekrar oynatılmaz.

Timeout sonrası tekrar aynı olayı iki kez ulaştırabilir. Alıcı idempotent olmalıdır; incident ID + olay türü + o olayın `lastSeenAt` zamanı tekrar ile sonraki gerçek yeniden açılmayı ayırt etmeye yardımcı olur. Yalnızca incident ID’yi sonsuza kadar elemek, meşru yeniden açılmaları da susturur. Kalıcı outbox ve açık delivery/idempotency ID ileride geliştirilecek alanlardır.

## Yedek, saklama ve secret

Varsayılan saatlik bakım, 24 saatte bir doğrulanmış SQLite yedeği oluşturur; 14 yedek tutar, 180 günden eski tamamlanmış taramaları ve 30 günden eski ham artifact’ları temizler. Ayarlar → Yönetim merkezi → Veri bölümünden değiştirin. Bu politika bütün incident/audit geçmişi için genel silme garantisi değildir.

Native manuel yedek; uygulama çalışabilir:

```bash
npm run backup
```

Container:

```bash
docker compose exec app npm run backup
# Komutun çıktısındaki gerçek dosya adını kullanın:
docker compose cp app:/data/backups/tlsentinel-YYYYMMDDTHHMMSSZ.db ./
```

Panelden de oluşturup indirebilirsiniz. Seçili yedekleri ayrı şifreli depoya çıkarın ve test edin; aynı volume’daki kopya volume kaybına karşı korumaz. Kalıcı `TLS_SENTINEL_SECRET_KEY` veya üretilen `/data/.secret-key` ayrıca güvenli şekilde korunmalıdır. Anahtar yoksa geri yüklenen webhook adresleri çözülemez. SQLite yedeği bütün ham testssl artifact’larının veya Caddy PKI durumunun arşivi değildir.

POSIX veri dizinleri `0700`, veritabanı/yedek/secret dosyaları `0600` kullanır; başlangıçta mevcut izinler de sıkılaştırılır. Container volume sahibi `10001:10001` olmalıdır. İzin hatasını herkese yazma yetkisi vererek çözmeyin.

## Kontrollü geri yükleme

Restore uygulama verisini değiştirir. Kaynağı doğrulayın, önce volume dışında kurtarma kopyası alın. Uyumlu uygulama sürümünü kullanın, bütün yazıcıları durdurun ve eski şifreleme anahtarını koruyun.

Native; önce uygulamayı durdurun:

```bash
npm run restore -- /tam/yol/yedek.db --confirm
```

Compose:

```bash
docker compose cp ./yedek.db app:/data/backups/restore-source.db
docker compose stop app
docker compose run --rm app npm run restore -- /data/backups/restore-source.db --confirm
docker compose up -d app
```

Araç SQLite bütünlüğünü ve gerekli tabloları kontrol eder, veri dizininde özel kilit alır, değiştirmeden önce `pre-restore-*` kurtarma kopyası üretir. Aktif uygulama/yedek kilidi varsa çalışmayı reddeder. Canlı restore zorlamak için kilit dosyasını silmeyin veya korumayı atlatmayın. Akışı gerçek olaydan önce ayrı ortamda prova edin.

Sonrasında giriş, kullanıcılar, asset sayıları, son taramalar, incident geçmişi ve webhook çözme/test teslimatını doğrulayın. Yeniden başlayan süreç yarıda kalmış taramaları ele alabilir; ilk bakım döngüsünü izleyin.

## Sağlık ve kaynak sınırları

- `/api/health/live` minimum kimlik doğrulama öncesi canlılık bilgisidir; ayrıntılı `/api/health` çalışma alanı erişim kontrolüne tabidir.
- Compose uygulamada 2 GiB bellek, 256 süreç, 128 MiB `/tmp`, dönen log ve kontrollü kapanış süresi kullanır. Taramaları büyütmeden ölçün.
- testssl stdout/stderr, JSON artifact ve POSIX tek-dosya boyutu sınırlıdır. Bazı testssl sürümleri doğrudan `/tmp` kullanır; native kurulumda toplam disk sınırı için OS kotası/ayrı geçici dosya sistemi gerekir.
- Kontrollü kapanış yeni işi durdurur ve scanner alt süreçlerini temizler; kalıcı webhook replay sağlamaz.

## Sık sorunlar

| Belirti | Kontrol |
| --- | --- |
| Kurulum kodu reddediliyor | Aktif API’nin konsolunu okuyun; süre dolduysa sihirbazı yenileyip yeni kodu alın. Ekran görüntüsü/issue’da kod paylaşmayın. |
| LAN girişi çalışmıyor | HTTPS, LAN ayarı, tam origin/port, sertifika güveni, proxy başlıkları ve firewall’ı kontrol edin. |
| Invalid Host | Başlatmadan önce `TLS_SENTINEL_UI_ORIGINS` / Compose HTTPS host içine doğru adresi ekleyin. |
| Deep motor bulunamıyor | Executable yolu, çalıştırma izni ve desteklenen sürümü kontrol edin; yola rastgele flag eklemeyin. |
| DNS kontrolü unknown | Erişilebilir public resolver yapılandırın ve sonucu inceleyin; unknown sağlıklı sonucu değildir. |
| Hata sonrası eski not | Son kullanışlı snapshot korunmuştur; tarama tarihini/durumunu ve asıl hatayı inceleyin. |
| İkinci API/restore açılmıyor | Aynı veri dizinini kullanan süreci bulun ve temiz durdurun; aktif kilidi silmeyin. |
| Webhook gelmiyor | Önem eşiği, açılma/yeniden açılma ayrımı, kanal etkinliği, public HTTPS hedefi ve teslimat geçmişini kontrol edin. |
| Restore sonrası webhook hatalı | Eski şifreleme secret’ının doğru geri getirildiğini doğrulayın. |

## Doğrulama ve bilinen sınırlar

Proje kökünde:

```bash
npm ci
npm test
npm run lint
npx tsc --noEmit
npm run test:e2e
npm run build
npm run test:web
npm audit --audit-level=high
```

Testlerde izole yerel fixture’lar bulunur. Dependency audit zamana bağlıdır; tek başına tam güvenlik denetimi değildir. CI Compose/Caddy sözdizimini de doğrular; bu, kendi altyapınızda tam dağıtım ve restore provası yerine geçmez.

Henüz olmayanlar: görsel kural editörü, kalıcı webhook outbox, e-posta bildirimi, SSO/OIDC, asset bazlı tenancy, snooze/bakım pencereleri ve tam saldırı yüzeyi keşfi. Bunları varmış gibi varsaymak yerine işletim prosedüründe sınır olarak kaydedin.
