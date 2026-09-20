# HostCanvas operasyon runbook’u

## Üretim öncesi kontrol

1. `TLS_SENTINEL_SECRET_KEY` değerini secret manager’dan sağlayın veya `/data/.secret-key` dosyasını yedekleyin. Bu anahtar kaybolursa kayıtlı webhook adresleri çözülemez.
2. `.env` içinde `TLS_SENTINEL_HTTPS_HOST` değerini istemcilerin kullanacağı tek hostname veya IPv4 adresi yapın (protokol/port/yol olmadan). `docker compose up --build -d` ile başlatıp `app` servisinin healthy olduğunu doğrulayın. Compose `.env.local` için ayrıca `--env-file .env.local` ister.
3. `https://YAPILANDIRILAN-ADRES:3443` adresinden ilk kurulumu açın, **LAN erişimi**ni etkinleştirin ve `docker compose logs app` içindeki kurulum kodunu kullanın. Kod localhost için de zorunludur, 15 dakika geçerlidir; süresi dolduğunda sayfayı yenileyip yeni konsol kodunu alın.
4. Caddy local CA sertifikasını yalnızca yönetilen istemcilere dağıtın. Kurumsal PKI varsa `Caddyfile` içindeki `tls internal` satırını kurum sertifikanızla değiştirin.
5. En az iki etkin admin hesabı oluşturun; günlük kullanım için operator/viewer hesapları tercih edin.
6. Bir test webhook’u gönderin, teslimat geçmişini ve audit kaydını doğrulayın.
7. Manuel yedek oluşturun, indirin ve ayrı bir test data dizininde geri yükleme provası yapın.

## Günlük kontroller

- Dashboard’da başarısız/kısmi taramalar ve büyüyen kuyruk sayısı
- Bildirim teslimatlarında tekrarlayan hata
- En az bir güncel ve indirilebilir yedek
- Audit kaydında beklenmeyen kullanıcı/ayar değişiklikleri
- Data volume disk doluluk oranı

## Yedek alma

Panelde **Ayarlar → Yönetim merkezi → Veri → Şimdi yedekle** kullanın veya uygulama çalışırken:

```bash
npm run backup
```

Docker volume’daki yedeği dışarı almak için önce panelden indirin. Alternatif olarak container içinde yedek oluşturup dosyayı kopyalayabilirsiniz:

```bash
docker compose exec app npm run backup
docker compose cp app:/data/backups/tlsentinel-YYYYMMDDTHHMMSSZ.db ./
```

Webhook şifrelerini geri açabilmek için aynı `TLS_SENTINEL_SECRET_KEY` veya `/data/.secret-key` de kurtarma planında bulunmalıdır.

## Geri yükleme

Geri yükleme yazma yapan ve çalışan veritabanını değiştiren kontrollü bir işlemdir:

1. Uygulamayı durdurun.
2. Kaynak `.db` dosyasının güvenilir bir yedek olduğundan emin olun.
3. Aynı uygulama sürümüyle restore komutunu çalıştırın.
4. Uygulamayı başlatın; dashboard, kullanıcı girişi, son taramalar ve webhook yapılandırmasını kontrol edin.

Yerel kurulum:

```bash
npm run restore -- /tam/yol/yedek.db --confirm
```

Docker kurulumu için yedeği önce volume’a kopyalayın, app servisini durdurun ve tek seferlik container çalıştırın:

```bash
docker compose cp ./yedek.db app:/data/backups/restore-source.db
docker compose stop app
docker compose run --rm app npm run restore -- /data/backups/restore-source.db --confirm
docker compose up -d app
```

Komut kaynak ve geçici dosyayı doğrular. Mevcut veritabanını değiştirmeden önce `/data/backups/pre-restore-*` adıyla acil durum kopyası üretir.

Veri dizini kilidi, uygulama veya yedekleme açıkken restore işlemini reddeder. Bir veri dizinini aynı anda iki API sürecine bağlamayın. POSIX üzerinde dizinler `0700`, veritabanı/yedek/secret dosyaları `0600` yapılır; mevcut verilerin izinleri de başlangıçta sıkılaştırılır. Container volume UID/GID sahibi `10001:10001` olmalıdır.

## Kaynaklar ve bildirim teslimatı

- Compose uygulamaya 2 GiB bellek, 256 süreç ve 128 MiB `/tmp` limiti; her servise dönen log dosyaları uygular. Büyük envanterlerde bu limitleri ölçerek artırın.
- testssl alt süreçleri temizlenir; standart çıktı, JSON artifact ve POSIX tek-dosya boyutu sınırlıdır. Bazı testssl sürümleri `TMPDIR` yerine doğrudan `/tmp` kullanır. Native kurulumda toplam geçici disk tüketimi için işletim sistemi kotası veya ayrı dosya sistemi kullanın; tek-dosya sınırı toplam kota değildir.
- Webhook başına DNS dahil 8 saniye süre sınırı ve geçici hatalarda en fazla 3 deneme vardır. Teslimat tarama kuyruğunu bekletmez, paralellik ve bekleyen işler sınırlıdır.
- Teslimat geçmişi kalıcıdır; bekleyen bildirimler bellektedir ve yeniden başlatmada otomatik tekrar gönderilmez. Belirsiz timeout sonrası tekrarlar aynı olayı birden fazla teslim edebilir. Alıcıda incident kimliği, olay türü ve olayın `lastSeenAt` zamanı gibi alanlarla idempotent işleme uygulayın; yalnızca incident kimliğini kalıcı olarak elemek sonraki meşru yeniden açılmaları da susturur.
- `/api/health/live` yalnızca canlılık bilgisi döndürür. Ayrıntılı motor/env bilgileri `/api/health` erişim kontrolünün arkasındadır.

## Olay müdahalesi

- Hesap şüphesinde kullanıcıyı devre dışı bırakın; aktif oturumları otomatik sonlanır.
- Webhook sızıntısında sağlayıcı tarafındaki secret’ı döndürün, HostCanvas kanalını silip yeniden oluşturun.
- `TLS_SENTINEL_SECRET_KEY` sızıntısında tüm webhook secret’larını döndürün ve yeni anahtarla kanalları yeniden kaydedin.
- Audit kayıtları SQLite içindedir; adli saklama gerekiyorsa doğrulanmış yedeği salt okunur harici ortama kopyalayın.
