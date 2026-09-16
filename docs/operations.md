# HostCanvas operasyon runbook’u

## Üretim öncesi kontrol

1. `TLS_SENTINEL_SECRET_KEY` değerini secret manager’dan sağlayın veya `/data/.secret-key` dosyasını yedekleyin. Bu anahtar kaybolursa kayıtlı webhook adresleri çözülemez.
2. `docker compose up --build -d` ile servisleri başlatın ve `docker compose ps` çıktısında `app` servisinin healthy olduğunu doğrulayın.
3. `https://SUNUCU-IP:3443` adresinden ilk kurulumu açın, **LAN erişimi**ni etkinleştirin ve `docker compose logs app` içindeki kurulum kodunu kullanın.
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

## Olay müdahalesi

- Hesap şüphesinde kullanıcıyı devre dışı bırakın; aktif oturumları otomatik sonlanır.
- Webhook sızıntısında sağlayıcı tarafındaki secret’ı döndürün, HostCanvas kanalını silip yeniden oluşturun.
- `TLS_SENTINEL_SECRET_KEY` sızıntısında tüm webhook secret’larını döndürün ve yeni anahtarla kanalları yeniden kaydedin.
- Audit kayıtları SQLite içindedir; adli saklama gerekiyorsa doğrulanmış yedeği salt okunur harici ortama kopyalayın.
