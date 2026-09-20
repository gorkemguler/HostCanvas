# Kurulum ve güvenli LAN erişimi

[English](https://github.com/gorkemguler/HostCanvas/wiki/Installation-and-LAN) · [Ana sayfa](https://github.com/gorkemguler/HostCanvas/wiki)

## Kurulum seçimi

Yerel geliştirme/değerlendirme için native kurulum; sürekli çalışan servis için üretim build’i veya Compose/Caddy kullanın. Temel gereksinim Node.js 24.21.0 veya yenisidir; `.node-version` ve Dockerfile taban sürümü sabitler. Native deep tarama için ayrıca testssl.sh 3.2.x gerekir. Docker image testssl.sh 3.2.4 içerir.

### Native kurulum

```bash
git clone https://github.com/gorkemguler/HostCanvas.git
cd HostCanvas
npm ci
cp .env.example .env.local
npm run dev
```

`http://localhost:3000` adresini açın. Üretim çalıştırması için geliştirme süreçlerini durdurduktan sonra:

```bash
npm run build
npm start
```

`npm start`, derlenmiş arayüzü ve API’yi başlatır; geliştirme sunucusunu çalıştırmaz. Aynı veri dizininde ikinci API başlatmayın. Varsayılan portlar arayüz için 3000, API için 8787’dir. Yalnızca yerel native erişim istiyorsanız başlamadan önce `TLS_SENTINEL_API_HOST=127.0.0.1` ve `TLS_SENTINEL_WEB_HOST=127.0.0.1` ayarlayın.

### İlk kurulum sihirbazı

1. Türkçe/İngilizce seçin ve kurum adını girin.
2. Yerel erişim veya kimlik doğrulamalı LAN erişimini seçin. LAN için HTTPS gereklidir.
3. API konsolundaki tek kullanımlık kurulum kodunu alın. Localhost’ta da zorunludur; 15 dakika geçerlidir. Süresi dolarsa sihirbazı yenileyip konsoldaki yeni kodu kullanın.
4. Yönetici hesabını ve varsayılan tarama ayarlarını oluşturun.
5. İsterseniz ilk asset’i ekleyin. Tarama yetkinizi onaylayın. Dış CT servisine sorgu göndermek istemiyorsanız subdomain keşfini işaretlemeyin.
6. Giriş yapmayı, yetkili bir test taramasını ve incident görünümünü doğrulayın.

Dil, kurum, erişim politikası ve tarama varsayılanları daha sonra Ayarlar’dan değiştirilebilir. Varlığa özel alanlar envanterden düzenlenir. Kurulum sihirbazı hesap kurtarma aracı değildir; parola sıfırlamak için canlı veritabanını silmeyin.

## Docker ve LAN için HTTPS

Klonlanan proje kökünde:

```bash
cp .env.example .env
# Başlatmadan önce .env dosyasını düzenleyin:
# TLS_SENTINEL_HTTPS_HOST=192.168.1.20
docker compose up --build -d
docker compose logs app
```

`TLS_SENTINEL_HTTPS_HOST` için sunucunun gerçek hostname veya IPv4 adresini yazın; **protokol, port ve yol eklemeyin**. Kendi adresinizle `https://192.168.1.20:3443` açın. Her istemcide aynı origin’i kullanın. Kurulumda LAN erişimini açın ve konsol kodunu girin.

Caddy kendi yerel CA’sıyla sertifika üretir. Dışarı alınacak dosya **açık kök sertifikadır**; CA private key’i değildir:

```bash
docker compose cp proxy:/data/caddy/pki/authorities/local/root.crt ./host-canvas-local-ca.crt
```

Sertifikanın kaynağını doğrulayın ve kurumunuzun güvenilir kök dağıtım prosedürüyle yalnızca yönetilen cihazlara yükleyin. Tarayıcı uyarısını atlamak üretim çözümü değildir. Kurumsal PKI varsa `tls internal` yerine kurum sertifikası/anahtarını güvenli mount ve izinlerle yapılandırın.

Compose LAN’a yalnızca HTTPS 3443 açar; ham 3000/8787 portları host loopback’e bağlıdır. Uygulama root olmayan kullanıcıyla, düşürülmüş yetkiler ve salt okunur root dosya sistemiyle çalışır. Veriler named volume’da tutulur; volume dışına ayrıca yedek çıkarın.

## Origin listesi ve özel reverse proxy

Arayüz ve API aynı HTTPS origin’den sunulmalıdır. Ayarlar’a gerçek arayüz origin’ini, standart dışı portuyla birlikte ekleyin: örneğin `https://hostcanvas.example.internal:3443`. Origin’de yol bulunmaz; gereksiz adresleri izin listesine eklemeyin.

Özel proxy kullanıyorsanız hostname doğrulamasının çalışması için **ilk kurulumdan önce** `TLS_SENTINEL_UI_ORIGINS` değerini hazırlayın. `TLS_SENTINEL_TRUST_PROXY=true` yalnızca API’ye güvenilmeyen istemciler doğrudan erişemiyorsa açılmalıdır. Proxy `X-Forwarded-For` ve `X-Forwarded-Proto` başlıklarını istemci girdisine güvenmeden **yeniden yazmalıdır**; gelen değerleri ekleyip geçirmemelidir. Sağlanan Caddy bunu yapar. Yanlış proxy ayarı gerçek istemciyi gizleyebilir veya erişim kararını zayıflatabilir.

Normal kurulumda `NEXT_PUBLIC_TLS_SENTINEL_API_URL` boş kalsın; HTTPS’te API aynı origin’den kullanılır. `NEXT_PUBLIC_*` değişkenlerine secret koymayın. Uzaktan erişim için VPN veya kurum erişim katmanı kullanın; servis doğrudan internete açık çok kiracılı SaaS olarak tasarlanmamıştır.

## Yapılandırma

Native başlatıcı/API için `TLS_SENTINEL_*` önceliği: dışarıdan export edilen ortam → `.env.<mode>.local` → `.env.local` (test modunda hariç) → `.env.<mode>` → `.env`. Sunucu ayarı değişince süreçleri yeniden başlatın. Compose varsayılan olarak `.env` okur; `.env.local` için `--env-file .env.local` kullanın. Sadece `.env.local` oluşturmak Compose değişkenlerini ayarlamaz.

| Değişken | Varsayılan / açıklama |
| --- | --- |
| `TLS_SENTINEL_DATA_DIR` | Native `data/`, container `/data` |
| `TLS_SENTINEL_UI_ORIGINS` | Localhost origin’leri; özel proxy origin’ini ekleyin |
| `TLS_SENTINEL_TRUST_PROXY` | `false`; Compose sınırlı proxy topolojisinde açar |
| `TLS_SENTINEL_HTTPS_HOST` | `localhost`; Compose/Caddy hostname veya IPv4 |
| `TLS_SENTINEL_ALLOW_PRIVATE_TARGETS` | `false`; asset bazında iç ağ onayı da gereklidir |
| `TLS_SENTINEL_PUBLIC_DNS_RESOLVER` | Boş; public DNS/e-posta kontrolleri resolver olmadan devre dışıdır |
| `TLS_SENTINEL_CRT_NAME_ENABLED` | `true`; keşif için ayrıca asset formunda onay gerekir |
| `TLS_SENTINEL_CRT_NAME_LIMIT` | Keşif başına 200 yeni asset; 1–500 arası |
| `TLS_SENTINEL_MAX_CONCURRENT_SCANS` | 2; 1–8 aralığında |
| `TLS_SENTINEL_TESTSSL_PATH` | `testssl.sh`; flag içeren komut değil, executable yolu |
| `TLS_SENTINEL_TESTSSL_TIMEOUT_MS` | 240000; 30000–900000 aralığında |
| `TLS_SENTINEL_SECRET_KEY` | Opsiyonel kalıcı secret; yoksa korumalı `.secret-key` üretilir |

`TLS_SENTINEL_*` ve `tlsentinel.db` adları eski kurulumlarla uyumluluk için korunur. Kesin başvuru: [.env.example](https://github.com/gorkemguler/HostCanvas/blob/main/.env.example) ve [server/config.mjs](https://github.com/gorkemguler/HostCanvas/blob/main/server/config.mjs). `.env`, veritabanı, private key, webhook secret veya gerçek envanter çıktısını Git’e koymayın.

## Ekibe açmadan önce

- İkinci bir yönetilen istemcide HTTPS güvenini ve LAN kimlik doğrulamasını doğrulayın.
- İkinci etkin admin oluşturun; günlük işlemlerde operator/viewer kullanın.
- Viewer’ın envanter/ayar değiştiremediğini kontrol edin.
- Ayrı veri dizininde yedek ve restore provası yapın.
- Firewall, origin listesi ve proxy başlıklarının yeniden yazılmasını kontrol edin.
- Küçük ve yetkili envanterle bildirim ve kaynak kullanımını ölçün; sonra paralelliği artırın.
