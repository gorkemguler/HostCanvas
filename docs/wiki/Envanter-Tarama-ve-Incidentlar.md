# Envanter, tarama ve incident yönetimi

[English](https://github.com/gorkemguler/HostCanvas/wiki/Inventory-Scanning-and-Incidents) · [Ana sayfa](https://github.com/gorkemguler/HostCanvas/wiki)

## Doğru kapsamı eklemek

Asset, hostname ve portu temsil eder. `api.example.com` gibi hostname girin; `https://api.example.com/yol`, doğrudan IP, wildcard veya komut argümanı girmeyin. Yalnızca sahibi olduğunuz veya açık tarama yetkiniz bulunan adları ekleyin.

Etiket, sorumlu ekip ve ortam bilgisini doldurun; tarama profili, aralık ve sertifika yenileme eşiğini seçin. Varsayılan aralık 720 dakika (12 saat) şeklindedir. Aralık asset için geçerlidir; her kuralın bağımsız zamanlayıcısı yoktur.

Sorumlu alanı operasyonel bilgidir; ayrı bir yetki sınırı değildir. Admin/operator/viewer rolleri çalışma alanında geçerlidir; asset bazlı çok kiracılı yetkilendirme yoktur. CSV envanter çıktısını kurum içi veri olarak koruyun.

### İç ağ hedefleri

Private/loopback/link-local ve diğer ayrılmış hedefler varsayılan olarak engellenir. İç ağ taraması için iki onay gerekir:

1. Sunucuda `TLS_SENTINEL_ALLOW_PRIVATE_TARGETS=true`.
2. İlgili asset’te **İç ağ hedefi** seçeneği.

Bu ayar scanner’ın erişebildiği kapsamı bilinçli olarak genişletir. Operator/admin erişimini ve sunucunun ağ erişimini sınırlayın. Sadece bir doğrulama hatasını geçmek için açmayın. DNS sonuçları tarama anında yeniden doğrulanır; seçilen IP sabitlenir, hostname SNI/Host kimliği olarak korunur.

## İsteğe bağlı subdomain keşfi

Apex domain eklerken gerekiyorsa `crt.name` keşfini işaretleyin. Domain adı harici bir certificate-transparency indeksine gönderilir. Seçenek varsayılan olarak boş gelir; entegrasyonun global açık olması her asset için sorgu onayı anlamına gelmez.

Sonuçlar normalize edilir, domain kapsamına göre filtrelenir; wildcard ve tekrarlar elenir. Varsayılan olarak en fazla 200 yeni subdomain asset oluşturulur; sınır 1–500 arasında yapılandırılabilir. Kaynak/üst asset ilişkisi saklanır ve taramalar yığılmayı azaltacak şekilde zamana yayılır.

Keşif pasiftir: bulunan adın canlı, hâlâ size ait veya taramaya yetkili olduğunuz bir sistem olduğunu kanıtlamaz. Envanteri gözden geçirin. Bu mekanizma sürekli brute-force enumerasyon veya bütün internet varlıklarının keşfi değildir. İndeks kapsamı, kota ve servis erişimi sonuçları etkiler. Keşif hatası “subdomain yok” demek değildir.

## Tarama profilleri ve zamanlama

| Profil | İçerik | Kullanım |
| --- | --- | --- |
| Native | TLS sertifika/protokol verileri, HTTP başlıkları/cookie özetleri, yapılandırılmışsa public DNS | Hafif ve düzenli izleme |
| Deep | Native gözlemler ve testssl.sh’nin sabit IDS-friendly profili | Daha maliyetli cipher/protokol/TLS zafiyet incelemesi |

İşler kuyruğa alınır; varsayılan paralellik 2, yapılandırılabilir aralık 1–8’dir. Zamanlayıcı varsayılan 30 saniyede bir zamanı gelen işleri kontrol eder. Büyük envanterde kuyruğun boşalması zaman alır. Süre ve kaynak kullanımını ölçmeden bütün asset’lere deep tarama başlatmayın.

Public DNS ifşası, DNSSEC, DMARC ve SPF için public resolver yapılandırması gerekir. Sistem resolver’ının split-horizon iç ağ cevabı, public ifşa kanıtı sayılmaz. Native protokol sonuçları yerel Node/OpenSSL yetenekleriyle sınırlanabilir; gerektiğinde deep profille doğrulayın.

Deep motor hatası, native gözlemleri koruyan `partial` tarama üretebilir; önceki deep incident’ları çözmez. Başarısız taramada son kullanılabilir snapshot korunur; yapılandırılmış aralık ile 15 dakikanın küçük olanı kadar sonra yeniden deneme planlanır. Bu yüzden başarısız taramanın yanında görünen eski not/bitiş tarihi güncel kanıt değildir.

Queued/running işler SQLite’ta izlenir. Restart sonrası yarıda kalan işler ele alınır; her ağ çağrısı kaldığı byte’tan sürdürülebilir değildir. Yeniden başlatma sonrası tarama geçmişini kontrol edin.

## Sonuçları yorumlamak

- `fail`: kuralın koşulunu destekleyen kanıt var; incident açılır/güncellenir.
- `pass`: yeterli kanıtla risk görülmedi; eşleşen incident çözülebilir.
- `unknown`: veri eksik, yetersiz veya kullanılamaz; mevcut incident kapanmamalıdır.

Başarılı iş durumu, akışın bittiğini belirtir; her probe’un kesin sonuç ürettiğini garanti etmez. Sadece durum rozeti veya nota değil, gözlem ve değerlendirmelere bakın. Nota yalnızca doğrulanmış fail’ler etki ettiği için A notunun yanında unknown kontroller bulunabilir.

Operasyonel notlar: critical F, high C, medium B, low A-, fail yoksa A. SSL Labs notu veya sertifikasyon değildir. HTTP başlığı/e-posta politikası bulgusu, ortamınıza göre doğrudan istismar edilebilir zafiyet yerine sıkılaştırma önerisi olabilir.

## Incident iş akışı

1. Başlığı, kanıtı, hostname/portu, önem derecesini ve tarama zamanını inceleyin.
2. İncelemeyi üstlendiğinizde `acknowledged` yapın; kontrol çalışmaya devam eder.
3. Sertifika/DNS/HTTP ayarını düzeltip yeni tarama başlatın.
4. Güvenilir `pass` otomatik çözer. Gerekçesiyle elle `resolved` da yapılabilir; sonraki fail tekrar açar.

Durumlar `open`, `acknowledged`, `resolved` şeklindedir. Tekrarlayan fail, aynı incident’ın kanıtını/önemini/son görülmesini/sayacını günceller. Çözülmüş sorun tekrarlarsa aynı ID ile yeniden açılır. Otomatik bildirim yalnızca açılma/yeniden açılmada üretilir; her taramada veya çözülmede değil.

Asset arşivlemek sonraki taramaları durdurur, geçmişi koruyarak aktif incident’ları kapatır. Bu, uzak sistemin düzeldiğinin kanıtı değildir; arşiv kaynaklı kapanmayı başarılı kontrolden ayırın.

Çoklu discriminator için `pass` sınırı dahil özel kural ayrıntıları: [Kendi incident türünü oluşturma](https://github.com/gorkemguler/HostCanvas/wiki/Ozel-Incident-Turu-Olusturma). Bildirim ve saklama politikası: [Operasyon](https://github.com/gorkemguler/HostCanvas/wiki/Operasyon-ve-Sorun-Giderme).
