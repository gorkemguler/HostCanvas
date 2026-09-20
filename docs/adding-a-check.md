# Yeni kontrol / özel incident türü ekleme

Tam rehberler:

- [Türkçe: Kendi incident türünü oluşturma](wiki/Ozel-Incident-Turu-Olusturma.md)
- [English: Creating custom incident types](wiki/Custom-Incident-Types.md)
- [Wiki sürümü](https://github.com/gorkemguler/HostCanvas/wiki/Ozel-Incident-Turu-Olusturma)

HostCanvas şu anda kodla tanımlanan kurallar kullanır; panelden template yükleme veya görsel kural editörü yoktur. Yeni kontrol için gözlem toplayan probe ile karar veren kural birbirinden ayrılır:

```text
doğrulanmış ve IP’si sabitlenmiş hedef → probe → observation
observation + politika → saf kural → pass | fail | unknown
değerlendirmeler → incident reconciliation → açılma/yeniden açılma bildirimi
```

## En kısa yol

1. Mevcut TLS/HTTP/DNS gözleminde yeterli veri varsa yeni ağ isteği eklemeyin.
2. [Çalışır sertifika ömrü örneğini](../examples/custom-check/certificate-validity.mjs) başlangıç alın. Örneğin 90 günlük eşiği bir kurum politikasıdır; genel CA zorunluluğu iddiası değildir.
3. `server/rules/index.mjs` içinde `ruleCatalog` kaydını **ve** `evaluateObservations` içindeki fonksiyon çağrısını ekleyin. Yalnızca katalog kaydı kontrolü çalıştırmaz.
4. [Örnek testlerdeki](../tests/custom-check-example.test.mjs) fail/pass/unknown, sınır değerleri ve yaşam döngüsü senaryolarını yeni üretim modülüne uyarlayın; ana evaluator entegrasyonunu ayrıca test edin.
5. Testleri çalıştırın, API’yi yeniden başlatın veya Docker image’ını yeniden derleyin. Yetkili test varlığında aynı bulgunun tekrarında aynı incident’ın güncellendiğini doğrulayın.

## Değişmez kurallar

- Eksik/timeout/bozuk gözlem `unknown` olmalı; mevcut incident’ı çözmemeli.
- Sabit `ruleKey` kullanın. Sertifika rotasyonu veya scan ID yüzünden kimliği değiştirmeyin.
- `enabled` katalog metadatası, `recommendedCadence` gösterim önerisidir; genel runtime kapatma veya bağımsız kural zamanlaması sağlamaz.
- Mevcut reconciliation’da `pass`, aynı asset ve ruleKey altındaki **bütün** aktif discriminator’ları çözer. Aynı kural için alt-öğe bazında pass ve fail karıştırmayın. Ayrıntılı rehber çoklu sonuç stratejisini açıklar.
- `completePrefixes` yalnızca gerçekten tam taranan, dar ve kuralın sahip olduğu isim alanlarında kullanılmalıdır; kısmi sonuçta kapatma yapmayın.
- Kanıt küçük, JSON-serileştirilebilir ve secret içermeyen veri olmalıdır. UI’ya güvensiz HTML basmayın.
- Kuraldan ağ isteği, veritabanı yazımı veya webhook gönderimi yapmayın; ilgili mevcut katmanı kullanın.

Örnek varsayılan uygulamaya etkinleştirilmiş değildir. Entegrasyon adımları, kanıt sözleşmesi, bildirim davranışı, yeni probe güvenliği ve hata giderme için yukarıdaki tam rehberleri okuyun.
