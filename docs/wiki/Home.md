# HostCanvas Wiki

Local-first domain inventory, certificate monitoring, security checks and incident management. HostCanvas is not a full EASM platform and does not claim complete attack-surface coverage.

Yerelde çalışan domain envanteri, sertifika takibi, güvenlik kontrolleri ve incident yönetimi. HostCanvas tam kapsamlı bir EASM ürünü değildir.

## English documentation

1. [Installation and secure LAN access](https://github.com/gorkemguler/HostCanvas/wiki/Installation-and-LAN) — native/Docker setup, first administrator, HTTPS, origin and proxy settings.
2. [Inventory, scanning and incidents](https://github.com/gorkemguler/HostCanvas/wiki/Inventory-Scanning-and-Incidents) — asset fields, optional subdomain discovery, profiles, scheduling, coverage and lifecycle.
3. [Creating custom incident types](https://github.com/gorkemguler/HostCanvas/wiki/Custom-Incident-Types) — tested rule example, integration, evidence, multi-finding caveats, lifecycle tests and safe probe development.
4. [Operations and troubleshooting](https://github.com/gorkemguler/HostCanvas/wiki/Operations-and-Troubleshooting) — roles, webhook delivery, backups, restore, retention, diagnostics and limitations.
5. [Incident check policies](https://github.com/gorkemguler/HostCanvas/wiki/Check-Policies) — HSTS, scoped cookies, CAA, DNS-over-TLS opt-in and persistent scan-health incidents.

## Türkçe belgeler

1. [Kurulum ve güvenli LAN erişimi](https://github.com/gorkemguler/HostCanvas/wiki/Kurulum-ve-LAN) — native/Docker kurulum, ilk yönetici, HTTPS, origin ve proxy ayarları.
2. [Envanter, tarama ve incident yönetimi](https://github.com/gorkemguler/HostCanvas/wiki/Envanter-Tarama-ve-Incidentlar) — asset alanları, isteğe bağlı subdomain keşfi, profiller, zamanlama ve yaşam döngüsü.
3. [Kendi incident türünü oluşturma](https://github.com/gorkemguler/HostCanvas/wiki/Ozel-Incident-Turu-Olusturma) — test edilmiş kural örneği, entegrasyon, kanıt, çoklu bulgu sınırları, testler ve güvenli probe geliştirme.
4. [Operasyon ve sorun giderme](https://github.com/gorkemguler/HostCanvas/wiki/Operasyon-ve-Sorun-Giderme) — roller, webhook, yedekleme, geri yükleme, saklama politikası ve sınırlamalar.
5. [Incident kontrol politikaları](https://github.com/gorkemguler/HostCanvas/wiki/Kontrol-Politikalari) — HSTS, kapsamlı cookie ayarları, CAA, DNS-over-TLS onayı ve kalıcı tarama sağlığı incident’ları.

## Scope and safety / Kapsam ve güvenlik

- Scan only assets you own or are authorized to assess. / Yalnızca size ait veya taramaya yetkili olduğunuz varlıkları tarayın.
- LAN access requires authentication and HTTPS; keep the service off the public internet. / LAN erişiminde kimlik doğrulama ve HTTPS zorunludur; servisi doğrudan internete açmayın.
- Missing evidence is `unknown`, not proof of safety. / Eksik kanıt `unknown` demektir; güvenli olduğunun kanıtı değildir.
- Custom incident rules are code extensions today, not a visual template builder. / Özel incident kuralları bugün kodla eklenir; görsel template editörü bulunmaz.

[Repository / Depo](https://github.com/gorkemguler/HostCanvas) · [Versioned documentation source / Sürümlenen belge kaynağı](https://github.com/gorkemguler/HostCanvas/blob/main/docs/wiki-index.md) · [Environment reference / Ortam değişkenleri](https://github.com/gorkemguler/HostCanvas/blob/main/.env.example)

These pages describe the current `main` implementation in the 0.3.x line. For a pinned deployment, read the documentation at the matching Git commit. / Belgeler 0.3.x serisinin güncel `main` uygulamasını anlatır. Sabit bir sürüm kullanıyorsanız aynı Git commit’indeki belgeleri okuyun.
