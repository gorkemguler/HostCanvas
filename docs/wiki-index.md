# HostCanvas documentation / Belgeler

The Markdown files below are the versioned source for the [GitHub Wiki](https://github.com/gorkemguler/HostCanvas/wiki). They can also be read directly in the repository or offline. / Aşağıdaki Markdown dosyaları GitHub Wiki’nin sürümlenen kaynağıdır; doğrudan depodan veya çevrimdışı da okunabilir.

| English | Türkçe |
| --- | --- |
| [Installation and LAN](wiki/Installation-and-LAN.md) | [Kurulum ve LAN](wiki/Kurulum-ve-LAN.md) |
| [Inventory, scanning and incidents](wiki/Inventory-Scanning-and-Incidents.md) | [Envanter, tarama ve incident](wiki/Envanter-Tarama-ve-Incidentlar.md) |
| [Creating custom incident types](wiki/Custom-Incident-Types.md) | [Kendi incident türünü oluşturma](wiki/Ozel-Incident-Turu-Olusturma.md) |
| [Operations and troubleshooting](wiki/Operations-and-Troubleshooting.md) | [Operasyon ve sorun giderme](wiki/Operasyon-ve-Sorun-Giderme.md) |

## Tested custom-rule example / Test edilen özel kural örneği

- [Runnable certificate-lifetime rule / Çalışır sertifika ömrü kuralı](../examples/custom-check/certificate-validity.mjs)
- [Unit and lifecycle tests / Birim ve yaşam döngüsü testleri](../tests/custom-check-example.test.mjs)
- The example is not enabled by default. Follow the guide to register **and invoke** it. / Örnek varsayılan olarak etkin değildir; rehberdeki katalog kaydı **ve fonksiyon çağrısı** adımlarını izleyin.

## Maintaining the Wiki / Wiki bakımı

Edit `docs/wiki/*.md` in the main repository first and review the diff. Publish those same files to the separate `HostCanvas.wiki.git` repository; `_Sidebar.md` and `_Footer.md` provide shared navigation. GitHub may require creating the first Wiki page through the signed-in web interface before that Git repository exists. Do not overwrite unrelated Wiki pages or force-push its history.

Önce ana depodaki `docs/wiki/*.md` dosyalarını düzenleyip diff’i inceleyin. Aynı dosyaları ayrı `HostCanvas.wiki.git` deposuna yayınlayın; `_Sidebar.md` ve `_Footer.md` ortak navigasyondur. Wiki Git deposu oluşmadan önce GitHub web arayüzünde oturum açarak ilk sayfayı oluşturmak gerekebilir. İlgisiz sayfaları veya Wiki geçmişini ezmeyin.
