# Rust Süreç Gezgini (macOS) — Tasarım

Tarih: 2026-11-05 · Durum: onay bekliyor

## Amaç ve neden

Kullanıcı macOS'ta Windows Process Explorer benzeri, detaylı bir süreç gezgini istiyor. Mevcut
`ptree.py` (curses, Terminal'de çalışan) yalnızca ağaç + öldürme yapıyor. Yeni sürüm Rust ile,
kendi penceresi olan native bir uygulama olacak ve Process Explorer'daki detayın macOS'ta
karşılığı olan her şeyi içerecek. Kullanıcının ölçütü: "detaylı ne varsa koy, hepsi kalsın."

## Hedefler (kullanıcının onayladığı kapsam)

### Ana pencere — süreç ağacı
- Ebeveyn → çocuk ağacı, dalları açıp kapama; düz liste moduna geçiş (ağaçsız, sıralanabilir).
- Sütunlar: ikon + ad, PID, CPU %, bellek (RSS), thread sayısı, kullanıcı, açıklama, şirket.
  Sütun başlığına tıklayınca sıralama (ağaç modunda kardeşler arasında sıralanır);
  sütunlar açılıp kapatılabilir.
- Renkler (Process Explorer mantığı): kendi süreçlerin, sistem/root süreçleri, yeni başlayan
  (yeşil vurgu, birkaç saniye), kapanan (kırmızı vurgu, birkaç saniye sonra kaybolur),
  duraklatılmış (gri).
- Arama/filtre kutusu: ad, PID veya yol; eşleşenler ebeveynleriyle birlikte gösterilir
  (`ptree.py`'deki davranış).
- Uygulama ikonları.

### Alt panel — seçili süreç
Sekmeler:
- **Açık dosyalar ve soketler** (Windows "handles" karşılığı): tür, yol / adres.
- **Kütüphaneler** (DLL karşılığı): yüklü dylib / eşlenmiş dosyalar.
- **Thread'ler**: ID, ad, CPU kullanımı, durum.
- **Ağ**: TCP/UDP bağlantıları — yerel/uzak adres, port, durum.

### Özellikler penceresi (satıra çift tık)
Tam yol ve komut satırı, ortam değişkenleri, çalışma klasörü, başlama zamanı, ebeveyn,
kullanıcı, imza bilgisi (imzalı mı, imzalayan, Team ID), CPU ve bellek geçmişi grafikleri.

### Üst çubuk
Sistem geneli CPU, bellek, disk G/Ç ve ağ G/Ç için mini zaman grafikleri.

### Eylemler (sağ tık menüsü + kısayollar)
- Sonlandır (SIGTERM), zorla sonlandır (SIGKILL), ağacı sonlandır (önce çocuklar).
- Duraklat / devam ettir (SIGSTOP / SIGCONT).
- Öncelik (nice) değiştir.
- Finder'da göster.
- **Nişangâh**: araç çubuğundan sürükleyip bir pencerenin üstünde bırakınca o pencerenin
  sahibi süreç ağaçta seçilir.
- Yıkıcı her eylem (sonlandır, ağacı sonlandır, zorla sonlandır) onay ister.

### Yetki
- Normal kullanıcıyla açılır. Araç çubuğunda **"Yönetici modu"** düğmesi (macOS şifre
  penceresi). Kullanıcı bunu yeterli buldu; şifresiz kalıcı tam yetki istenmiyor.
- Uygulama (Claude kararı): pencere her zaman normal kullanıcı olarak kalır — root GUI'de
  ikon, Dock ve pencere listesi davranışı güvenilir değil. Düğme, aynı binary'yi `--helper`
  bayrağıyla root olarak başlatır (`osascript … with administrator privileges`). Helper
  detay okuma ve sinyal gönderme isteklerini yerel bir Unix soketi üzerinden, rastgele bir
  token ile doğrulayarak karşılar. Hiçbir şey kurulmaz; uygulama kapanınca veya soket
  kopunca helper da kapanır. Bu yüzden veri okuma kodu baştan helper'da da çalışabilecek
  şekilde ayrı bir katman olmalı.
- Yetki yüzünden okunamayan detaylar boş kalmaz: "Erişim yok — yönetici olarak yeniden başlatın"
  yazar.

### VirusTotal (isteğe bağlı)
- Varsayılan **kapalı**. Ayarlardan açılır, kullanıcı kendi API anahtarını girer.
- Açıkken yalnızca çalıştırılabilir dosyanın SHA-256 özeti gönderilir, dosya asla yüklenmez.
  Sonuç (ör. `0/72`) ayrı bir sütunda gösterilir.
- **Tüm süreçler otomatik kontrol edilir** (kullanıcı kararı): arka planda hız sınırlı bir
  kuyruk (ücretsiz anahtar: dakikada 4, günde 500 sorgu; günlük sınır dolunca ertesi güne
  kalır). Aynı yürütülebilir dosyayı kullanan süreçler tek sorgu sayılır. Sütunda durumlar:
  `bekliyor`, `sorgulanıyor`, `bilinmiyor` (VT'de kaydı yok), `x/y`, `hata`. Sonuçlar diskte
  önbellekte tutulur ve yeniden başlatmada korunur; dosya değişirse (özet değişir) yeniden
  sorgulanır. Özet hesaplama düşük öncelikli arka plan işidir ve CPU bütçesine dahildir.
- Sağ tık "Şimdi kontrol et" seçili süreci kuyruğun başına alır.

## Hedef olmayanlar
- Windows/Linux desteği.
- Süreç başına GPU kullanımı (macOS'ta güvenilir kaynak yok — kullanıcıya bildirildi).
- Şifre sormadan kalıcı root yetkisi, launchd helper, App Store dağıtımı, notarization.
- Dosya içeriğini herhangi bir servise yüklemek.

## Anti-hedefler (çalışsa bile başarısızlık sayılır)
- Uygulamanın kendisinin ~600 süreçte, tek çekirdeğe göre (Activity Monitor ölçeği) ölçülen
  CPU bütçesini aşması (Claude kararı): pencere arka planda veya simge durumundayken **%2**,
  önde ve görünür ama kullanıcı bir şey yapmıyorken **%5**. CPU % sütunu da aynı ölçeği
  kullanır (100% = bir çekirdek), Mac geleneğine uygun.
- Sistem diline göre bozulmak (`ptree.py`'deki `3,7` hatası gibi) — sayı biçimlendirme ve
  ayrıştırma locale'den bağımsız olmalı.
- Onaysız süreç öldürmek.
- Kullanıcı izni olmadan ağa veri göndermek.

## Kısıtlar ve kararlar

| Konu | Karar | Kimin |
|------|-------|-------|
| Dil | Rust | kullanıcı |
| Platform | Yalnızca macOS (Apple Silicon, Darwin 25) | kullanıcı (bağlam) |
| Kapsam | Yukarıdaki listenin tamamı | kullanıcı |
| Yetki modeli | "Yönetici olarak yeniden başlat" düğmesi | kullanıcı |
| GUI | egui / eframe | Claude |
| Süreç, CPU, bellek, sistem G/Ç | `sysinfo` crate | Claude |
| Dosyalar, soketler, thread'ler, eşlenmiş bölgeler | `libproc` (proc_pidinfo / proc_pidfdinfo / PROC_PIDREGIONPATHINFO); hazır crate yetmezse doğrudan FFI | Claude |
| İmza, şirket | Security framework (SecStaticCode + signing information); şirket = imzalayan sertifikanın kurum adı | Claude |
| Açıklama | `.app` içindeyse Info.plist'teki ad/açıklama, yoksa boş | Claude |
| İkonlar | NSWorkspace (objc2) → egui texture; yola göre önbellek | Claude |
| Nişangâh | CGWindowListCopyWindowInfo ile bırakılan noktadaki en üstteki pencerenin sahip PID'si | Claude |
| Yenileme | Arka plan örnekleme thread'i, varsayılan 1 sn, ayarlanabilir; detaylar yalnızca seçili süreç için okunur | Claude |
| Arayüz dili | Türkçe | Claude |
| Konum | `taskmanager/` altında ayrı Cargo projesi; `ptree.py` yedek olarak kalır | Claude |
| Paket | `.app` paketi, `~/Applications/Process Tree.app`'in yerini alır (mevcut Python sarmalayıcısını değiştirir), ad-hoc imzalı | Claude |

## Bilinen macOS sınırları (kullanıcı bilmeli)
- Sistem çerçevelerinin çoğu dyld paylaşımlı önbelleğinden gelir; kütüphaneler sekmesinde
  tek tek değil, paylaşımlı önbellek dosyası olarak görünebilirler. Yalnızca diskte ayrı duran
  dylib'ler isimleriyle listelenir.
- Root olarak bile SIP korumalı bazı süreçlerin detayları okunamaz; bu durumda "erişim yok"
  gösterilir.
- Nişangâh pencere başlıkları için Ekran Kaydı izni gerekebilir; PID için gerekmez.

## Test yaklaşımı
- Saf mantık birim testli: ağaç kurma, filtre (ebeveynler korunur), sıralama, yeni/kapanan
  süreç farkı, ağacı sonlandırma sırası (önce yapraklar), sayı biçimlendirme (locale bağımsız).
- Veri toplayıcılar kendi süreci üzerinde entegrasyon testli: geçici dosya aç → açık dosyalar
  listesinde görünsün; TCP soket aç → ağ listesinde görünsün; çocuk süreç başlat → ağaçta
  ebeveynin altında görünsün; thread başlat → thread sayısı artsın.
- CPU bütçesi ölçülür: uygulamanın kendi PID'sinin CPU'su 60 sn boyunca hem arka planda
  (%2 altı) hem önde görünürken (%5 altı) ölçülür.

## İnşa edene bırakılanlar
Modül yapısı, crate sürümleri, renk tonları, kısayol tuşları, panel boyutları, grafik geçmiş
uzunluğu, ayarların nerede saklandığı (ör. `~/Library/Application Support/`), hata
mesajlarının tam metni.
