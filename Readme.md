# EasyWireShark

Scapy tabanlı, terminal üzerinden çalışan eğitim amaçlı bir ağ paketi dinleyicisi. Program, seçilen ağ arayüzünde filtreye uyan IPv4 paketlerini yakalar; DNS, HTTP, FTP ve Telnet trafiğinin bazı alanlarını ayrıştırır, özet sayaçları tutar ve isteğe bağlı olarak yakalanan paketleri Wireshark'ta açılabilen `.pcap` dosyasına yazar.

> **Yasal ve etik kullanım:** Bu aracı yalnızca kendi cihazınızda/ağınızda veya açıkça izin verilmiş laboratuvar ortamında kullanın. Ağ trafiği kişisel ve hassas veriler içerebilir. Başkalarının trafiğini izinsiz yakalamayın, kaydetmeyin veya paylaşmayın. Bu depo eğitim amacı taşır; kullanım sorumluluğu kullanıcıya aittir.

## Neler yapar?

- BPF filtresiyle seçilen trafiği Scapy üzerinden yakalar.
- DNS sorgularında istenen alan adını, cevap kayıtlarında görülebilen IP adreslerini gösterir.
- HTTP istek metodunu, host bilgisini ve yolu; HTTP yanıt durum kodunu gösterir.
- HTTP Basic Auth ve form gövdesinde kimlik bilgisi olabilecek metinleri işaretler. Bu sezgisel bir aramadır, doğrulama değildir.
- FTP ve Telnet trafiğinde görülen ham metni ve `USER`/`PASS` benzeri satırları gösterir.
- Paket ve protokol sayaçlarıyla, görülen alan adlarıyla ve olası eşleşmelerle kapanış özeti üretir.
- `-o` seçeneğiyle yakalanan paketleri `.pcap` dosyasına kaydeder.

## Bu proje ne öğretir?

- Paketlerin IP, TCP/UDP ve uygulama katmanı alanlarının nasıl incelendiğini.
- DNS sorgusu/yanıtı ile HTTP istek/yanıtı arasındaki farkı.
- HTTP, FTP ve Telnet gibi şifresiz protokollerde içeriğin neden görülebildiğini.
- Base64'ün şifreleme olmadığını ve tek başına gizlilik sağlamadığını.
- BPF filtreleriyle paket yakalamanın nasıl daraltıldığını.

## Gereksinimler

- Python 3.8 veya üzeri
- Scapy (`requirements.txt` içinde)
- Paket yakalama erişimi: Linux/macOS'ta çoğunlukla yönetici/root yetkisi; Windows'ta Npcap

Windows'ta [Npcap](https://npcap.com/#download) kurun. Kurulum sırasında WinPcap API uyumluluk seçeneği gerekebilir. Yönetici yetkisiyle çalıştırın.

## Kurulum

```bash
git clone <REPOSITORY_URL>
cd WireSharkEasy
python -m venv .venv
```

Linux/macOS:

```bash
source .venv/bin/activate
python -m pip install -r requirements.txt
sudo .venv/bin/python EasyWireShark.py
```

Windows PowerShell:

```powershell
.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python EasyWireShark.py -i "Wi-Fi"
```

Windows'ta terminali yönetici olarak açın. Arayüz adını sisteminizdeki gerçek ada göre değiştirin. Linux'ta arayüzleri `ip link`, macOS'ta `ifconfig`, Windows'ta `ipconfig` ile inceleyebilirsiniz.

## Kullanım

```text
python EasyWireShark.py [-h] [-i INTERFACE] [-f FILTER] [-o OUTPUT] [-v] [-c COUNT]
```

| Seçenek | Açıklama | Varsayılan |
|---|---|---|
| `-i`, `--interface` | Dinlenecek ağ arayüzü | Scapy otomatik seçer |
| `-f`, `--filter` | BPF yakalama filtresi | `tcp port 80 or tcp port 21 or tcp port 23 or udp port 53` |
| `-o`, `--output` | Yakalanan paketleri kaydedecek `.pcap` yolu | Kayıt kapalı |
| `-v`, `--verbose` | Tanınan kategorilerin dışında kalan TCP paketlerini de gösterir | Kapalı |
| `-c`, `--count` | Belirtilen sayıda filtreye uyan paket sonrası durur; `0` sınırsızdır | `0` |

Örnekler:

```bash
# HTTP, FTP, Telnet ve DNS için varsayılan filtreyle başlat
sudo python EasyWireShark.py -i eth0

# Yalnızca HTTP trafiğini göster
sudo python EasyWireShark.py -f "tcp port 80" -v

# 100 paketten sonra bitir ve yakalamayı kaydet
sudo python EasyWireShark.py -c 100 -o lab-kaydi.pcap
```

Dinlemeyi Ctrl+C ile durdurabilirsiniz. Program özet üretir ve kayıt seçeneği verilmişse PCAP dosyasını yazar. Yakalama kapsamını dar tutun; `.pcap` dosyaları hassas içerik taşıyabilir.

## Kodun akışı

1. `main()` komut satırı seçeneklerini okur ve Scapy `sniff()` yakalamasını başlatır.
2. Her yakalanan paket `paket_isle()` callback fonksiyonuna gelir. IP katmanı olmayan paketler bu sürümde atlanır.
3. Callback, paketi DNS, HTTP istek/yanıtı veya FTP/Telnet işleyicisine yönlendirir. `-v`, diğer TCP paketleri için özet başlık bilgisi ekler.
4. `DinleyiciDurumu` sayaçları, görülen domainleri, olası kimlik bilgisi eşleşmelerini ve kayıt açıksa paketleri bellekte tutar.
5. Ctrl+C veya `--count` ile yakalama bitince özet basılır ve istenmişse paketler `wrpcap()` ile dosyaya yazılır.

`Renk` sınıfı terminal ANSI renk kodlarını içerir; protokollerin anlamını değiştirmez, çıktıyı renklendirir. Proje tek ana Python dosyasından oluşur; README dışında başka çalışma zamanı modülü yoktur.

## Sınırlamalar ve dikkat edilmesi gerekenler

- HTTPS/TLS içeriği çözülmez. Şifreli oturumların içindeki HTTP yolu, gövdesi veya kimlik bilgileri bu araçla okunamaz.
- Varsayılan filtre yalnızca belirtilen portları kapsar. Örneğin HTTPS (443) varsayılan filtreye dahil değildir.
- DNS-over-HTTPS/DNS-over-TLS gibi şifreli DNS yöntemleri normal DNS sorgusu olarak görünmeyebilir.
- Bu sürüm yalnızca IPv4 `IP` katmanı olan paketleri işler; ARP ve IPv6 ayrıştırılmaz.
- HTTP/FTP/Telnet analizleri protokol ayrıştırma ve ham payload üzerinde yapılan basit kontrollerdir. TCP segmentleri uygulama mesajlarıyla birebir örtüşmeyebilir; bu nedenle kayıtlar eksik veya yanlış pozitif olabilir.
- `--count`, BPF filtresine uyan yakalanan paketleri sayar; protokol sayaçları ise yalnızca kodun tanıdığı mesaj/olaylar için artar. Bunlar aynı sayı değildir.
- `-o` seçeneği yakalanan paketleri bellekte biriktirir; uzun yakalamalarda bellek kullanımı artabilir.
- Paket yakalama platforma, ağ kartına, sürücüye ve yetkilere bağlıdır. Her cihazda aynı sonuç garanti edilmez.

## İleri seviye geliştirme fikirleri

Bu maddeler mevcut özellik değildir; ileride projeye eklenebilecek fikirlerdir:

1. **Modüler mimari:** Yakalama, protokol ayrıştırıcıları, raporlama ve CLI kodlarını ayrı Python modüllerine bölmek; işleyiciler için ortak arayüz tanımlamak.
2. **IPv6 ve ARP desteği:** IPv6 katmanlarını ayrıştırmak; ARP istek/yanıtlarını ayrı sayaçlarla göstermek. ARP işlenirken IP katmanı zorunlu varsayımını kaldırmak gerekir.
3. **PCAPNG ve akış takibi:** PCAPNG desteği, TCP akışlarını yeniden birleştirme ve parçalara bölünmüş HTTP mesajlarını doğru analiz etme.
4. **Daha güvenli veri işleme:** Kimlik bilgisi içeriğini varsayılan olarak göstermemek; maskeleme, izinli test modu ve hassas PCAP dosyaları için açık uyarı seçenekleri eklemek.
5. **Konfigürasyon ve filtre profilleri:** Hazır protokol profilleri, filtre doğrulaması ve yapılandırma dosyası desteği.
6. **Canlı istatistik arayüzü:** Paket hızı, protokol dağılımı ve en çok görülen uç noktalar için terminal paneli veya yerel web arayüzü.
7. **Dışa aktarma ve depolama:** JSON/CSV raporu veya SQLite depolama; saklama süresi ve veri minimizasyonu ayarları.
8. **Tespit kuralları:** Şüpheli tarama ve olağandışı bağlantı örüntüleri için ayarlanabilir kurallar, önem derecesi ve açıklanabilir uyarılar.
9. **Test ve kalite:** Örnek/anonim PCAP dosyalarıyla birim testleri, statik analiz, biçimlendirme ve otomatik CI iş akışı.
10. **Kullanılabilirlik:** Arayüz listesini uygulama içinden gösterme, renk desteklenmeyen terminalleri algılama ve daha anlaşılır hata mesajları.

## Proje dosyaları

```text
EasyWireShark.py   # Paket yakalama ve analiz uygulaması
Readme.md          # Kurulum, kullanım, sınırlar ve geliştirme fikirleri
requirements.txt   # Python bağımlılıkları
LICENSE            # MIT lisansı
```

## Lisans

Bu proje MIT lisansı altındadır. Ayrıntılar için [LICENSE](LICENSE) dosyasına bakın.
