# Gelişmiş Paket Dinleyici (Packet Sniffer)

Eğitim amaçlı, `Scapy` tabanlı bir ağ trafiği analiz aracı. HTTP, DNS, FTP ve
Telnet trafiğini yakalar, düz metin kimlik bilgilerini tespit eder ve
yakalanan paketleri `.pcap` dosyasına kaydeder.

> ⚠️ **Yasal Uyarı**
> Bu araç sadece **kendi ağınızda**, **kendi trafiğinizde** veya üzerinde
> **açıkça izniniz olan** sistemlerde (örn. kendi lab/test ortamınız)
> kullanılmalıdır. Başkasına ait ağ trafiğini izinsiz dinlemek/kaydetmek
> Türkiye'de TCK 243–244 ve KVKK kapsamında suç teşkil edebilir. Bu proje
> yalnızca ağ protokollerini ve güvenlik kavramlarını öğrenmek amacıyla
> hazırlanmıştır.

## Bu Proje Ne Öğretir?

- **Paket anatomisi**: Header (başlık) ve payload (veri yükü) ayrımı
- **OSI katmanları**: IP (Katman 3), TCP/UDP (Katman 4), HTTP/DNS/FTP (Katman 7)
- **Şifresiz protokollerin riski**: HTTP, FTP, Telnet düz metin gönderir;
  HTTPS/SSH ise şifreler — bu farkı canlı örneklerle görürsünüz
- **Base64 ≠ şifreleme**: HTTP Basic Auth örneğiyle Base64'ün sadece bir
  kodlama yöntemi olduğunu, güvenlik sağlamadığını gösterir
- **BPF filtreleri**: `tcp port 80` gibi filtre ifadeleriyle trafiği
  hedeflemeyi öğretir

## Gereksinimler

- Python 3.8+
- Root / Administrator yetkisi (ham soket erişimi için zorunludur)
- Linux, macOS veya Windows (Npcap kurulu olmalı — aşağıya bakın)

## Kurulum

```bash
# Sanal ortam oluşturmanız önerilir
python3 -m venv venv
source venv/bin/activate      # Windows: venv\Scripts\activate

pip install -r requirements.txt
```

### Windows için ek adım

Scapy, Windows'ta paket yakalamak için [Npcap](https://npcap.com/#download)
gerektirir. Kurulum sırasında **"WinPcap API-compatible Mode"** seçeneğini
işaretleyin.

## Kullanım

En basit haliyle çalıştırma:

```bash
sudo python3 EasyWireShark.py
```

### Komut satırı seçenekleri

| Parametre         | Açıklama                                                        | Varsayılan                                    |
|--------------------|-------------------------------------------------------------------|------------------------------------------------|
| `-i`, `--interface` | Dinlenecek ağ arayüzü (örn. `eth0`, `wlan0`, `Wi-Fi`) | Otomatik seçim |
| `-f`, `--filter` | BPF filtre ifadesi | `tcp port 80 or tcp port 21 or tcp port 23 or udp port 53` |
| `-o`, `--output` | Yakalanan paketleri kaydedeceğiniz `.pcap` dosyası | Kapalı (kaydetmez) |
| `-v`, `--verbose` | Kategorize edilmemiş TCP paketlerini de göster | Kapalı |
| `-c`, `--count` | Belirli sayıda paket sonrası otomatik dur (`0` = sınırsız) | `0` |

### Örnekler

```bash
# Belirli bir arayüzü dinle ve trafiği kaydet
sudo python3 EasyWireShark.py -i eth0 -o kayit.pcap

# Sadece HTTP trafiğini, ayrıntılı modda dinle
sudo python3 EasyWireShark.py -f "tcp port 80" -v

# 100 paket yakalayınca otomatik dur
sudo python3 EasyWireShark.py -c 100
```

Ağ arayüzü adınızı öğrenmek için:

```bash
ip a          # Linux
ifconfig      # macOS
ipconfig      # Windows
```

## Örnek Çıktı

```
[14:32:07] [DNS SORGU] 192.168.1.34 -> 'example.com'
    -> çözümlenen IP: 93.184.216.34
[14:32:09] [HTTP GET] 192.168.1.34 -> http://example.com/login
    [!] Form verisinde olası kimlik bilgisi: ['ali123']

============================================================
DİNLEME ÖZETİ
============================================================
Süre                 : 42.3 saniye
Toplam paket         : 156
Protokol dağılımı    : {'DNS': 34, 'HTTP': 12}
Ziyaret edilen site  : 8 farklı domain

TESPİT EDİLEN KİMLİK BİLGİLERİ (1):
  [14:32:09] HTTP-Form: ['ali123']
============================================================
```

## Proje Yapısı

```
.
├── EasyWireShark.py        # Ana script
├── requirements.txt        # Python bağımlılıkları
└── README.md                # Bu dosya
```

## Sınırlamalar

- **HTTPS trafiği okunamaz** — TLS ile şifrelendiği için içerik görünmez;
  sadece hangi IP/porta bağlanıldığı görülebilir.
- Modern web siteleri çoğunlukla DNS-over-HTTPS (DoH) kullanabildiği için
  DNS sorguları da her zaman düz metin görünmeyebilir.
- Anahtar kelime/regex tabanlı kimlik bilgisi tespiti kesin değildir; yanlış
  pozitif veya negatif sonuçlar verebilir.

## Olası Geliştirmeler

- Canlı istatistik paneli için `threading`
- ARP spoofing / MITM tespiti
- Yakalanan verileri SQLite veritabanına kaydetme
- GeoIP ile IP'lerin coğrafi konumunu gösterme

## Lisans / Sorumluluk Reddi

Bu proje eğitim amaçlıdır, hiçbir garanti verilmez. Kullanımından doğacak
her türlü sorumluluk kullanıcıya aittir.