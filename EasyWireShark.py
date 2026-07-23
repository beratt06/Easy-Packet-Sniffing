#!/usr/bin/env python3
"""
Gelişmiş Paket Dinleyici (Advanced Packet Sniffer) - Eğitim Amaçlı
=====================================================================
Bu araç; HTTP, DNS, FTP ve Telnet trafiğini analiz eder, düz metin
kimlik bilgilerini tespit eder, yakalanan trafiği bir .pcap dosyasına
kaydeder ve program sonunda özet istatistik raporu üretir.

KULLANIM UYARISI:
- SADECE kendi ağınızda / laboratuvar ortamında, kendi trafiğinizde
  veya izniniz olan sistemlerde kullanın.
- Başkasının trafiğini izinsiz dinlemek/kaydetmek birçok ülkede suçtur
  (örn. Türkiye'de TCK 243/244, KVKK kapsamında sorumluluk doğurabilir).
- Root/Administrator yetkisi gerektirir.

Kurulum:
    pip install scapy

Çalıştırma örnekleri:
    sudo python3 gelismis_dinleyici.py
    sudo python3 gelismis_dinleyici.py -i eth0 -o kayit.pcap
    sudo python3 gelismis_dinleyici.py --filter "tcp port 80" -v
"""

import argparse
import base64
import re
import signal
import sys
import time
from collections import Counter
from datetime import datetime

from scapy.all import sniff, wrpcap, IP, TCP, UDP, Raw
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.http import HTTPRequest, HTTPResponse


# ---------------------------------------------------------------------
# TERMİNAL RENKLERİ (harici kütüphaneye gerek kalmasın diye ham ANSI kodları)
# ---------------------------------------------------------------------
class Renk:
    KIRMIZI = "\033[91m"
    YESIL = "\033[92m"
    SARI = "\033[93m"
    MAVI = "\033[94m"
    MOR = "\033[95m"
    CYAN = "\033[96m"
    GRI = "\033[90m"
    SIFIRLA = "\033[0m"
    KALIN = "\033[1m"


# ---------------------------------------------------------------------
# GLOBAL DURUM: Program çalışırken toplanan istatistikler ve yakalanan
# paketler. Bunları bir sınıf içinde tutmak, main() ve callback
# fonksiyonu arasında "global" anahtar kelimesi kirliliği yaratmadan
# veri paylaşmamızı sağlar.
# ---------------------------------------------------------------------
class DinleyiciDurumu:
    def __init__(self):
        self.baslangic_zamani = time.time()
        self.toplam_paket = 0
        self.protokol_sayaci = Counter()      # {"HTTP": 5, "DNS": 12, ...}
        self.ziyaret_edilen_siteler = set()   # Tekrar eden DNS sorgularını tekilleştirir
        self.bulunan_kimlik_bilgileri = []    # [(zaman, protokol, detay), ...]
        self.yakalanan_paketler = []          # pcap'e yazmak için ham paket listesi


durum = DinleyiciDurumu()


# ---------------------------------------------------------------------
# YARDIMCI FONKSİYONLAR
# ---------------------------------------------------------------------

def zaman_damgasi():
    """Okunabilir saat damgası üretir, örn: 14:32:07"""
    return datetime.now().strftime("%H:%M:%S")


def kimlik_bilgisi_ara(veri: str) -> list:
    """
    Ham metin (payload) içinde kullanıcı adı/şifre benzeri kalıpları
    regex ile arar. Bu, gerçek DLP (Data Loss Prevention) araçlarının
    kullandığı yöntemin çok basitleştirilmiş halidir.

    Neden regex? Çünkü form verileri genelde
    'anahtar=deger&anahtar2=deger2' (URL-encoded) formatında gelir;
    bunu satır satır ayrıştırmak yerine desen eşleştirme kullanıyoruz.
    """
    kaliplar = [
        r'(?:user(?:name)?|login|email)\s*=\s*([^&\s]+)',
        r'(?:pass(?:word)?|pwd)\s*=\s*([^&\s]+)',
    ]
    bulunanlar = []
    for kalip in kaliplar:
        eslesmeler = re.findall(kalip, veri, re.IGNORECASE)
        bulunanlar.extend(eslesmeler)
    return bulunanlar


def basic_auth_coz(header_degeri: str) -> str:
    """
    HTTP Basic Authentication, kullanıcı:şifre bilgisini Base64 ile
    kodlar (ŞİFRELEMEZ, sadece kodlar!). 'Authorization: Basic xxxx'
    başlığını yakaladığımızda bunu çözüp göstermek, Base64'ün bir
    güvenlik önlemi OLMADIĞINI somut olarak öğretir.
    """
    try:
        kodlanmis = header_degeri.split()[1]
        cozulmus = base64.b64decode(kodlanmis).decode('utf-8', errors='ignore')
        return cozulmus  # "kullanici:sifre" formatında döner
    except Exception:
        return "(çözülemedi)"


# ---------------------------------------------------------------------
# PROTOKOLE ÖZEL İŞLEYİCİLER
# Her fonksiyon tek bir protokolden sorumludur (Single Responsibility
# prensibi) — bu, kodu hem okunur hem de genişletilebilir kılar.
# ---------------------------------------------------------------------

def dns_isle(paket):
    """DNS sorgu ve cevaplarını ayrıştırır."""
    if paket.haslayer(DNSQR):
        site = paket[DNSQR].qname.decode('utf-8', errors='ignore').rstrip('.')
        if site not in durum.ziyaret_edilen_siteler:
            durum.ziyaret_edilen_siteler.add(site)
            print(f"{Renk.MAVI}[{zaman_damgasi()}] [DNS SORGU]{Renk.SIFIRLA} "
                  f"{paket[IP].src} -> '{site}'")
        durum.protokol_sayaci["DNS"] += 1

    # DNSRR = DNS Resource Record (cevap kısmı). Sorgunun IP cevabını
    # da göstermek istersek burayı kullanırız.
    if paket.haslayer(DNSRR) and paket[DNS].ancount > 0:
        try:
            cevap_ip = paket[DNSRR].rdata
            print(f"{Renk.GRI}    -> çözümlenen IP: {cevap_ip}{Renk.SIFIRLA}")
        except Exception:
            pass


def http_istek_isle(paket):
    """HTTP isteklerini (GET/POST vb.) ayrıştırır."""
    http = paket[HTTPRequest]
    host = http.Host.decode(errors='ignore') if http.Host else "?"
    yol = http.Path.decode(errors='ignore') if http.Path else "?"
    metod = http.Method.decode(errors='ignore') if http.Method else "?"

    print(f"{Renk.YESIL}[{zaman_damgasi()}] [HTTP {metod}]{Renk.SIFIRLA} "
          f"{paket[IP].src} -> http://{host}{yol}")
    durum.protokol_sayaci["HTTP"] += 1

    # Basic Auth kontrolü
    if hasattr(http, 'Authorization') and http.Authorization:
        auth_deger = http.Authorization.decode(errors='ignore')
        if 'Basic' in auth_deger:
            cozulmus = basic_auth_coz(auth_deger)
            mesaj = f"HTTP Basic Auth çözüldü: {cozulmus}"
            print(f"{Renk.KIRMIZI}{Renk.KALIN}    [!] {mesaj}{Renk.SIFIRLA}")
            durum.bulunan_kimlik_bilgileri.append((zaman_damgasi(), "HTTP-BasicAuth", cozulmus))

    # POST body içinde form verisi / şifre arama
    if paket.haslayer(Raw):
        try:
            yuk = paket[Raw].load.decode('utf-8', errors='ignore')
            bulunanlar = kimlik_bilgisi_ara(yuk)
            if bulunanlar:
                mesaj = f"Form verisinde olası kimlik bilgisi: {bulunanlar}"
                print(f"{Renk.KIRMIZI}{Renk.KALIN}    [!] {mesaj}{Renk.SIFIRLA}")
                durum.bulunan_kimlik_bilgileri.append((zaman_damgasi(), "HTTP-Form", str(bulunanlar)))
        except Exception:
            pass


def http_cevap_isle(paket):
    """HTTP sunucu cevaplarını (status code) ayrıştırır."""
    http = paket[HTTPResponse]
    durum_kodu = http.Status_Code.decode(errors='ignore') if http.Status_Code else "?"
    print(f"{Renk.GRI}[{zaman_damgasi()}] [HTTP CEVAP] {paket[IP].src} -> "
          f"durum kodu: {durum_kodu}{Renk.SIFIRLA}")
    durum.protokol_sayaci["HTTP-Response"] += 1


def ftp_telnet_isle(paket):
    """
    FTP (port 21) ve Telnet (port 23) tamamen şifresizdir; kullanıcı
    adı/şifre satır satır düz metin olarak gönderilir. Bu protokoller
    günümüzde SSH/SFTP ile değiştirildi ama hâlâ bazı eski sistemlerde
    kullanılıyor -- bu yüzden dinleyicimize dahil ediyoruz.
    """
    if not paket.haslayer(Raw):
        return

    port = None
    if paket.haslayer(TCP):
        port = paket[TCP].dport if paket[TCP].dport in (21, 23) else paket[TCP].sport

    if port not in (21, 23):
        return

    veri = paket[Raw].load.decode('utf-8', errors='ignore').strip()
    if not veri:
        return

    protokol_adi = "FTP" if port == 21 else "TELNET"
    print(f"{Renk.SARI}[{zaman_damgasi()}] [{protokol_adi}]{Renk.SIFIRLA} "
          f"{paket[IP].src} -> {veri}")
    durum.protokol_sayaci[protokol_adi] += 1

    if re.search(r'(USER|PASS)\s+', veri, re.IGNORECASE):
        print(f"{Renk.KIRMIZI}{Renk.KALIN}    [!] Düz metin kimlik bilgisi: {veri}{Renk.SIFIRLA}")
        durum.bulunan_kimlik_bilgileri.append((zaman_damgasi(), protokol_adi, veri))


# ---------------------------------------------------------------------
# ANA CALLBACK: sniff() her paket yakaladığında burası tetiklenir.
# Bu fonksiyon bir "dispatcher" (yönlendirici) gibi çalışır: paketin
# türüne bakıp doğru işleyiciye yönlendirir.
# ---------------------------------------------------------------------

def paket_isle(paket, pcap_kaydet: bool, ayrintili: bool):
    if not paket.haslayer(IP):
        return

    durum.toplam_paket += 1
    if pcap_kaydet:
        durum.yakalanan_paketler.append(paket)

    try:
        if paket.haslayer(DNSQR) or paket.haslayer(DNSRR):
            dns_isle(paket)
        elif paket.haslayer(HTTPRequest):
            http_istek_isle(paket)
        elif paket.haslayer(HTTPResponse):
            http_cevap_isle(paket)
        elif paket.haslayer(TCP) and (paket[TCP].dport in (21, 23) or paket[TCP].sport in (21, 23)):
            ftp_telnet_isle(paket)
        elif ayrintili and paket.haslayer(TCP):
            # -v (verbose) modunda, yukarıdaki hiçbir kategoriye
            # girmeyen TCP paketlerini de ham başlık bilgisiyle gösterir.
            print(f"{Renk.GRI}[{zaman_damgasi()}] [TCP] {paket[IP].src}:{paket[TCP].sport} "
                  f"-> {paket[IP].dst}:{paket[TCP].dport}{Renk.SIFIRLA}")
    except Exception as hata:
        # Bozuk/eksik paketler programı çökertmesin diye try/except ile
        # koruyoruz -- gerçek dünyada paketler her zaman "kitaptaki gibi"
        # gelmez.
        if ayrintili:
            print(f"{Renk.GRI}[uyarı] paket ayrıştırılamadı: {hata}{Renk.SIFIRLA}")


# ---------------------------------------------------------------------
# ÖZET RAPOR: Program CTRL+C ile durdurulduğunda çağrılır.
# ---------------------------------------------------------------------

def ozet_rapor_yazdir():
    gecen_sure = time.time() - durum.baslangic_zamani
    print("\n" + "=" * 65)
    print(f"{Renk.KALIN}DİNLEME ÖZETİ{Renk.SIFIRLA}")
    print("=" * 65)
    print(f"Süre                 : {gecen_sure:.1f} saniye")
    print(f"Toplam paket         : {durum.toplam_paket}")
    print(f"Protokol dağılımı    : {dict(durum.protokol_sayaci)}")
    print(f"Ziyaret edilen site  : {len(durum.ziyaret_edilen_siteler)} farklı domain")

    if durum.bulunan_kimlik_bilgileri:
        print(f"\n{Renk.KIRMIZI}{Renk.KALIN}TESPİT EDİLEN KİMLİK BİLGİLERİ ({len(durum.bulunan_kimlik_bilgileri)}):{Renk.SIFIRLA}")
        for zaman, protokol, detay in durum.bulunan_kimlik_bilgileri:
            print(f"  [{zaman}] {protokol}: {detay}")
    else:
        print("\nHiç düz metin kimlik bilgisi tespit edilmedi.")
    print("=" * 65)


def cikis_isleyici(sig, frame, pcap_dosyasi):
    """CTRL+C (SIGINT) yakalandığında temiz kapanış yapar."""
    ozet_rapor_yazdir()
    if pcap_dosyasi and durum.yakalanan_paketler:
        print(f"\n{len(durum.yakalanan_paketler)} paket '{pcap_dosyasi}' dosyasına kaydediliyor...")
        wrpcap(pcap_dosyasi, durum.yakalanan_paketler)
        print(f"{Renk.YESIL}Kayıt tamamlandı: {pcap_dosyasi}{Renk.SIFIRLA}")
    sys.exit(0)


# ---------------------------------------------------------------------
# GİRİŞ NOKTASI
# ---------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Eğitim amaçlı gelişmiş paket dinleyici (HTTP/DNS/FTP/Telnet)."
    )
    parser.add_argument("-i", "--interface", default=None,
                         help="Dinlenecek ağ arayüzü (örn: eth0, wlan0). Boş bırakılırsa otomatik seçilir.")
    parser.add_argument("-f", "--filter", default="tcp port 80 or tcp port 21 or tcp port 23 or udp port 53",
                         help="BPF filtre ifadesi.")
    parser.add_argument("-o", "--output", default=None,
                         help="Yakalanan paketleri kaydedeceğiniz .pcap dosya adı (örn: kayit.pcap).")
    parser.add_argument("-v", "--verbose", action="store_true",
                         help="Kategorize edilmemiş TCP paketlerini de göster.")
    parser.add_argument("-c", "--count", type=int, default=0,
                         help="Belirli sayıda paket yakaladıktan sonra otomatik dur (0 = sınırsız).")
    args = parser.parse_args()

    # CTRL+C'yi yakalayıp temiz kapanış + özet rapor için ayarlıyoruz.
    signal.signal(signal.SIGINT, lambda s, f: cikis_isleyici(s, f, args.output))

    print("=" * 65)
    print(f"{Renk.KALIN}Gelişmiş Paket Dinleyici başlatılıyor...{Renk.SIFIRLA}")
    print(f"Arayüz   : {args.interface or '(otomatik)'}")
    print(f"Filtre   : {args.filter}")
    print(f"Kayıt    : {args.output or '(kapalı)'}")
    print("Durdurmak için CTRL + C")
    print("=" * 65 + "\n")

    sniff(
        iface=args.interface,
        filter=args.filter,
        prn=lambda paket: paket_isle(paket, pcap_kaydet=bool(args.output), ayrintili=args.verbose),
        store=0,
        count=args.count if args.count > 0 else 0,
    )

    # count belirtilmişse sniff() kendiliğinden burada biter,
    # bu durumda da özet raporu ve pcap kaydını elle tetikliyoruz.
    cikis_isleyici(None, None, args.output)


if __name__ == "__main__":
    main()