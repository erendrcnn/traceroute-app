"""
Eren D.

[Kullanim]        
                LINUX:      (traceroute)
                $ sudo python3 traceroute.py etu.edu.tr
                WINDOWS:    (tracert)
                > python traceroute.py etu.edu.tr

[Parametreler]    
                -s: Gonderilecek paket sayisi   (varsayilan: 3)
                -z: Zaman asimi suresi (ms)     (varsayilan: 2000)
                -m: Maksimum hop sayisi         (varsayilan: 30)
                -b: Paket boyutu (bayt)         (varsayilan: 40)
"""

import sys
import time
import argparse
import os
import select
import struct
import socket

MIN_BEKLEME = 2000
ZAMANLAYICI = time.perf_counter

# IP adresini alan adina cevir - alan adi verilirse IP adresini dondur
def ipye_cevir(hostname):
    ip_parcalari = hostname.strip().split('.')
    # IP adresi mi yoksa alan adi mi oldugunu kontrol et
    if (len(ip_parcalari) == 4 and
        all(parca.isdigit() and
            0 <= int(parca) <= 255 for parca in ip_parcalari)):
        return hostname

    # Alan adini IP adresine cevir
    return socket.gethostbyname(hostname)

# Bu fonksiyon, paketin kontrol toplamini hesaplar (IP ve ICMP basliklari icin)
def toplam_kontrol(paket):
    toplam = 0

    # 2 byte'lik parcalara bolerek toplam degiskenini hesapla
    for i in range(0, len(paket) - len(paket) % 2, 2):
        # Sistemin byte dizilimine gore (little-endian veya big-endian) 16 bitlik birimi al
        birim = (paket[i + 1] << 8 | paket[i]
                 ) if sys.byteorder == "little" else (paket[i] << 8 | paket[i + 1])
        # Tasmayi onlemek icin maskele
        toplam = (toplam + birim) & 0xffffffff

    # Eger paket tek byte ise son byte'i toplam degiskenine ekle
    if len(paket) % 2:
        toplam = (toplam + paket[-1]) & 0xffffffff

    # 16 bitlik tasmayi onleyerek toplam degiskenini 16 bitlik hale getir
    toplam = (toplam >> 16) + (toplam & 0xffff)
    # Tekrar tasmayi onle
    toplam += toplam >> 16
    # Sonucun tersini al ve byte dizilimini duzelt
    return ((~toplam & 0xffff) >> 8) | (((~toplam & 0xffff) & 0xff) << 8)


# Bu sinif, ICMP mesajlarini gonderir ve alir
class IPAnaliz:
    def __init__(self, hedef_sunucu, paket_sayisi, paket_boyutu, maksimum_hop, zaman_asimi):
        self.hedef_sunucu = hedef_sunucu

        try:
            self.hedef_ip = ipye_cevir(hedef_sunucu)
        except socket.gaierror:
            print("Error1: Hostname could not be resolved {}".format(hedef_sunucu))

        self.paket_sayisi = paket_sayisi if paket_sayisi > 0 else 1
        self.paket_boyutu = paket_boyutu if paket_boyutu > 0 else 1
        self.maksimum_hop = maksimum_hop if maksimum_hop > 0 else 1
        self.zaman_asimi = zaman_asimi if zaman_asimi > MIN_BEKLEME else MIN_BEKLEME
        self.sira_no = 0                        # ICMP Echo Request sira numarasi
        self.ttl = 1                            # Time To Live (TTL)
        self.kimlik = 0xffff & os.getpid()      # ICMP Echo Request kimlik numarasi - 16 bit (0-65535)

    # Bu fonksiyon, ip adresini izleyerek hedef sunucuya ulasip ulasilmadigini kontrol eder
    # ICMP Protokolü - Tip 0: Echo Reply, Tip 3: Destination Unreachable, Tip 11: Time Exceeded
    def takipci(self):
        # ICMP soketi olustur
        try:
            icmp_soketi = socket.socket(
                socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname("ICMP"))
            # Soketin zaman asimini ayarla ve TTL'yi belirle - Linux ve Windows icin
            try:
                icmp_soketi.setsockopt(socket.SOL_IP, socket.IP_TTL, self.ttl)
            except socket.error as hata:
                icmp_soketi.setsockopt(
                    socket.IPPROTO_IP, socket.IP_TTL, self.ttl)
        except socket.error as hata:
            print("Permission denied: ICMP messages can only be sent from processes running as root" if hata.errno == 1 
                  else f"Error2 - ICMP socket could not be created: {hata}")
            sys.exit()

        # Ilk paket icin baslangic mesaji
        if self.ttl == 1:
            print("Tracing route to {} ...".format(self.hedef_sunucu))

        # ICMP mesajini gonder - Eger mesaj gonderilemezse soketi kapat
        if not self.icmp_echo_gonder(icmp_soketi):
            return

        # ICMP mesajini al
        alma_zamani, icmp_basligi, ip_basligi = self.icmp_cevap_al(icmp_soketi)
        icmp_soketi.close()

        # Eger ICMP mesaji alinirsa
        if alma_zamani:
            ulasildi = icmp_basligi and icmp_basligi['tip'] == 0
            ip = socket.inet_ntoa(struct.pack('!I', ip_basligi['Kaynak_IP']))
            if ulasildi:
                print("{:<2}\t{}   Reached".format(self.ttl, ip))
            else:
                print("{:<2}\t{}".format(self.ttl, ip))
            if ulasildi:
                return icmp_basligi

        # Bir sonraki hop'a gec
        return icmp_basligi

    # Bu fonksiyon, TTL'yi arttirarak rota izler
    def rota_izle(self):
        icmp_basligi = None
        while self.ttl <= self.maksimum_hop:
            icmp_basligi = self.takipci()
            if icmp_basligi is not None and icmp_basligi['tip'] == 0:
                break
            self.ttl += 1

    # Bu fonksiyon, ICMP mesajini gonderir ve gonderme zamani dondurur
    # BBHHH: Sirasiyla 8 bit tip, 8 bit kod, 16 bit kontrol toplami, 16 bit kimlik, 16 bit sira numarasi (big-endian)
    def icmp_echo_gonder(self, icmp_soketi):
        yuk = bytes([i & 0xff for i in range(65, 65 + self.paket_boyutu)])
        baslik = struct.pack("!BBHHH", 8, 0, 0,
                             self.kimlik, self.sira_no)
        kontrol_toplami = toplam_kontrol(baslik + yuk)
        paket = struct.pack("!BBHHH", 8, 0,
                            kontrol_toplami, self.kimlik, self.sira_no) + yuk

        try:
            icmp_soketi.sendto(paket, (self.hedef_sunucu, 1))
        except socket.error as hata:
            print("Error3 - ICMP message could not be sent: {}".format(hata))
            icmp_soketi.close()
            return
        return ZAMANLAYICI()

    # Bu fonksiyon, ICMP mesajini alir ve alinma zamani, ICMP basligi ve IP basligini isler.
    def icmp_cevap_al(self, icmp_soketi):
        while True:
            okuma_listesi, _, _ = select.select([icmp_soketi], [], [], self.zaman_asimi / 1000)
            if not okuma_listesi:
                print("{:<2}\t* * * Request timed out.".format(self.ttl))
                return None, None, None

            alma_zamani = ZAMANLAYICI()
            paket_verisi, _ = icmp_soketi.recvfrom(2048)

            # IP başlığından alınacak bilgiler: sürüm/IHL, TTL, Protokol, Kaynak IP, Hedef IP
            # !I: 4 byte'lik unsigned integer (big-endian)
            ip_basligi = {
                'SurumIHL': paket_verisi[0],
                'TTL': paket_verisi[8],
                'Protokol': paket_verisi[9],
                'Kaynak_IP': struct.unpack('!I', paket_verisi[12:16])[0],
                'Hedef_IP': struct.unpack('!I', paket_verisi[16:20])[0]
            }

            # ICMP başlığından alınacak bilgiler: tip, kod, kimlik, sıra numarası
            # !H: 2 byte'lik unsigned short (big-endian)
            icmp_basligi = {
                'tip': paket_verisi[20],
                'kod': paket_verisi[21],
                'kimlik': struct.unpack('!H', paket_verisi[24:26])[0],
                'sira_numarasi': struct.unpack('!H', paket_verisi[26:28])[0]
            }

            return alma_zamani, icmp_basligi, ip_basligi

# Programi calistir
if __name__ == '__main__':
    # Argumanlari al
    cozumleyici = argparse.ArgumentParser(
        description="Bir hedef sunucuya traceroute islemi yapar.")
    cozumleyici.add_argument('hedef_sunucu', type=str,
                             help="Hedef sunucunun IP adresi veya alan adi")
    cozumleyici.add_argument('-s', '--sayi', type=int, default=3,
                             help="Gonderilecek paket sayisi (varsayilan: 3)")
    cozumleyici.add_argument('-z', '--zaman_asimi', type=int,
                             default=MIN_BEKLEME, help="Zaman asimi suresi (ms) (varsayilan: 1000)")
    cozumleyici.add_argument('-m', '--maksimum_hop', type=int,
                             default=30, help="Maksimum hop sayisi (varsayilan: 30)")
    cozumleyici.add_argument('-b', '--paket_boyutu', type=int,
                             default=40, help="Paket boyutu (bayt) (varsayilan: 40)")
    argumanlar = cozumleyici.parse_args()

    # Traceroute parametrelerini ayarla
    izleyici = IPAnaliz(argumanlar.hedef_sunucu, argumanlar.sayi,
                       argumanlar.paket_boyutu, argumanlar.maksimum_hop, argumanlar.zaman_asimi)

    # Rota izle
    izleyici.rota_izle()