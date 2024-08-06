# Eren D.

import socket
import os
import struct
import sys

# [Kullanim]: $ sudo python3 traceroute_201101038.py chatgpt.com

# Parametreler
ZAMAN_ASIMI = 2 # Zaman asimi suresi (saniye)
MAX_ADIM = 30   # Maksimum hop sayisi

def soket_olustur(zaman_asimi):
    soket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    soket.settimeout(zaman_asimi)
    return soket

def paket_olustur(id):
    baslik = struct.pack('bbHHh', 8, 0, 0, id, 1)
    veri = 192 * b'Q'
    kontrol_toplami = toplam_kontrol(baslik + veri)
    baslik = struct.pack('bbHHh', 8, 0, kontrol_toplami, id, 1)
    return baslik + veri

def toplam_kontrol(kaynak_dizi):
    toplam = 0
    sayim_sonu = (len(kaynak_dizi) // 2) * 2
    for say in range(0, sayim_sonu, 2):
        bu = kaynak_dizi[say+1] * 256 + kaynak_dizi[say]
        toplam = toplam + bu
        toplam = toplam & 0xffffffff
    if sayim_sonu < len(kaynak_dizi):
        toplam = toplam + kaynak_dizi[-1]
        toplam = toplam & 0xffffffff
    toplam = (toplam >> 16) + (toplam & 0xffff)
    toplam = toplam + (toplam >> 16)
    cevap = ~toplam
    cevap = cevap & 0xffff
    cevap = cevap >> 8 | (cevap << 8 & 0xff00)
    return cevap

def adres_takip(hedef_adres, zaman_asimi=ZAMAN_ASIMI, maksimum_adim=MAX_ADIM):
    print("Tracing route to %s ..." % hedef_adres)
    icmp = socket.getprotobyname('icmp')
    hedef_adres = socket.gethostbyname(hedef_adres)
    for ttl in range(1, maksimum_adim + 1):
        soket = soket_olustur(zaman_asimi)
        try:
            soket.setsockopt(socket.SOL_IP, socket.IP_TTL, struct.pack('I', ttl))
        except socket.error as e:
            soket.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, struct.pack('I', ttl))
        paket_id = os.getpid() & 0xFFFF
        paket = paket_olustur(paket_id)
        gonderilen = soket.sendto(paket, (hedef_adres, 1))
        try:
            _, suanki_adres = soket.recvfrom(512)
            suanki_adres = suanki_adres[0]
            print("%d\t%s" % (ttl, suanki_adres))
        except socket.timeout:
            print("%d\t* * * Request timed out." % ttl)
        finally:
            soket.close()

        if suanki_adres == hedef_adres:
            print("%d\t%s   Reached" % (ttl, suanki_adres))
            break
    else:
        print("Unable to reach the destination within the max hops.")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 traceroute.py <hostname>")
        sys.exit(1)
    sunucu_ismi = sys.argv[1]
    adres_takip(sunucu_ismi)