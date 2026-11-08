# P2PTransfer - Windows x64

Basit, konsol tabanli TCP dosya aktarim prototipi.

## Gereksinimler
- Windows 10/11 x64
- Visual Studio 2022 veya Visual Studio Build Tools
- Desktop development with C++ (MSVC)

## Derleme
1. `x64 Native Tools Command Prompt for VS 2022` acin.
2. Bu klasore gidin.
3. `build_release.bat` dosyasini calistirin.

Derleme basarili olursa `P2PTransfer.exe` olusur.

## Kullanma
Server bilgisayarinda:
    P2PTransfer.exe server

Client bilgisayarinda:
    P2PTransfer.exe client 192.168.1.25

Dosya gondermek:
    /send "C:\Users\Kullanici\Desktop\ornek.zip"

Cikis:
    /quit

Alinan dosyalar calisma klasorundeki `received` klasorune kaydedilir.

## LAN / WAN
- LAN: Server bilgisayarinin `ipconfig` ciktisindaki IPv4 adresini kullanin.
- WAN: Iki bilgisayari ayni Tailscale agina ekleyip server'in Tailscale IPv4 adresini kullanin.
- Windows Firewall'da TCP 5000 icin izin gerekebilir.
- Router uzerinden portu dogrudan internete acmayin.

## ONEMLI GUVENLIK UYARISI
Bu bir ilk prototiptir. Uygulama seviyesinde sifreleme, kimlik dogrulama,
gonderim onayi ve SHA-256 butunluk kontrolu henuz yoktur. Yalnizca guvendiginiz
LAN veya VPN aginda test edin. Bilinmeyen kisilerden gelen dosyalari acmayin.

Bu paket onceden derlenmis ve test edilmis bir EXE icermiyor; EXE Windows
uzerinde MSVC ile build_release.bat kullanilarak olusturulur.
