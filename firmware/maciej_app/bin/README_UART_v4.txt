ELEKTRODA ALI M3801 TEST FOR MACIEJ - v4 (demo)

Aktualizacja UART dla bootloadera z dump_maciej.bin.
Wymagania: Python 3.10+, pyserial, UART 3,3 V (115200, 8E1).
Rozpakuj caly ZIP do jednego katalogu. Polacz TX-RX, RX-TX i GND.
Zamknij inne programy uzywajace portu tunera. COM3 zastap swoim portem.

python -m pip install pyserial
python maciej_uart.py --port COM3 --capture-boot 60 flash elektroda_ali_m3801_maciej_v4.maincode.bin --backup before-maciej-v4.bin

- Oryginalne oprogramowanie lub v1/v2: wlacz tuner po komunikacie gotowosci.
- Gdy dziala v3 lub v4: zostaw tuner wlaczony. Wysylane przez skrypt "c"
  uruchomi go ponownie i przechwyci oryginalny bootloader (v4 robi to po
  trzech znakach "c" w pustej linii polecen).
- Skrypt zapisze pelny backup, wgra maincode i zweryfikuje cale 4 MiB.
  Dwa odczyty trwaja lacznie okolo 14 minut. Nie wylaczaj tunera podczas zapisu.
- Do kolejnej aktualizacji uzyj nowej nazwy backupu. Stary nie jest nadpisywany.

v4 to demo z prawdziwa linia polecen: cale komendy zakonczone Enter.
Terminal 115200 8E1 (np. PuTTY), znak zachety "m3801> ".
Edycja linii jak w bashu: strzalki lewo/prawo, Home/End (Ctrl-A/Ctrl-E),
Ctrl-strzalki (Alt-B/Alt-F) o slowo, Backspace, Delete (Ctrl-D), Ctrl-W
kasuje slowo, Ctrl-U wszystko przed kursorem, Ctrl-K wszystko za nim,
Ctrl-Y wkleja skasowane, Ctrl-L czysci ekran, Ctrl-C porzuca linie.
Strzalki gora/dol przywracaja poprzednie komendy zaczynajace sie od tego,
co juz wpisano (64 ostatnie, bez powtorzen); Ctrl-R szuka komendy
zawierajacej wpisywany tekst; !! powtarza ostatnia, !n komende numer n z
'history', !-n n-ta od konca, !tekst ostatnia zaczynajaca sie od tekstu.
Tab dopelnia nazwe komendy, jej podkomende (np. "rf sp" -> "rf spectrum")
i nazwe pliku albo katalogu na dysku ("ls 4:/c6" -> "ls 4:/c64/");
gdy pasuje kilka, wypisuje je (dlugie listy po drugim Tab).
Komende mozna tez zaczac od '/' (np. /restart, /lsusb).

  help                 lista komend (help <komenda> - opis jednej)
  version / ping       banner i wersja / odpowiedz "pong v4"
  info / uptime        uklad, zegar CPU, adresy w pamieci, czas pracy
  echo <slowa>         wypisuje argumenty
  md <adres> [dl]      zrzut pamieci (RAM, okno flash, rejestry)
  mr <adres>           odczyt slowa 32-bit
  mw <adres> <wart>    zapis slowa 32-bit (RAM i rejestry, nie flash)
  screen ...           rysuje na ekranie testowym (i go pokazuje): demo | bars |
                       clear [rrggbb] | text <x> <y> <slowa> |
                       rect <x> <y> <w> <h> <rrggbb> | on | off
  testscreen           ekran testowy na TV (ramki, paski kolorow); dowolny
                       klawisz klawiatury USB (wpisuje sie tez) albo
                       "console" wraca do konsoli
  console              konsola na TV (widok po starcie)
  explorer [n:][sciezka]
                       menedzer plikow na TV w biezacym katalogu, zgrany z
                       "cd" w obie strony: strzalki/PgUp/PgDn wybieraja,
                       Enter otwiera (obraz: przegladarka, plik gry -
                       .nes, .gb, .sms, .sg, .md, .crt, .adf itd., takze w
                       .zip albo .gz: gra, inny plik: jego poczatek),
                       Backspace w gore,
                       "/" albo Tab - wpisywanie sciezki w pasku; mysz:
                       klik, podwojny klik, kolko; Esc wraca do konsoli;
                       F2 zmienia nazwe, F7 nowy katalog, Delete/F8
                       usuwa (y), F5/F6 kopiuj/przenies plik, Insert wkleja
  panel <tekst>        4 znaki na wyswietlaczu panelu; panel bright 0..7
                       (plyty z TM1650)
  keys                 stan klawiszy panelu (klawisze sa tez zglaszane same);
                       bez TM1650: dwa przyciski na GPIO 31 i 9
  ir                   ostatni kod pilota; ir raw on|off - czasy impulsow
  usb                  port USB: stan, predkosc i deskryptory podlaczonego
                       urzadzenia (VID:PID, nazwy, interfejsy); usb reset -
                       reset magistrali, usb init - kontroler od nowa,
                       usb kbd [report|interrupt|raw on|off] - klawiatura,
                       usb mouse - mysz (kursor, przyciski, liczniki),
                       usb reg <offset> [bajt] - rejestr kontrolera,
                       usb ctl <typ> <zadanie> <wartosc> <indeks> <dlugosc>
                       [urzadzenie] - dowolne zadanie kontrolne do urzadzenia
                       o danym adresie (np. usb ctl 0x80 6 0x100 0 18 2);
                       zadanie OUT wysyla bajty z ostatniego odczytu
  lsusb                urzadzenia USB, po jednej linii
  disks                dyski USB (pendrive, czytnik kart): rozmiar, partycje,
                       systemy plikow
  ls [n:][sciezka]     katalog na dysku USB (FAT12, FAT16, FAT32, NTFS, dlugie
                       nazwy); n - numer urzadzenia z lsusb (np. ls 3:/docs),
                       bez niego biezacy katalog (cd), a przed pierwszym cd
                       pierwszy wolumin FAT; "dir" to samo
  cd [n:][sciezka]     biezacy katalog, widoczny w znaku zachety
                       (m3801 3:/Docs>); cd .. - wyzej, cd / - korzen,
                       samo cd - bez katalogu; pwd - pokazuje go
  cat [n:]sciezka      plik tekstowy z dysku USB (Ctrl-C przerywa; plik
                       binarny: pierwsze 256 bajtow szesnastkowo)
  mkdir <sciezka>      nowy katalog (ZAPIS na dysk; dlugie nazwy tez)
  rmdir <sciezka>      usuwa pusty katalog (zapis)
  rm [-r] <sciezka>    usuwa plik; -r: katalog z cala zawartoscia (zapis)
  touch <sciezka>      nowy pusty plik (zapis)
  cp [-r] <skad> <dokad>
                       kopiuje plik (do katalogu: do niego, pod ta sama
                       nazwa; takze na inny dysk); -r: katalog z cala
                       zawartoscia (zapis)
  mv <skad> <dokad>    zmienia nazwe pliku lub katalogu albo przenosi go
                       do innego katalogu tego samego woluminu (zapis)
  komenda > plik       to, co komenda wypisuje, trafia do pliku (np.
                       ls > 4:/lista.txt, echo tekst > 4:/a.txt); >> dopisuje
                       na koncu pliku; nazwy ze spacjami w "..." albo '...'
  sector [n:]<numer>   jeden sektor dysku USB szesnastkowo
  sum [n:]sciezka      plik przeczytany do konca: rozmiar, CRC-32 (jak 7-Zip),
                       pierwsze bajty, predkosc (Ctrl-C przerywa)
  head [-n N] <plik>   pierwsze N linii pliku (10); tail - ostatnie N
  df [n:]              woluminy dyskow: rozmiar, wolne i zajete miejsce
  ntfs [n:] [reset-journal]
                       wolumin NTFS: geometria, stan dziennika i czy demo go
                       zapisuje (tylko wolumin zamkniety czysto przez Windows:
                       "Bezpieczne usuwanie"); reset-journal czysci dziennik
                       tak jak ntfs-3g
  view [-1] [-s | -c] <plik>
                       obraz na TV (JPEG zwykly i progresywny, PNG, GIF, BMP),
                       dopasowany do ekranu, obrocony wg EXIF zdjecia;
                       strzalka w prawo / spacja - nastepny obraz z katalogu,
                       w lewo - poprzedni, i - szczegoly, Esc albo q konczy.
                       Zwykly JPEG dekoduje sprzetowo uklad wideo (-s: tylko
                       procesor; -c: oba, porownane, nic nie pokazuje)
  play [-n klatki] [-x] [-k] [-v] [-1] <plik>
                       film z pliku (.ts, .mpg, .m2v, .vob, .264, .mp4,
                       .mov: wideo MPEG-2, MPEG-1 albo H.264, dzwiek MPEG;
                       dzwiek .mp4, AAC, nie gra) na TV, dekodowany
                       sprzetowymi dekoderami MPEG-2 / H.264 ukladu;
                       dzwiek przez "snd". Esc,
                       Ctrl-C, q albo EXIT na pilocie konczy; -n tyle klatek,
                       -x tak szybko jak dekoduje (bez dzwieku), -k ostatnia
                       klatka zostaje na TV (zdejmuje ja Esc na klawiaturze
                       USB, EXIT na pilocie albo "av off"), -v kazda klatka
                       opisana, -1 obraz w swoim rozmiarze (zamiast na
                       wysokosc ekranu)
  av <polecenie>       dekoder wideo i warstwa obrazu: av status (rejestry),
                       av shot <plik.bmp|plik.yuv> (ostatnia klatka do
                       pliku), av show, av off (z powrotem menu), av reset
  gb [-f klatki] <plik.gb>
                       gra Game Boy albo Game Boy Color na TV (gra na Color
                       w kolorach, starsza w czterech odcieniach), 59,7
                       klatki na sekunde (kartridze bez MBC, MBC1, MBC2,
                       MBC3, MBC5; bez dzwieku): klawisze jak w nes;
                       pamiec z bateria w pliku .sav obok gry
  nes [-f klatki] <plik.nes>
                       gra NES na TV, 60 klatek na sekunde (mappery 0, 1, 2,
                       3, 4, 7, 11, 34, 66, 71; bez dzwieku): strzalki albo
                       W A S D, X = A, Z = B, Enter = Start, Tab = Select
                       (klawiatura USB, UART, pilot: strzalki, OK = A, 0 = B,
                       MENU = Start, INFO = Select); Ctrl-C albo Esc konczy;
                       pamiec baterii gry w pliku .sav obok niej. Kazdy
                       emulator bierze tez gre spakowana w .zip (najwiekszy
                       plik w nim, ktory nie jest tekstem ani obrazkiem)
                       albo .gz (tez .adz Amigi)
  sms [-f klatki] <plik.sms>
                       gra Sega Master System na TV (256 x 192, 3 razy
                       wiekszy; mappery Sega i Codemasters, pamiec kartridza
                       w pliku .sav; bez dzwieku): X = przycisk 2, Z =
                       przycisk 1, Enter = Pause; reszta jak w nes
  gg [-f klatki] <plik.gg>
                       gra Sega Game Gear na TV (160 x 144, 5 razy wiekszy):
                       X = przycisk 2, Z = przycisk 1, Enter = Start
  sg [-f klatki] <plik.sg|plik.sc>
                       gra Sega SG-1000 / SC-3000 na TV (256 x 192, 3 razy
                       wiekszy; kartridze do 48 KB, powyzej mapper Sega;
                       tylko pady, bez dzwieku): X = przycisk 2, Z =
                       przycisk 1, Enter = Pause; reszta jak w nes
  megadrive [-r j|u|e] [-f klatki] <plik>
                       gra Sega Mega Drive / Genesis na TV (320 x 224 albo
                       256 x 224, 3 razy wiekszy; .md, .gen, .bin, .smd;
                       NTSC albo PAL wg regionu z naglowka albo -r) z
                       dzwiekiem (YM2612 i PSG): X = B, Z = A, Tab / spacja
                       = C, Enter = Start (klawiatura USB, UART, pilot);
                       pad 3-przyciskowy; pamiec kartridza w pliku .sav
  zx [-f klatki] [plik]
                       ZX Spectrum 48K / 128K + Pentagon BetaDisk 128 na TV
                       (320 x 240 z ramka, 3 razy wiekszy, 50 klatek/s):
                       snapshot (.sna, .z80), tasma (.tap, .tzx) albo dyskietka
                       TR-DOS (.trd, .scl) z dzwiekiem beeper + AY-3-8912 48 kHz;
                       bez pliku: BASIC. Opcjonalne 48.rom, 128.rom i trdos.rom
                       w katalogu zx/ albo wbudowany loader. Klawiatura USB jest
                       klawiatura Spectrum (Shift = CAPS SHIFT, Ctrl / Alt =
                       SYMBOL SHIFT, Backspace = DELETE), strzalki to tez
                       joystick Kempston (ogien: OK na pilocie); Esc konczy
  a26 [-f klatki] <plik.a26>
                       gra Atari 2600 na TV (160 x 228, 5 razy szerszy i 3
                       razy wyzszy; kartridze 2K, 4K, F8, F6, F4 i ich RAM
                       Superchip, FE, E0, 3F, E7, FA; NTSC; bez dzwieku):
                       strzalki, X albo Z = ogien, Enter = Reset konsoli,
                       Tab = Select
  c64 [-f klatki] [plik]
                       Commodore 64 (PAL) na TV (352 x 240 z ramka, 3 razy
                       wiekszy, 50 klatek/s): program (.prg, .t64) albo
                       dyskietka (.d64) - wczytuje sie i startuje (RUN) sam,
                       LOAD z dyskietki dziala tez pozniej; albo kartridz
                       (.crt: zwykly 8K/16K/Ultimax, Ocean, Magic Desk,
                       EasyFlash, System 3, Dinamic, Fun Play, Super Games,
                       RGCD, Simons' BASIC, Final Cartridge III) - start z
                       kartridza; bez pliku: BASIC.
                       ROM-y C64 to pliki kernal.rom, basic.rom i chargen.rom
                       (nie ma ich w demie) obok programu, w katalogu c64/
                       albo na szczycie dysku. Klawiatura USB jest klawiatura
                       C64 (Tab = RUN/STOP, PageUp = RESTORE, Alt = C=),
                       strzalki to joystick w porcie 2 (ogien: prawy Ctrl,
                       OK na pilocie; F9 zamienia porty); MENU na pilocie =
                       SPACJA, INFO = F7; znaki wpisane przez UART / telnet
                       sa na nim wpisywane; Esc konczy
  amiga [-f klatki] [plik.adf]
                       Amiga 500 (PAL, OCS) na TV (352 x 272 z ramka, 2 razy
                       wiekszy) z obrazem dyskietki (.adf) w stacji (bez
                       pliku: pusta stacja). Kickstart to plik kick.rom (256
                       albo 512 KB, nie ma go w demie) albo darmowy AROS:
                       aros-rom.bin + aros-ext.bin - obok dyskietki, w
                       katalogu amiga/ albo na szczycie dysku. Klawiatura USB
                       jest klawiatura Amigi, strzalki to joystick (ogien:
                       prawy Ctrl, OK na pilocie), lewy przycisk myszy: Page
                       Up / Page Down albo 0 na pilocie; MENU = Return, INFO
                       = spacja; bez dzwieku; Esc konczy
  dos [-f klatki] <plik.exe>
                       PC z DOS-em (286 AT z karta VGA: tryby tekstowe,
                       CGA, EGA, 256 kolorow) na TV (320 x 200, 3 razy
                       wiekszy) uruchamiajacy program DOS (.exe, .com);
                       BIOS i DOS sa wbudowane, bez dzwieku. Klawiatura
                       USB jest klawiatura PC (Esc konczy); pilot: strzalki,
                       OK = gora, 0 = spacja, MENU = Enter, INFO = Esc
  pce [-f klatki] <plik.pce>
                       PC Engine / TurboGrafx-16 na TV z 6-kanalowym dzwiekiem
                       PSG i 2 KB pamieci zapisu (.sav)
  coleco [-f klatki] <plik.col>
                       ColecoVision na TV (256 x 192 x3, MegaCart i Super Game
                       Module, SN76489; coleco.rom w col/ albo wbudowany BIOS)
  msx [-f klatki] <plik.rom|plik.mx1>
                       MSX1 na TV (zwykle, Konami, Konami SCC, ASCII8/16,
                       AY-3-8910 + SCC; msx.rom w msx/ albo wbudowany BIOS)
  msx2 [-f klatki] <plik.mx2|plik.dsk|plik.rom>
                       MSX2 na TV (Yamaha V9938 128 KB VRAM, SCREEN 0..8,
                       sprzetowy blitter, 256 KB Mapper, RP5C01 RTC, dyskietki
                       .dsk, dzwiek AY-3-8910 + SCC + YM2413; cbios_main_msx2.rom
                       w msx2/ albo wbudowany BIOS MSX2)
  ws [-f klatki] <plik.ws|plik.wsc>
                       Bandai WonderSwan / WonderSwan Color na TV (224 x 144
                       x5 albo pionowo 144 x 224 x3, dzwiek 4-kanalowy, .sav)
  snes [-f klatki] <plik.sfc|plik.smc>
                       Super Nintendo / Super Famicom na TV (LoROM, HiROM,
                       ExHiROM, tryby 0-7, dzwiek SPC700 BRR, zapis .sav)
  neogeo [-f klatki] <plik.neo>
                       SNK Neo Geo AES / MVS na TV (320 x 224 x3, Z80 + YM2610,
                       64 KB .sav; uni-bios.rom w neogeo/ albo wbudowany BIOS)
  gba [-f klatki] <plik.gba>
                       Game Boy Advance na TV (240 x 160 x4, DirectSound + PSG,
                       SRAM / Flash / EEPROM .sav; gba_bios.bin albo wbudowany)
  a78 [-f klatki] <plik.a78>
                       Atari 7800 ProSystem na TV (MARIA, TIA + POKEY, .sav)
  lynx [-f klatki] <plik.lnx|plik.lyx>
                       Atari Lynx na TV (160 x 102 x6 albo pionowo, skalowanie
                       Suzy, dzwiek Mikey; lynxboot.img albo wbudowany loader)
  vectrex [-f klatki] [plik.vec]
                       GCE Vectrex na TV (wektorowy ekran 540 x 720, AY-3-8912;
                       bez pliku: Mine Storm z vectrex.rom albo Vector Storm)
  fds [-f klatki] <plik.fds>
                       Famicom Disk System na TV (1-8 stron, Q obraca dysk,
                       dzwiek RP2C33, zapisy dysku w .sav, wbudowany BIOS)
  ngp [-f klatki] <plik.ngp|plik.ngc>
                       Neo Geo Pocket / Color na TV (160 x 152 x4, Z80 + T6W28
                       + DAC, zapis Flash 64 KB w .sav, wbudowany BIOS)
  odyssey2 [-f klatki] <plik.o2>
                       Magnavox Odyssey2 / Videopac G7000 na TV (Intel 8048 +
                       8244, 640 x 720, klawiatura 0..9, wbudowany BIOS)
  intv [-f klatki] <plik.int|plik.rom>
                       Mattel Intellivision na TV (CP1610 + STIC + AY-3-8914,
                       704 x 624, wbudowane EXEC i GROM albo exec.bin/grom.bin)
  psx [-f klatki] <plik.exe|plik.cue|plik.iso>
                       Sony PlayStation 1 na TV (R3000A + GTE 3D, GPU 15/24bpp,
                       MDEC, plyty CD .cue/.bin i .iso czytane strumieniowo,
                       24-glosowy dzwiek SPU ADPCM, karta pamieci 128 KB .sav;
                       scph1001.bin w psx/ albo wbudowany BIOS)
  cps [-f klatki] <plik.cps|plik.zip>
                       Automaty Capcom CPS-1 / CPS-1.5 / CPS-2 na TV (384 x 224
                       x3, 68000 + Z80, deszyfrowanie CPS-2 .key i Kabuki, 3
                       warstwy tla + rowscroll, dzwiek YM2151 + OKIM6295 oraz
                       16-glosowy QSound DSP, zapis EEPROM 93C46 w .sav)
  atarist [-f klatki] [plik.st|plik.msa|plik.prg]
                       Atari 520ST / 1040STFM na TV (320 x 200 x3, 640 x 200,
                       640 x 400; 68000 8 MHz, Shifter + STE Blitter, MFP, IKBD,
                       WD1772 FDC, dzwiek YM2149F; darmowy EmuTOS etos256uk.img
                       albo tos.img w atarist/, lub wbudowany TOS)
  sys16 [-f klatki] <plik.s16|plik.zip>
                       Automaty Sega System 16A / 16B / OutRun-Road na TV
                       (320 x 224 x3, 68000 + Z80, mapper 315-5195, warstwy tli
                       315-5197 + skalowane duszki + generator drogi, dzwiek
                       YM2151 + uPD7759 + Sega 16-ch PCM, zapis NVRAM .sav)
  atari8 [-f klatki] [plik.atr|plik.xex|plik.car|plik.rom]
                       Atari 800XL / 130XE (128 KB) na TV (336 x 240 x3, SALLY
                       6502C, ANTIC tryby 2..F + DLI + WSYNC, GTIA duszki P/M i
                       tryby 9/10/11, bankowanie 130XE PORTB, dzwiek POKEY 48 kHz,
                       zapis dyskietek .atr w .sav; wbudowany AltirraOS XL + BASIC
                       albo atarixl.rom / ataribas.rom w atari8/; bez pliku: BASIC)
  a5200 [-f klatki] <plik.a52|plik.car>
                       Atari 5200 SuperSystem na TV (336 x 240 x3, kartridze
                       4K..40K, ANTIC + GTIA + POKEY 48 kHz, drazek analogowy i
                       klawiatura 0..9; wbudowany Altirra 5200 OS albo 5200.rom)
  snd <polecenie>      dzwiek (prototyp): snd init, snd beep [Hz] [ms] (ton
                       testowy), snd vol 0..100, snd status, snd stop -
                       48 kHz na HDMI (po "video init") i na SCART (L/P)
  rf <polecenie>       wejscie antenowe (DVB-T): tuner MxL603 (I2C 0x60)
                       i demodulator S3811 ustawiane tak jak robi to
                       oryginalny soft dump.bin: rf init, rf tune <MHz albo
                       kanal> [6|7|8], rf status (lock, poziom, jakosc,
                       bledy), rf scan, rf services (nazwy kanalow
                       multipleksu), rf ts <s> [plik] (PID-y albo nagranie
                       .ts), rf spectrum (poziom sygnalu z anteny od 174 do
                       862 MHz jako wykres na TV), rf live [od do] (ten
                       wykres odswiezany na biezaco, sterowany klawiszami);
                       tylko DVB-T, nie DVB-T2
  tty                  porty szeregowe USB: porty modulu GSM / LTE (SIMCom,
                       Quectel, Huawei, ZTE ...), urzadzenia CDC ACM
                       i przejsciowki USB-UART (CH340 / CH341, CP210x, FTDI,
                       PL2303)
  stty [n] [baud]      predkosc portu szeregowego (8N1): pokazuje albo
                       ustawia, np. stty 0 9600 (przejsciowki startuja
                       z 115200)
  at [komenda]         jedna komenda AT do portu AT modulu i jej odpowiedz do
                       OK / ERROR oraz to, co przychodzi zaraz po nich (dane
                       AT+HTTPREAD); najpierw linie, ktore modul wyslal
                       wczesniej (+HTTPACTION, RING); np. at +csq, at i,
                       at +cpin?; linia zaczynajaca sie od AT tez tam trafia;
                       dziala > plik
  cu [n]               terminal polaczony z portem szeregowym n (bez n: port
                       AT modulu): co wpiszesz, idzie do portu, odpowiedzi
                       widac; "~." na poczatku linii albo Ctrl-] konczy
  ifconfig             lacze sieciowe: adapter Ethernet USB (CDC ECM, np.
                       RTL8153) albo modul LTE (RNDIS, np. SIMCom A7670E),
                       gdy adaptera nie ma albo nie dostal adresu: MAC,
                       adres IP z DHCP, router
  dhcp                 ponownie prosi serwer DHCP o adres
  arp                  tabela ARP
  ping [-c n] <host>   ping jak w Linuksie przez siec: adres albo nazwa
                       (DNS z DHCP), TTL i czas kazdej odpowiedzi, Ctrl-C
                       konczy i pokazuje statystyke (samo "ping": pong)
  wget [-O n:plik] [--no-check-certificate] <url>
                       strona http:// albo https:// przez siec: na konsoli
                       albo zapisana na dysku USB; przekierowania (301,
                       302...) sa sledzone. https: TLS 1.2 (BearSSL),
                       certyfikat sprawdzany wzgledem 118 glownych urzedow
                       Mozilli i zegara z NTP ("date" musi pokazywac czas);
                       --no-check-certificate nie sprawdza nic. Bez TLS 1.3.
  ntp [serwer] / date  zegar z sieci (sam po DHCP) / data i godzina: UTC
                       i polska (CET / CEST)
  netstat              TCP: porty, polaczenia, liczniki
  loop                 petla glowna: przebiegi, najwolniejszy, co trwalo
  Przez siec: telnet <adres tunera> (port 23) - ta sama linia polecen co
  na UART; python tools/maciej_netload.py <adres> [app.bin] - nowa wersja
  demo uruchamiana z RAM w ~1 s (flash bez zmian, restart wraca do niej);
  ftp://<adres tunera> (port 21, bez hasla, 2 klienty) - serwer FTP: w katalogu
  glownym wszystkie dyski ("4 PHONE CARD", "9 ..."), pobieranie,
  wysylanie, usuwanie, zmiana nazw i katalogi na FAT i NTFS (NTFS gdy demo
  go zapisuje: "ntfs"); tryb pasywny (porty danych 50021/50022) i aktywny.
  http://<adres tunera> (port 80, bez hasla) - strona tunera w przegladarce
  (takze na telefonie): pliki na dyskach (przegladanie, pobieranie,
  wysylanie przyciskiem albo przeciagnieciem, zmiana nazw, usuwanie, nowe
  katalogi; obrazy i teksty otwieraja sie w przegladarce), obraz z TV na
  zywo (co ok. 1 s; "Full size" - pelne 1280 x 720), pilot na ekranie
  (strzalki, OK, Esc, Tab, A/B do gier, Ctrl-C) i linia polecen jak przez
  telnet. Gdy dziala polecenie (np. gra), obraz, pilot i linia polecen
  dzialaja dalej, a pliki czekaja na jego koniec; jeden plik naraz
  (strona albo FTP - drugi dostaje "sprobuj za chwile").
  \\<adres tunera>\4 (port 445, SMB2, bez hasla) - dyski jako udzialy
  Windows: w Eksploratorze, "net view \\<adres>", "net use", robocopy;
  kopiowanie w obie strony, zmiana nazw, usuwanie, katalogi. Logowanie
  jako gosc: Windows 10 Home / Pro je przyjmuje, Windows 11 24H2 Pro oraz
  wersje Enterprise / Education je blokuja. Jeden zapisywany plik naraz.
  SSDP (UPnP, UDP 1900): tuner widac w Windows w "Sieci" (Inne urzadzenia)
  jako "M3801 v4 demo (adres)"; dwuklik otwiera strone tunera.
  Data i godzina z NTP: w prawym gornym rogu konsoli na TV, po czasie pracy
  watchdog [test|off|on]
                       watchdog ukladu: dziala od startu demo; gdy demo stanie
                       na 8 s, tuner sam sie restartuje; test - przestaje go
                       karmic (tuner restartuje sie po 8 s)
  clear                czysci ekran terminala (i konsoli na TV)
  history [n | -c]     poprzednie komendy z numerami (n ostatnich; -c
                       czysci historie)
  video init [opticum|comsat] [rev0|rev1]
                       odtwarza zapisy rejestrow, ktorymi oryginalne
                       oprogramowanie plyty wlacza obraz 720p i nadajnik HDMI
                       (demo robi to samo przy starcie);
                       bez nazwy - tabela tej plyty, bez rev0/rev1 - tabela
                       wersji ukladu (bajt 0xB8000000)
  reboot / restart     restart przez oryginalny bootloader
  bootloader           restart do oryginalnego bootloadera: przytrzymaj klawisz c
                       (albo uruchom maciej_uart.py), zeby w nim zostac

Konsola na TV (widok po starcie): to samo co na UART - komunikaty startowe,
znak zachety, wpisywane komendy (z UART albo klawiatury USB), ich wyniki
i zdarzenia ([usb] ..., [panel] ...) - jak konsola w Linuksie: 105 x 42
znakow, pasek tytulu, znak zachety na zielono, kursor miga. Linie przewijaja
sie w gore; ostatnie 512 linii zostaje - PgUp / PgDn (klawiatura USB albo
ESC [ 5 ~ / ESC [ 6 ~ z terminala) przewija o pol ekranu. "testscreen"
pokazuje dawny ekran demo (ekran testowy), klawisz na klawiaturze USB albo
"console" wraca do konsoli.
Zapis na dyski: mkdir, rmdir, rm, touch, cp, mv i "komenda > plik" zapisuja
wolumin FAT (wszystkie kopie FAT, dlugie nazwy, FSInfo w FAT32; pliki
tekstowe maja konce linii jak w Linuksie) i NTFS - ten tylko wtedy, gdy
Windows zamknal go czysto (pusty dziennik: "Bezpieczne usuwanie" przed
wyjeciem; "ntfs n:" mowi, czy demo go zapisuje). Po zapisie przez demo
warto sprawdzic pendrive w Windows (chkdsk). Nowe pliki i katalogi maja date
z zegara, gdy NTP go ustawil (czas polski); wczesniej 2026-11-13 12:00. Czesc
katalogowa sciezki moze miec 95 znakow, nazwa 127 - dluzsze sa odrzucane.
Dysk chroniony przed zapisem (MODE SENSE) nie jest zapisywany. Uwaga: zapis
zmienia dane na pendrivie - najpierw sprobuj na pendrivie bez waznych plikow.
Modul GSM / LTE (sprawdzone z SIMCom A7670E, 1e0e:9011): jego porty to
ttyUSB0..3 ("tty"), "at +csq" pyta o zasieg, "cu" otwiera port AT jak
terminal. Gdy modul sie zrestartuje (np. po AT+CRESET), demo samo
konfiguruje go ponownie; pojedynczy blad transmisji USB (np. gdy modul nadaje
w GSM) nie przerywa "at" ani "cu". Karta SIM z PIN-em: at +cpin=<PIN> (albo
wylacz PIN w telefonie).
Internet przez modul (jego funkcja RNDIS, jak usb0 w Linuksie): gdy nie ma
adaptera Ethernet, gdy zostanie odlaczony albo nie dostanie adresu z DHCP,
siec demo (ping, wget, ntp, telnet, FTP, netload) idzie przez modul; jego
DHCP daje adres, a jego router wyjscie do sieci komorkowej. "ifconfig"
pokazuje, ktore lacze jest w uzyciu. (Sprawdzone w emulatorze; modul musi
miec aktywne polaczenie danych.)
Strona WWW przez modul (jego wlasny klient HTTP):
  at +cgact=1,1                              (polaczenie danych)
  at +httpinit
  at +httppara="URL","http://example.com/"
  at +httpaction=0                           (po kilku sekundach modul wysle
                                              +HTTPACTION: 0,200,<dlugosc>)
  at +httpread=0,<dlugosc>                   (strona; mozna tez > plik)
  at +httpterm
Sprawdzone przez GSM: example.com, 577 bajtow.

Pilot: kazda odebrana ramka NEC jest wypisywana z kodem i nazwa klawisza,
pokazana na ekranie i na panelu. Klawisze panelu: wypisywane po nacisnieciu.
USB: po podlaczeniu urzadzenia demo samo odczytuje jego deskryptory
i pokazuje nazwe na ekranie. Pendrive i czytniki kart (mass storage, SCSI,
bulk-only) sa od razu sprawdzane: nazwa, rozmiar, partycje (MBR lub GPT)
i system plikow. Pliki mozna czytac i zapisywac na FAT12/16/32 i NTFS;
exFAT jest rozpoznawany, ale nie czytany. Sprawdzone na Comsat TE 1050 HD:
karta FAT16 w czytniku 05e3:0751 i pendrive NTFS 64 GB.
Przejsciowki USB-UART (CH340 / CH341 w trybie szeregowym, CP210x, FTDI,
PL2303): kazda jest portem ttyUSB<n> (115200 8N1), "stty n <baud>" zmienia
predkosc, "cu n" otwiera terminal. Sprawdzone: CH340 1a86:7523 (ustawianie
predkosci). CH341A w trybie I2C/SPI (1a86:5512, programator 24xx/25xx) jest
tylko rozpoznawany.
Obrazy: "view plik" albo Enter w eksploratorze; zdjecie 2000 x 1333 JPEG
dekoduje sie okolo 1,5 s. Zwykly (nie progresywny) JPEG dekoduje uklad wideo
(tryb JPEG dekodera MPEG-2): 1920 x 1080 w 56 ms zamiast 1 s, zdjecie
6000 x 4000 pokazane w ok. 1 s zamiast 14 s. Progresywny, niskiej jakosci
albo nietypowy JPEG dekoduje procesor jak dotad. Gry NES: "nes plik.nes" albo Enter w
eksploratorze; dziala pelne 60 klatek/s (klatka ok. 8 ms + 1,5 ms rysowania).
Gier komercyjnych (np. Mario) demo nie zawiera - mozna uzyc wlasnych kopii
albo darmowych gier homebrew (np. Nova the Squirrel, Thwaite).
Gry Game Boy i Game Boy Color: "gb plik.gb" (albo .gbc) lub Enter w
eksploratorze; klatka ok. 6-7 ms + 0,7 ms rysowania (gra na Color w podwojnej
predkosci ok. 12 ms + 1,5 ms), obraz 5 razy wiekszy (800 x 720).
Gry Sega Master System i Game Gear: "sms plik.sms", "gg plik.gg" albo Enter
w eksploratorze; klatka ok. 4-5 ms + 1-2 ms rysowania. ZX Spectrum 48K: "zx
plik.tap" (albo .tzx, .sna, .z80) lub "zx" bez pliku (BASIC); potrzebny jest
plik 48.rom (ROM Spectrum, 16 KB - Amstrad pozwala go uzywac w emulatorach)
obok programu, w zx/ albo na szczycie dysku; klatka ok. 4 ms + 2,5 ms.
Tasmy ladowane sa od razu przez procedure LD-BYTES z ROM-u, wiec gry z
wlasnym turbo-loaderem sie nie wczytaja. Atari 2600: "a26 plik.a26" albo
Enter w eksploratorze; klatka ok. 3,5-5,5 ms + 1 ms. Sprawdzone na Comsat TE
1050 HD z darmowymi grami homebrew (np. Snake Pit, Sushi Nights, Ramiro el
Vampiro, Halo 2600, Thrust).
Commodore 64: "c64 plik.t64" (albo .prg, .d64) lub "c64" bez pliku (BASIC)
albo Enter w eksploratorze; potrzebne sa ROM-y kernal.rom (8 KB), basic.rom
(8 KB) i chargen.rom (4 KB) obok programu, w c64/ albo na szczycie dysku
(pliki z VICE pod tymi nazwami). LOAD jest robiony od razu (bez stacji
1541), wiec gry z wlasnym szybkim loaderem dzialajacym w stacji sie nie
wczytaja. Klatka ok. 3-4 ms + 3-5 ms rysowania. Sprawdzone na Comsacie:
Magicland Dizzy (wersja .t64 z trainerem), Hessian (.d64).
Dzwiek (prototyp, jeszcze nie sluchany): uklad dzwiekowy S3811 ustawiany tak
jak robi to oryginalny soft (dump.bin), 48 kHz na HDMI i na wyjsciu SCART.
Gry NES graja z dzwiekiem (oba kanaly prostokatne, trojkat, szum, DMC). Na
pudelku sprawdzone tylko po licznikach (sprzet pobiera probki z predkoscia
48000/s, nic nie ginie). Test: "video init", "snd init", "snd beep 1000 3000".
Filmy: "play plik.ts" albo Enter w eksploratorze (.ts, .mpg, .m2v, .vob,
.264, .h264, .mp4, .m4v, .mov). Obraz MPEG-1/2 dekoduje sprzetowy dekoder
MPEG-2 ukladu S3811 (ten sam, ktorego uzywa oryginalny soft do nagran),
obraz H.264 - drugi silnik tego samego bloku (profile Baseline, Main
i High, do 1920 x 1080); dzwiek MPEG (Layer II) dekodowany programowo,
zmiksowany do mono. MPEG-2 na pudelku: plik 720 x 576, 25 klatek/s,
6 Mbit/s gra w czasie rzeczywistym (500 klatek w 20,3 s, 0 bledow), klatki
odczytane z pamieci zgodne z ffmpeg; 1920 x 1080 tez sie dekoduje (do
24 ms na klatke), ale pojedyncze klatki HD sie spozniaja (3 na 250).
Skaler obrazu bierze filtry z tablicy w RAM-ie (rejestr +0x1E4 wskazuje
blok parametrow) - player wpisuje je sam, policzone tak jak w oryginalnym
sofcie; bez nich obraz na TV byl rozsypany, choc klatki w pamieci dobre.
Warstwa obrazu czyta klatke linia po linii (tryb 1 w +0x190, bity 17-18);
w trybie pol (0) obraz mial polowe wysokosci, a pod nim byly smieci.
Obraz na TV sprawdzony okiem (kamera telefonu): caly, kolory dobre.
H.264 na pudelku: zwiastun Sintel 1920 x 1080, 24 klatki/s, gra w czasie
rzeczywistym z dzwiekiem (1253 klatki w 52,6 s, zadna spozniona), klatki
odczytane z pamieci identyczne co do bajtu z ffmpeg, obraz na TV sprawdzony
okiem. Pliki .mp4 / .mov: obraz H.264 gra (720p z pliku .mp4 w czasie
rzeczywistym, klatki identyczne z ffmpeg), dzwiek (zwykle AAC) nie - film
gra bez dzwieku; z dzwiekiem: przerobic na .ts, np. "ffmpeg -i film.mp4
-c:v copy -c:a mp2 film.ts". Nie obslugiwane: H.264 z przeplotem (1080i,
czeste w nagraniach z telewizji HD), 10 bitow, 4:2:2, HEVC (DVB-T2
w Polsce i nowsze telefony: uklad nie ma do niego dekodera), pliki .mp4
dzielone na fragmenty (moof). Pliki wrzucac przez FTP. Wczesniejsze wydania
v4 potrafily zepsuc plik wysylany przez FTP na dysk USB (kilkadziesiat
bajtow w kilku miejscach; blad w obsludze DMA kontrolera USB, naprawiony) -
pliki wyslane wczesniej warto porownac z oryginalem.
PC z DOS-em: "dos plik.exe" albo Enter w eksploratorze (.exe, .com); jeden
program bez plikow danych obok (Magicland Dizzy z 1993 ich nie potrzebuje:
spacja na ekranie ustawien, Z / X albo strzalki - chodzenie, K albo gora -
skok, spacja albo Enter - podnies / uzyj). Klatka ok. 2,5-4 ms + 2-2,5 ms
rysowania (z 14,3 ms). Sprawdzone na Comsacie: Magicland Dizzy (DOS).
Amiga 500: "amiga plik.adf" albo Enter w eksploratorze; potrzebny jest
Kickstart (kick.rom) albo darmowy zamiennik AROS (aros-rom.bin i aros-ext.bin
ze strony aros.sourceforge.io) w amiga/. Dyskietka jest czytana tak jak
prawdziwa stacja (sciezki MFM), wiec dzialaja tez gry z wlasnym loaderem.
Klatka ok. 5,5-9 ms + 3-4 ms rysowania. Sprawdzone na Comsacie: Magicland
Dizzy (wersja TRSi) z AROS-em - start ok. 30 s, intro wymaga klikniecia
myszka (0 na pilocie albo Page Down).
Sega Mega Drive / Genesis: "megadrive plik.md" (albo .gen, .bin, .smd) albo
Enter w eksploratorze (.bin tylko gdy naglowek mowi, ze to gra Mega Drive).
68000 jest ten sam co w Amidze (wspolny plik m68k.inc), Z80 ten sam co w
Master System; obraz rysowany linia po linii (plany A i B, okno, sprite'y,
cien / podswietlenie, przewijanie calym ekranem, pasami i liniami), dzwiek
YM2612 (FM, 6 kanalow, DAC) i PSG. Na pudelku z dzwiekiem: Super Mario
World (Taiwan) 12,3 ms + 2,7 ms rysowania, Super Mario Bros. (hack PD)
9,3 + 1,9 ms, Snake 9,7 + 2,3 ms - pelne 60 klatek/s. Zapisy rejestrow
ukladow dzwiekowych sa zbierane przez cala klatke i graja sie na jej koncu
za jednym razem (to samo co probka po probce, ale tablice zostaja w
cache'u: dzwiek kosztowal 5,1 ms klatki, teraz 2,3 ms), a operatory FM sa
liczone co druga probke (26,6 kHz). Dema z efektami w kazdej linii
(wobble, scaling) nie mieszcza sie w 16,7 ms. Nie ma: zmian w polowie
linii, trybu interlace 2 (tylko pierwsze pole), SSG-EG i CSM w YM2612,
pada 6-przyciskowego z klawiatury. Gra Super Mario World (Taiwan) ma
zabezpieczenie (odczyt 0xA13000) - rozpoznawana po naglowku "SEGASEGA".
Sega SG-1000 / SC-3000: "sg plik.sg" (albo .sc) albo Enter w eksploratorze;
tryby obrazu TMS9918 (Graphics I i II z maskami, Multicolour, tekst 40
kolumn, sprite'y 8x8 / 16x16 z limitem 4 na linie). Klatka ok. 5 ms + 1,6
ms. Kartridze z wlasnym RAM-em: do 32 KB - 8 KB RAM-u od 0x8000 (The
Castle), 33-48 KB z pustym 0x2000-0x3FFF - RAM tam. Bez klawiatury SC-3000.
Kartridze C64 (.crt): "c64 gra.crt" albo Enter w eksploratorze; typ
rozpoznawany po naglowku "C64 CARTRIDGE", nie po nazwie; ROM-y C64 nadal
potrzebne. Klatka ok. 3,3 ms + 2,7 ms. Zapis do flasha EasyFlash jest
ignorowany (gry nie zapisza stanu), zamrazarki (Action Replay itp.) i
przycisk NMI Final Cartridge III nie sa obslugiwane.
Kolejne konsole (wszystkie z dzwiekiem 48 kHz przez "snd", obsluga .zip/.gz,
wbudowanymi czystymi zamiennikami BIOS-ow i otwieraniem z "explorer",
sprawdzone na pudelku S3811 z darmowymi grami homebrew): PC Engine ("pce",
4-10 ms/klatke), ColecoVision ("coleco", 2,5-3,5 ms) i MSX1 ("msx", 3-4,8 ms),
WonderSwan / Color ("ws", 2-10 ms przy 75,5 Hz), Super Nintendo ("snes", 6-16
ms, SPC700 BRR), Neo Geo AES/MVS ("neogeo", 2,5-14 ms, YM2610), Game Boy
Advance ("gba", 5-17 ms, ARM7TDMI + DirectSound), Atari 7800 ("a78", 4,3-6 ms)
i Atari Lynx ("lynx", 5-8,2 ms), Vectrex ("vectrex", 6-15,7 ms, 540 x 720),
Famicom Disk System ("fds", 4,6-11,3 ms), Neo Geo Pocket Color ("ngp", 8,8-11
ms), Odyssey2 / Videopac ("odyssey2", 2,5 ms), Intellivision ("intv", 4,4 ms)
oraz Sony PlayStation 1 ("psx", R3000A + GTE 3D + SPU ADPCM, strumieniowe
.cue/.bin i PS-X .exe: 2-15 ms/klatke na grach i demach 3D homebrew; eksplorator
sam odroznia pliki .exe PlayStation od programow DOS).
Archiwa: kazdy emulator bierze gre w .zip (metody stored i deflate; brany
jest najwiekszy plik, ktory nie jest tekstem, obrazkiem ani katalogiem) albo
w .gz (.adz Amigi tez); suma CRC-32 sprawdzana. Plik zapisu ma nazwe calego
pliku gry z dopisanym .sav (gra.nes.sav; przy archiwum gra.zip.sav), wiec gry
roznych konsol o tej samej nazwie maja osobne zapisy; starszy plik gra.sav
o wlasciwym rozmiarze jest nadal czytany, a zapis o innym rozmiarze (innej
konsoli) zostaje nietkniety. Gra w archiwum gra tak samo jak rozpakowana (te
same sumy obrazu na pudelku).
Wejscie antenowe ("rf"): tuner MaxLinear MxL603 na I2C 0x60 (SCB0) i
demodulator COFDM wbudowany w S3811 - ustawiane rejestr w rejestr tak jak
robi to oryginalny soft tunera (dump.bin). "rf scan" przeszukuje kanaly
21-69, "rf services" czyta nazwy kanalow (PAT, SDT), "rf ts 10 4:/x.ts"
nagrywa caly multipleks do pliku (do odtworzenia np. w VLC). Uwaga: S3811
odbiera tylko DVB-T, a w Polsce multipleksy nadaja juz w DVB-T2, wiec na
Comsacie w Polsce nie ma czego zlapac: tuner dziala, ale demodulator nie
zlapie DVB-T2. "rf spectrum" rysuje na TV poziom sygnalu z anteny od 174
do 862 MHz (ok. 35 s). Trzy rowne prostokaty po 8 MHz na 668,25, 742,5 i
816,75 MHz to NIE multipleksy ani LTE, tylko zaklocenia z samego pudelka:
harmoniczne jego zegara 74,25 MHz (zegar obrazu 720p; 9, 10 i 11 x 74,25).
Poza nimi poziom stoi na minimum (16 %): przy tych pomiarach antena nie
byla podlaczona. "rf live" to ten sam wykres mierzony w kolko: kazdy slupek rysowany
od razu po pomiarze (jedno przejscie calego pasma to nadal kilkadziesiat
sekund - tuner musi sie ustalic na kazdej czestotliwosci; waskie okno
odswieza sie co pare sekund). Klawisze (klawiatura USB, UART, pilot):
lewo / prawo - znacznik (czestotliwosc, kanal, poziom), gora / dol -
zblizenie / oddalenie wokol znacznika, PgUp / PgDn - przesuniecie okna,
F - cale pasmo, + / - krotszy / dluzszy czas pomiaru (szybciej, ale mniej
dokladnie), spacja - pauza, P - zapamietywanie szczytow, Enter - proba
zlapania DVB-T na kanale znacznika, Esc - koniec.
Hub USB: demo wlacza zasilanie portow huba, resetuje kazdy port z urzadzeniem
i odczytuje urzadzenia za hubem (takze hub za hubem), razem do 15 urzadzen
(hub musi miec jeden z pierwszych 7 adresow);
"lsusb" pokazuje kazde z numerem huba i portu. Podlaczenie i odlaczenie
urzadzenia w hubie jest zauwazane w ciagu okolo sekundy. Urzadzenia low
i full speed za hubem USB 2.0 sa obslugiwane przez translator huba (split).
Sprawdzone na Comsat TE 1050 HD z hubem 7-portowym (2 x 1a40:0101): hub,
drugi hub, trzy pamieci USB i klawiatura sa wykrywane, klawiatura za hubem
pisze.
Klawiatura USB (HID, protokol boot) pisze w tej samej linii polecen co UART:
uklad US, Enter, Backspace, strzalki gora/dol, Caps Lock, Esc = Ctrl-C,
przytrzymany klawisz sie powtarza. Wpisywana linie widac tez na TV (ramka
COMMAND LINE). Klawisze czytane sa z endpointu przerwan klawiatury, tak jak
robi to PC: kontroler pyta ja co 1 ms i dostaje raport, gdy zmieni sie stan
klawiszy. "usb kbd report" przelacza na odczyt przez GET_REPORT co 16 ms,
"usb kbd interrupt" z powrotem (demo przelacza sie tez samo, gdy wybrany
sposob jest odrzucany). Nie kazda klawiatura podaje klawisze przez GET_REPORT:
sprawdzona klawiatura low-speed 1a2c:2d23 odpowiada na nie zawsze zerami.
Pisanie na tej klawiaturze sprawdzone na Comsat TE 1050 HD.
Mysz USB (HID, protokol boot) przesuwa kursor (strzalke) po obrazie na TV,
zaczynajac od srodka. Z wcisnietym lewym przyciskiem rysuje linie, prawy
przycisk wybiera nastepny kolor (zolty, czerwony, zielony, niebieski, bialy,
pomaranczowy); przyciski i kolko sa wypisywane na UART z pozycja kursora.
Mysz odpytuje sam kontroler (jego endpoint D, co 8 ms), wiec nie przeszkadza
klawiaturze ani dyskom USB. "usb mouse" pokazuje pozycje kursora i liczniki.
Sprawdzone na Comsat TE 1050 HD: mysz A4Tech 09da:c10a (low speed) za hubem.

Plyty: Opticum HD N2 (dump_maciej.bin, panel TM1650 na GPIO 31 i 9) oraz
Comsat TE 1050 HD (dump.bin: bez wyswietlacza, dwa przyciski na tych samych
pinach, zwierane do masy). Gdy TM1650 nie odpowiada, demo przestaje sterowac
tymi pinami i czyta je jako przyciski UP (GPIO 31) i DOWN (GPIO 9).

Obraz: aplikacja rysuje 1280x720 (ARGB1555) na warstwie OSD. Na S3811
w wersji 1 naglowek warstwy (0x280 bajtow) niesie macierz RGB->YCbCr, tak jak
w oryginalnych aplikacjach; bez niej kazdy kolor bylby czarny. Bootloader nie
wlacza wyjscia wideo, wiec demo przy starcie samo odtwarza ustawienia obrazu
swojej plyty (to samo co "video init"), a dopiero potem USB - tak jak oryginal,
bo te zapisy rozlaczaja urzadzenie USB (po "video init" demo ustawia je
ponownie). Sterownik HDMI oryginalu uruchamia nadajnik dopiero, gdy wykryje
telewizor, dlatego tabele nagrano w emulatorze z "podlaczonym" telewizorem:
obejmuja start nadajnika HDMI (wyjscie z resetu, wylaczenie wyciszenia)
i koncza sie 1,5 s pozniej. Sprawdzone na Comsat TE 1050 HD (S3811 w wersji 1):
obraz przez HDMI, kolory poprawne.
Gdyby demo sie zawiesilo, watchdog po 8 s sam uruchomi tuner ponownie przez
oryginalny bootloader (skrypt aktualizacji zlapie go bez wylaczania zasilania).
Gdyby i to nie pomoglo: wylacz zasilanie i wlacz ponownie.

Do UART sluzy .maincode.bin. Bootloader, klucze i ustawienia zostaja zachowane.
Nie potrzeba szyfrowania - uzywane sa LZMA i CRC.
