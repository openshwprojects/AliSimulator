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
Strzalki gora/dol przywracaja poprzednie komendy, Backspace kasuje znak.
Komende mozna tez zaczac od '/' (np. /restart, /lsusb).

  help                 lista komend (help <komenda> - opis jednej)
  version / ping       banner i wersja / odpowiedz "pong v4"
  info / uptime        uklad, zegar CPU, adresy w pamieci, czas pracy
  echo <slowa>         wypisuje argumenty
  md <adres> [dl]      zrzut pamieci (RAM, okno flash, rejestry)
  mr <adres>           odczyt slowa 32-bit
  mw <adres> <wart>    zapis slowa 32-bit (RAM i rejestry, nie flash)
  screen ...           obraz na TV: demo | bars | clear [rrggbb] |
                       text <x> <y> <slowa> | rect <x> <y> <w> <h> <rrggbb> |
                       on | off
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
                       o danym adresie (np. usb ctl 0x80 6 0x100 0 18 2)
  lsusb                urzadzenia USB, po jednej linii
  disks                dyski USB (pendrive, czytnik kart): rozmiar, partycje,
                       systemy plikow
  ls [n:][/sciezka]    katalog na dysku USB (FAT12, FAT16, FAT32, dlugie
                       nazwy); n - numer urzadzenia z lsusb (np. ls 3:/docs),
                       bez niego pierwszy wolumin FAT
  cat [n:]/sciezka     plik tekstowy z dysku USB (Ctrl-C przerywa; plik
                       binarny: pierwsze 256 bajtow szesnastkowo)
  sector [n:]<numer>   jeden sektor dysku USB szesnastkowo
  watchdog [test|off|on]
                       watchdog ukladu: dziala od startu demo; gdy demo stanie
                       na 8 s, tuner sam sie restartuje; test - przestaje go
                       karmic (tuner restartuje sie po 8 s)
  clear                czysci ekran terminala
  video init [opticum|comsat] [rev0|rev1]
                       odtwarza zapisy rejestrow, ktorymi oryginalne
                       oprogramowanie plyty wlacza obraz 720p i nadajnik HDMI
                       (demo robi to samo przy starcie);
                       bez nazwy - tabela tej plyty, bez rev0/rev1 - tabela
                       wersji ukladu (bajt 0xB8000000)
  reboot / restart     restart przez oryginalny bootloader
  bootloader           restart do oryginalnego bootloadera: przytrzymaj klawisz c
                       (albo uruchom maciej_uart.py), zeby w nim zostac

Pilot: kazda odebrana ramka NEC jest wypisywana z kodem i nazwa klawisza,
pokazana na ekranie i na panelu. Klawisze panelu: wypisywane po nacisnieciu.
USB: po podlaczeniu urzadzenia demo samo odczytuje jego deskryptory
i pokazuje nazwe na ekranie. Pendrive i czytniki kart (mass storage, SCSI,
bulk-only) sa od razu sprawdzane: nazwa, rozmiar, partycje (MBR lub GPT)
i system plikow. Pliki mozna czytac z FAT12/16/32 (tylko odczyt); NTFS
i exFAT sa rozpoznawane, ale nie czytane. Sprawdzone na Comsat TE 1050 HD:
karta FAT16 w czytniku 05e3:0751 - ls i cat dzialaja.
Hub USB: demo wlacza zasilanie portow huba, resetuje kazdy port z urzadzeniem
i odczytuje urzadzenia za hubem (takze hub za hubem), razem do 7 urzadzen;
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
