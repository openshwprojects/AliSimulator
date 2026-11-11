ELEKTRODA ALI M3801 TEST FOR MACIEJ - v2

Paczka do aktualizacji UART dla bootloadera z dump_maciej.bin.
Wymagania: Python 3.10 lub nowszy, pyserial, adapter UART 3,3 V.
Nie trzeba pobierac repozytorium ani kompilowac aplikacji.

1. Rozpakuj caly ZIP do jednego katalogu i otworz w nim terminal.
2. Podlacz TX adaptera do RX tunera, RX adaptera do TX tunera i wspolna mase.
   Zamknij inne programy korzystajace z tego portu COM.
3. Zainstaluj pyserial:

python -m pip install pyserial

4. Uruchom ponizsza komende, zmieniajac COM3 na swoj port:

python maciej_uart.py --port COM3 --capture-boot 60 flash elektroda_ali_m3801_maciej_v2.maincode.bin --backup before-maciej-v2.bin

5. Gdy pojawi sie "Power-cycle the device now", od razu wylacz i wlacz
   zasilanie tunera. Skrypt przez 60 sekund przechwytuje bootloader
   i sam ustawia UART na 115200, 8E1.
6. Poczekaj na koniec. Skrypt odczyta backup, sprawdzi bootloader, wgra
   maincode, odczyta cala pamiec dla weryfikacji i zrestartuje tuner.
   Same dwa odczyty flash zajmuja lacznie okolo 14 minut.
   Zachowaj plik backupu. Nie przerywaj zasilania podczas zapisu flash.
7. Po zakonczeniu otworz terminal szeregowy 115200, 8E1.
   Wyslij "v" bez Enter - oczekiwane:

ELEKTRODA ALI M3801 TEST FOR MACIEJ
Version: v2

   Wyslij "p" bez Enter - oczekiwane: "pong v2".

Kolejne aktualizacje wykonuje sie tak samo. Uzyj nowej nazwy backupu,
np. before-maciej-v2-repeat.bin. Skrypt odmawia nadpisania starego backupu.

Do UART sluzy plik .maincode.bin (64 KiB). Pelny obraz 4 MiB jest
przeznaczony do symulatora lub programatora i nie jest dolaczony do tego ZIP-a.
Podmieniany jest maincode od 0x50000; oryginalny bootloader zostaje.
Nie jest potrzebne szyfrowanie - obraz uzywa kompresji LZMA i sum CRC.

W symulatorze sprawdzono dwie kolejne aktualizacje: oryginal -> v1 -> v2,
restart i zimny start kazdej wersji, odpowiedzi "v" i "p" oraz weryfikacje
flash. Sprawdzono tez ponowienie pakietu z blednym CRC.
Test na fizycznym tunerze pozostaje do wykonania.
