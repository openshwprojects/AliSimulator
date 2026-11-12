ELEKTRODA ALI M3801 TEST FOR MACIEJ - v3

Aktualizacja UART dla bootloadera z dump_maciej.bin.
Wymagania: Python 3.10+, pyserial, UART 3,3 V (115200, 8E1).
Rozpakuj caly ZIP do jednego katalogu. Polacz TX-RX, RX-TX i GND.
Zamknij inne programy uzywajace portu tunera. COM3 zastap swoim portem.

python -m pip install pyserial
python maciej_uart.py --port COM3 --capture-boot 60 flash elektroda_ali_m3801_maciej_v3.maincode.bin --backup before-maciej-v3.bin

- Oryginalne oprogramowanie lub v1/v2: wlacz tuner po komunikacie gotowosci.
- Gdy dziala juz v3: zostaw tuner wlaczony. Wysylane przez skrypt "c"
  uruchomi go ponownie i przechwyci oryginalny bootloader.
- Skrypt zapisze pelny backup, wgra maincode i zweryfikuje cale 4 MiB.
  Dwa odczyty trwaja lacznie okolo 14 minut. Nie wylaczaj tunera podczas zapisu.
- Do kolejnej aktualizacji uzyj nowej nazwy backupu. Stary nie jest nadpisywany.

Komendy aplikacji - pojedynczy znak, bez Enter:
- "v" - banner i "Version: v3"
- "p" - "pong v3"
- "r" - restart przez oryginalny bootloader, potem ponowny start aplikacji
- "c" - restart do przechwycenia przez updater; updater musi dalej wysylac "c"

Samo pojedyncze "c" nie gwarantuje pozostania w bootloaderze.
Do aktualizacji uzywaj skryptu z --capture-boot 60 lub profilu ALIM3801
w BK7231GUIFlashTool. Zwykle "r" bez przechwycenia uruchamia aplikacje.

Do UART sluzy .maincode.bin. Bootloader, klucze i ustawienia zostaja zachowane.
Nie potrzeba szyfrowania - uzywane sa LZMA i CRC.
