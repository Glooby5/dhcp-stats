# dhcp-stats
Monitorování DHCP komunikace

## Soubory
- `dhcp-stats.cpp` - hlavní zdrojový kód
- `dhcp-stats.8` - manuálová stránka
- `Makefile`

## Kompilace
- příkaz `make` je nutné spustit s právy superusera (kopíruje manuálovou stránku do obecné systémové složky)

## Spuštění
- spouštět s právy superuser
- je nutné zadat interface na kterém se bude odposlouchávat pomocí přepínače `-i`
- například `./dhcp-stats -i eth1 192.168.1.0/24 192.168.0.0/22`

## Zdrojový kód
- aplikace využívá knihovny pcap
- kostra programu vychází z příkladů ze souborů k předmětu