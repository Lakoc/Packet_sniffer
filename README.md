# Sniffer paketů `ipk-sniffer` 
Je jednoduchý síťový analýzator pro odposlech paketů. 
Program byl implementován v rámci kurzu "Počítačové komunikace a sítě". 
Program je implementovaný v jazyce C++. 

## Spuštění
Nejdříve je nutné zdrojový kód přeložit pomocí `make` v složce obsahující zdrojové kódy. 
Program je nutné spouštět s příslušných právy pro odposlech paketů, tedy nejlépe pomocí `sudo ./ipk-sniffer ...`
### Argumenty
Následně je již možné program spustit a to pomocí následujících argumentů.
- i *interface* (rozhraní, na kterém se bude poslouchat. Nebude-li tento parametr uveden, vypíše se seznam aktivních rozhraní)
- p *port* (bude filtrování paketů na daném rozhraní podle portu; nebude-li tento parametr uveden, uvažují se všechny porty)
- t nebo --tcp (bude zobrazovat pouze tcp pakety)
- -u nebo --udp (bude zobrazovat pouze udp pakety)
- -n *count* (určuje počet paketů, které se mají zobrazit, pokud není uvedeno, uvažuje se zobrazení pouze 1 paketu)
- --ipv4 (pro odposlouchávání pouze Ipv4 paketů)
- --ipv6 (pro odposlouchávání pouze Ipv6 paketů)
- --multiple_ports *ports_comma* (pro možnost filtrování vícero portů)

Kde ports_comma je řetězec síťových portů oddělených ','.
Jak v rozšíření, tak v základní verzi jako síťový port je uvažováne číslo (0 až 65535).

### Příklady spuštění
`sudo ./ipk-sniffer -i lo  --ipv6 -n 20` pro výpis 20 Ipv6 paketů na rozhraní loopback

`sudo ./ipk-sniffer -i wlp3s0  --ipv4` pro výpis 1 Ipv4 paketu na rozhraní wlp3s0

`sudo ./ipk-sniffer` pro výpis aktivních rozhraní

`sudo ./ipk-sniffer -i eth0 -p 23 --tcp -n 5` pro výpis 5 tcp paketů na portu 23 na rozhraní eth0

`sudo ./ipk-sniffer -i eth0 -p 1220 -u -n 5` pro výpis 5 udp paketů na portu 1220 na rozhraní eth0

`sudo ./ipk-sniffer -i eth0 --multiple_ports 1,2,3,4 -u -n 5` pro výpis 5 udp paketů na portech 1,2,3,4 na rozhraní eth0

## Případné rozšíření
Jako rozšíření nad rámec zadání bych považoval rozšířené možnosti filtrování paketů popsané výše, jakožto i uchovávání FQDN záznamu,
poslouchání na více portech zároveň a podporu Ipv6 paketů, u které jsem si ze zadání nebyl zcela jistý, zda bylo nutné ji implementovat.

## Seznam odevzdaných souborů
- `ipk-sniffer.cpp`
- `ipk-sniffer.h`
- `packetStructures.h`
- `manual.pdf`
- `README.md`
- `Makefile`# packet-sniffer
