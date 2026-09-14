# Changelog

## 1.5.10

- Doku: Die Add-on-Beschreibung nannte "RustScan", obwohl RustScan nicht
  installiert ist (das Dockerfile bringt nur nmap, iw, aircrack-ng u. a. mit).
  Der Fast-Scan-Endpunkt `/scan/rustscan` fuehrt tatsaechlich nmap aus
  (`nmap -T4 --open -p- --min-rate 5000`). Die Beschreibung nennt jetzt nur
  noch nmap.

## 1.5.9

- Sicherheit: Scan-Ergebnisse werden vor der Anzeige maskiert. Servicebanner,
  Versionsangaben, SSIDs und gefundene Zugangsdaten stammen von fremden
  Geraeten im Netz und wurden bisher ungefiltert per innerHTML eingefuegt.
  Ein praepariertes Geraet haette damit Javascript in der Addon-Oberflaeche
  ausfuehren koennen.

## 1.5.7

- Fix: Absicherung gegen einen Startabsturz. Beim Binden des Webservers
  fragt Python den Hostnamen per Reverse-DNS ab. Liefert der DNS-Server
  einen Namen, der kein gültiges UTF-8 ist, warf das einen
  UnicodeDecodeError und das Addon startete nicht (Supervisor-Status
  "error"). Die Abfrage ist jetzt gekapselt.

