# Changelog

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

