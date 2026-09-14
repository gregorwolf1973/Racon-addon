# Recon – Home Assistant Add-on

[!["Buy Me A Coffee"](https://www.buymeacoffee.com/assets/img/custom_images/orange_img.png)](https://buymeacoffee.com/gregorwolf1973)

Netzwerk-, IP- und WLAN-Scanner für Home Assistant OS. Das Add-on bündelt
gängige Recon-Werkzeuge hinter einer Weboberfläche, die über Home Assistant
Ingress in der Seitenleiste geöffnet wird.

> Nur im eigenen Netzwerk bzw. mit ausdrücklicher Erlaubnis einsetzen.

## Funktionen

- **IP-/Port-Scan** mit Nmap (Profile: quick, fast, service, full, os, stealth)
- **WLAN-Scan** mit `iw` / `iwlist` und `airodump-ng`; Monitor-Modus über
  `airmon-ng` (aircrack-ng)
- **Web-Tools**: Nikto (Schwachstellen-Scan) und ffuf (Directory-Fuzzing)
- **Login-Formular-Erkennung** und **Brute-Force** über Hydra sowie ein
  CSRF-fähiger Brute-Force
- **Wordlist-Verwaltung**: mitgelieferte SecLists-Listen plus eigene Uploads,
  dauerhaft gespeichert unter `/data`

## Voraussetzungen

- Läuft mit `host_network` und benötigt die Berechtigungen `NET_ADMIN`,
  `NET_RAW` und `SYS_ADMIN`
- Architekturen: `aarch64`, `amd64`

## Konfiguration

| Option | Typ | Standard | Beschreibung |
|--------|-----|----------|--------------|
| `port` | int | `8765` | Interner Port der Weboberfläche |

## Installation

1. In Home Assistant: **Settings → Add-ons → Add-on Store → ⋮ → Repositories**
2. Repository hinzufügen: `https://github.com/gregorwolf1973/Racon-addon`
3. Das Add-on **Recon** installieren und starten
4. Über die HA-Seitenleiste (Ingress) öffnen

## Support

Wenn dir dieses Add-on hilft, freue ich mich über einen Kaffee:

[!["Buy Me A Coffee"](https://www.buymeacoffee.com/assets/img/custom_images/orange_img.png)](https://buymeacoffee.com/gregorwolf1973)
