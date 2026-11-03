# Cyberdeck Netscan

Netzwerk-Scanner im Cyberpunk-Look – Teil der Cyberdeck-Reihe (Netrunner, Editor).

![Icon](build/icon.png)

## Funktionen
- **Geräte im Netz finden:** Ping-Sweep über ein Netz (`192.168.1.0/24`), einen Bereich (`10.0.0.1-10.0.0.50`) oder eine einzelne IP
- **Gründlich-Modus:** findet auch Geräte, die nicht auf Ping antworten (TCP-Check auf typische Ports)
- **MAC-Adresse und Hersteller** (offline, IEEE-OUI-Liste), erkennt VMs (VirtualBox, VMware, Hyper-V, QEMU, Proxmox)
- **Hostnamen** per Reverse-DNS
- **Portscan:** Top-Ports mit Dienstnamen, 1–1024, alle oder eigene Liste; Banner (z. B. SSH-Version); Web-Dienste mit einem Klick öffnen
- **Ping** und **Traceroute** live
- **CSV-Export** (öffnet sich direkt in Excel/LibreOffice)
- Auto-Update über GitHub-Releases, Linux (AppImage) und Windows

## Hinweis
Nur Netze scannen, für die du die Erlaubnis hast. Manche Geräte (z. B. NAS mit DoS-Schutz) sperren den Scanner nach einem Portscan kurz.

## Entwickeln
```
npm install
npm start
npm test          # End-to-End-Test (headless)
npm run oui       # Herstellerliste neu laden
```
