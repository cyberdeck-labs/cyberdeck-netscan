# Cyberdeck Netscan

Cyberpunk-styled network scanner – part of the Cyberdeck series (Netrunner, Editor).

![Icon](build/icon.png)

## Features
- **Find devices on the network:** ping sweep over a network (`192.168.1.0/24`), a range (`10.0.0.1-10.0.0.50`) or a single IP
- **Thorough mode:** also finds devices that don't answer pings (TCP check on common ports)
- **MAC address and vendor** (offline, IEEE OUI list), detects VMs (VirtualBox, VMware, Hyper-V, QEMU, Proxmox)
- **Hostnames** via reverse DNS
- **Port scan:** top ports with service names, 1–1024, all, or a custom list; banners (e.g. SSH version); open web services with one click
- Live **ping** and **traceroute**
- **CSV export** (opens directly in Excel/LibreOffice)
- Auto-update via GitHub Releases, Linux (AppImage) and Windows

## Note
Only scan networks you are allowed to scan. Some devices (e.g. NAS with DoS protection) briefly block the scanner after a port scan.

## Development
```
npm install
npm start
npm test          # end-to-end test (headless)
npm run oui       # refresh the vendor list
```
