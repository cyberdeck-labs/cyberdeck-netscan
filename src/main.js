// Cyberdeck Netscan – Hauptprozess: Netzwerk-Scan, Ports, Ping, Traceroute
const { app, BrowserWindow, ipcMain, dialog, shell } = require('electron');
const os = require('os'), net = require('net'), dns = require('dns').promises, fs = require('fs'), path = require('path');
const { spawn, execFile } = require('child_process');

const IS_WIN = process.platform === 'win32';
const IPV4 = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;
let OUI = {};
try { OUI = JSON.parse(fs.readFileSync(path.join(__dirname, 'oui.json'), 'utf8')); } catch {}
let win, scanAbort = null, streams = new Map();

// ---------- Hilfsfunktionen ----------
const ip2n = ip => ip.split('.').reduce((a, b) => (a * 256) + +b, 0);
const n2ip = n => [24, 16, 8, 0].map(s => (n >>> s) & 255).join('.');
const maskBits = m => m.split('.').reduce((a, o) => a + (+o).toString(2).split('1').length - 1, 0);
function parseTarget(t) {
  t = String(t).trim();
  let m = t.match(/^([\d.]+)\/(\d{1,2})$/);
  if (m && IPV4.test(m[1]) && +m[2] >= 16 && +m[2] <= 32) {
    const bits = +m[2], base = (ip2n(m[1]) & (bits === 0 ? 0 : (~0 << (32 - bits)))) >>> 0, size = 2 ** (32 - bits);
    const list = [];
    for (let i = (size > 2 ? 1 : 0); i < (size > 2 ? size - 1 : size); i++) list.push(n2ip(base + i));
    return list;
  }
  m = t.match(/^([\d.]+)\s*-\s*([\d.]+)$/);
  if (m && IPV4.test(m[1]) && IPV4.test(m[2])) {
    const a = ip2n(m[1]), b = ip2n(m[2]);
    if (b >= a && b - a < 65536) return Array.from({ length: b - a + 1 }, (_, i) => n2ip(a + i));
  }
  if (IPV4.test(t)) return [t];
  throw new Error('Ungültiges Ziel. Beispiele: 192.168.1.0/24, 10.0.0.1-10.0.0.50, 172.30.51.1 (min. /16)');
}
function vendor(mac) {
  if (!mac) return '';
  const p = mac.replace(/[^0-9a-f]/gi, '').toUpperCase().slice(0, 6);
  const VM = { '080027': 'VirtualBox (VM)', '0A0027': 'VirtualBox (Host-Adapter)', '000C29': 'VMware (VM)', '005056': 'VMware (VM)', '525400': 'QEMU/KVM (VM)', '00155D': 'Hyper-V (VM)', 'BC2411': 'Proxmox (VM)' };
  if (VM[p]) return VM[p];
  if ((parseInt(p.slice(0, 2), 16) & 2) && !OUI[p]) return '(zufällige MAC)';
  return OUI[p] || '';
}
function interfaces() {
  const out = [];
  for (const [name, addrs] of Object.entries(os.networkInterfaces()))
    for (const a of addrs) if (a.family === 'IPv4' && !a.internal) {
      const bits = maskBits(a.netmask), base = n2ip((ip2n(a.address) & (~0 << (32 - bits))) >>> 0);
      out.push({ name, ip: a.address, mac: a.mac, netmask: a.netmask, cidr: bits >= 20 ? `${base}/${bits}` : `${n2ip((ip2n(a.address) & (~0 << 8)) >>> 0)}/24`, bits });
    }
  return out;
}
function ping(ip, timeoutMs = 1000) {
  return new Promise(res => {
    const args = IS_WIN ? ['-n', '1', '-w', String(timeoutMs), ip] : ['-c', '1', '-W', String(Math.ceil(timeoutMs / 1000)), '-n', ip];
    execFile('ping', args, { timeout: timeoutMs + 1500, windowsHide: true }, (err, stdout) => {
      const m = String(stdout).match(/(?:time|Zeit)[=<]\s*([\d.,]+)\s*ms/i);
      const ok = !err && (IS_WIN ? /TTL=/i.test(stdout) : true);
      res(ok ? (m ? parseFloat(m[1].replace(',', '.')) : 0.5) : null);
    });
  });
}
function tcpProbe(ip, port, timeoutMs) {
  return new Promise(res => {
    const s = new net.Socket(); let done = false, t0 = Date.now();
    const fin = st => { if (done) return; done = true; s.destroy(); res({ state: st, ms: Date.now() - t0 }); };
    s.setTimeout(timeoutMs, () => fin('timeout'));
    s.once('connect', () => fin('open'));
    s.once('error', e => fin(e.code === 'ECONNREFUSED' ? 'refused' : 'error'));
    s.connect(port, ip);
  });
}
async function pool(items, n, fn, abort) {
  let i = 0;
  await Promise.all(Array.from({ length: Math.min(n, items.length) }, async () => {
    while (i < items.length && !(abort && abort.stop)) { const it = items[i++]; await fn(it); }
  }));
}
function arpTable() {
  return new Promise(res => {
    const cmd = IS_WIN ? ['arp', ['-a']] : ['ip', ['neigh', 'show']];
    execFile(cmd[0], cmd[1], { windowsHide: true }, (e, out) => {
      const map = {};
      for (const l of String(out || '').split(/\r?\n/)) {
        const m = IS_WIN ? l.match(/^\s*([\d.]+)\s+([0-9a-f]{2}(?:-[0-9a-f]{2}){5})/i) : l.match(/^([\d.]+) .*lladdr ([0-9a-f:]{17})/i);
        if (m) map[m[1]] = m[2].replace(/-/g, ':').toLowerCase();
      }
      res(map);
    });
  });
}
async function hostname(ip) {
  try { return (await Promise.race([dns.reverse(ip), new Promise((_, r) => setTimeout(r, 1500))]))[0] || ''; } catch { return ''; }
}

const SERVICES = { 20: 'FTP-Data', 21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS', 67: 'DHCP', 80: 'HTTP', 88: 'Kerberos', 110: 'POP3',
  111: 'RPC', 123: 'NTP', 135: 'MS-RPC', 139: 'NetBIOS', 143: 'IMAP', 161: 'SNMP', 389: 'LDAP', 443: 'HTTPS', 445: 'SMB', 465: 'SMTPS', 515: 'LPD',
  548: 'AFP', 587: 'SMTP-Submit', 631: 'IPP', 636: 'LDAPS', 853: 'DNS-over-TLS', 993: 'IMAPS', 995: 'POP3S', 1433: 'MSSQL', 1883: 'MQTT', 2049: 'NFS',
  3000: 'Web-Dev', 3306: 'MySQL', 3389: 'RDP', 5000: 'Synology/Web', 5001: 'Synology HTTPS', 5432: 'PostgreSQL', 5900: 'VNC', 8000: 'HTTP-Alt',
  8006: 'Proxmox', 8080: 'HTTP-Proxy', 8443: 'HTTPS-Alt', 9000: 'Portainer', 9100: 'Drucker (RAW)', 9443: 'Portainer HTTPS', 11434: 'Ollama' };
const TOP = Object.keys(SERVICES).map(Number);
const ALIVE_PORTS = [80, 443, 22, 445, 139, 3389, 53, 8080];

// ---------- IPC ----------
ipcMain.handle('interfaces', () => interfaces());
ipcMain.handle('sweep', async (_e, target, opts = {}) => {
  const ips = parseTarget(target);
  if (ips.length > 4096) throw new Error('Maximal 4096 Adressen pro Scan (z. B. /20).');
  const own = Object.fromEntries(interfaces().map(i => [i.ip, i.mac]));
  const abort = scanAbort = { stop: false };
  const found = []; let done = 0;
  const send = (ch, d) => win && !win.isDestroyed() && win.webContents.send(ch, d);
  await pool(ips, 64, async ip => {
    let ms = await ping(ip, opts.timeout || 1000), via = 'ICMP';
    if (ms === null && opts.tcp !== false) {
      const r = await Promise.all(ALIVE_PORTS.map(p => tcpProbe(ip, p, 500)));
      const hit = r.find(x => x.state === 'open' || x.state === 'refused');
      if (hit) { ms = hit.ms; via = 'TCP'; }
    }
    done++;
    if (ms !== null) { const h = { ip, ms, via, mac: own[ip] || '', self: !!own[ip] }; found.push(h); send('host', h); }
    if (done % 8 === 0 || done === ips.length) send('progress', { done, total: ips.length });
  }, abort);
  const arp = await arpTable();
  await pool(found, 16, async h => {
    h.mac = h.mac || arp[h.ip] || ''; h.vendor = vendor(h.mac); h.name = await hostname(h.ip);
    send('host', h);
  });
  scanAbort = null;
  return { total: ips.length, found: found.length, aborted: abort.stop };
});
ipcMain.handle('stop', () => { if (scanAbort) scanAbort.stop = true; for (const p of streams.values()) p.kill(); streams.clear(); });
ipcMain.handle('ports', async (_e, ip, spec) => {
  if (!IPV4.test(ip)) throw new Error('Ungültige IP');
  let ports = TOP;
  if (spec && spec !== 'top') {
    ports = [];
    for (const part of String(spec).split(',')) {
      const m = part.trim().match(/^(\d+)(?:-(\d+))?$/); if (!m) throw new Error('Ports z. B. "1-1024" oder "22,80,443"');
      for (let p = +m[1]; p <= +(m[2] || m[1]) && p <= 65535; p++) ports.push(p);
    }
    if (ports.length > 20000) throw new Error('Maximal 20000 Ports');
  }
  const abort = scanAbort = { stop: false }, open = []; let done = 0;
  await pool(ports, 200, async port => {
    const r = await tcpProbe(ip, port, 800); done++;
    if (r.state === 'open') {
      const o = { port, service: SERVICES[port] || '', banner: await banner(ip, port) };
      open.push(o); win.webContents.send('port', o);
    }
    if (done % 25 === 0 || done === ports.length) win.webContents.send('progress', { done, total: ports.length });
  }, abort);
  scanAbort = null;
  return open.sort((a, b) => a.port - b.port);
});
function banner(ip, port) {
  return new Promise(res => {
    if ([80, 443, 8080, 8443, 5000, 5001, 8006, 9443].includes(port)) return res('');
    const s = net.connect(port, ip); let buf = '';
    const fin = () => { s.destroy(); res(buf.replace(/[^\x20-\x7e]+/g, ' ').trim().slice(0, 120)); };
    s.setTimeout(900, fin); s.on('data', d => { buf += d; if (buf.length > 100) fin(); }); s.on('error', fin); s.on('close', fin);
  });
}
ipcMain.handle('stream', (_e, kind, ip) => {
  if (!IPV4.test(ip)) throw new Error('Ungültige IP');
  let cmd, args;
  if (kind === 'ping') { cmd = 'ping'; args = IS_WIN ? ['-t', ip] : ['-n', ip]; }
  else if (IS_WIN) { cmd = 'tracert'; args = ['-d', '-w', '1000', ip]; }
  else { cmd = fs.existsSync('/usr/bin/traceroute') || fs.existsSync('/usr/sbin/traceroute') ? 'traceroute' : 'tracepath'; args = cmd === 'traceroute' ? ['-n', '-w', '1', '-q', '1', ip] : ['-n', ip]; }
  const id = Date.now() + Math.random();
  const p = spawn(cmd, args, { windowsHide: true }); streams.set(id, p);
  const out = d => win.webContents.send('stream', { id, text: String(d) });
  p.stdout.on('data', out); p.stderr.on('data', out);
  p.on('error', e => out(`Fehler: ${e.message}\n`));
  p.on('close', c => { streams.delete(id); win.webContents.send('stream', { id, end: true, code: c }); });
  return id;
});
ipcMain.handle('export', async (_e, rows) => {
  const r = await dialog.showSaveDialog(win, { defaultPath: `netscan-${new Date().toISOString().slice(0, 16).replace(/[:T]/g, '-')}.csv`, filters: [{ name: 'CSV', extensions: ['csv'] }] });
  if (r.canceled) return null;
  const esc = v => `"${String(v ?? '').replace(/"/g, '""')}"`;
  fs.writeFileSync(r.filePath, '\ufeffIP;Hostname;MAC;Hersteller;Latenz (ms);Erkannt über;Offene Ports\n' +
    rows.map(h => [h.ip, h.name, h.mac, h.vendor, h.ms, h.via, (h.ports || []).join(' ')].map(esc).join(';')).join('\n'));
  return r.filePath;
});
ipcMain.handle('open', (_e, url) => { if (/^https?:\/\/[\d.]+(:\d+)?\/?$/.test(url)) shell.openExternal(url); });

// ---------- Fenster ----------
app.whenReady().then(() => {
  win = new BrowserWindow({ width: 1280, height: 800, minWidth: 900, minHeight: 560, backgroundColor: '#07070d', title: 'Cyberdeck Netscan',
    autoHideMenuBar: true, icon: path.join(__dirname, '..', 'build', 'icon.png'),
    webPreferences: { preload: path.join(__dirname, 'preload.js'), contextIsolation: true, nodeIntegration: false, sandbox: true } });
  win.loadFile(path.join(__dirname, 'index.html'));
  if (process.env.NETSCAN_UIEVAL) {   // Test-Hook (e2e)
    if (process.env.NETSCAN_SIZE) win.setContentSize(...process.env.NETSCAN_SIZE.split('x').map(Number));
    win.webContents.once('did-finish-load', async () => {
      try { const r = await win.webContents.executeJavaScript(fs.readFileSync(process.env.NETSCAN_UIEVAL, 'utf8')); console.log('UIEVAL ' + JSON.stringify(r));
        if (process.env.NETSCAN_SHOT) fs.writeFileSync(process.env.NETSCAN_SHOT, (await win.webContents.capturePage()).toPNG()); }
      catch (e) { console.log('UIEVAL-ERR ' + e.message); }
      app.exit(0);
    });
  }
  if (app.isPackaged && !process.env.NETSCAN_UIEVAL) {
    try { require('electron-updater').autoUpdater.checkForUpdatesAndNotify(); } catch {}
  }
});
app.on('window-all-closed', () => app.quit());
