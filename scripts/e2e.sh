#!/usr/bin/env bash
# End-to-End-Test: startet die App headless, scannt 127.0.0.1, Portscan gegen einen Test-Server, Ping-Stream, Fehlerfall.
# Optional: GW=<IP des Gateways> testet MAC/Hersteller-Erkennung an einem echten Gerät.
set -u
cd "$(dirname "$0")/.."
PORT=$((40000 + RANDOM % 20000))
node -e "require('net').createServer(s=>{s.write('SSH-2.0-NetscanTest\r\n')}).listen($PORT,'127.0.0.1')" & SRV=$!
trap 'kill $SRV 2>/dev/null' EXIT
sleep 0.5
T=$(mktemp --suffix=.js)
cat > "$T" <<EOF
(async () => {
  const \$ = id => document.getElementById(id), wait = ms => new Promise(r => setTimeout(r, ms));
  const until = async (f, ms = 15000) => { const t = Date.now(); while (Date.now() - t < ms) { if (f()) return true; await wait(150); } return false; };
  const r = {};
  await until(() => document.querySelectorAll('.iface').length > 0, 3000);
  r.ifaces = document.querySelectorAll('.iface').length;
  r.targetPrefilled = \$('target').value;
  \$('target').value = '999.1.1.1'; \$('scan').click();
  r.badTarget = await until(() => /Ungültiges Ziel/.test(\$('progress').textContent), 3000);
  \$('target').value = '127.0.0.1'; \$('scan').click();
  r.localhostFound = await until(() => !!document.querySelector('#hosts tr[data-ip="127.0.0.1"]'));
  await until(() => !\$('scan').disabled);
  document.querySelector('#hosts tr[data-ip="127.0.0.1"]').click();
  r.detailOpen = !\$('detail').classList.contains('hidden');
  \$('pspec').value = 'custom'; \$('pspec').onchange(); \$('pcustom').value = '$PORT,1'; \$('pscan').click();
  r.portOpen = await until(() => \$('ports').textContent.includes('$PORT/tcp'));
  r.banner = await until(() => \$('ports').textContent.includes('SSH-2.0-NetscanTest'));
  r.closedPortHidden = !\$('ports').textContent.includes('1/tcp ');
  await until(() => !\$('pscan').disabled);
  \$('ping').click();
  r.pingStream = await until(() => /ttl|TTL/.test(\$('console').textContent), 6000);
  \$('sstop').click();
  if ('${GW:-}') {
    \$('target').value = '${GW:-}'; \$('scan').click();
    await until(() => !\$('scan').disabled && document.querySelector('#hosts tr'), 20000);
    await wait(2500);
    const tr = document.querySelector('#hosts tr'); r.gateway = tr ? tr.innerText.replace(/\s+/g, ' ') : null;
  }
  r.status = \$('stat').textContent;
  return r;
})()
EOF
OUT=$(NETSCAN_UIEVAL="$T" timeout 90 node_modules/.bin/electron . --ozone-platform=headless 2>/dev/null | grep -E '^UIEVAL')
rm -f "$T"
echo "$OUT"
echo "$OUT" | python3 -c "
import sys, json
l = sys.stdin.read().strip()
if not l.startswith('UIEVAL '): print('FEHLER:', l); sys.exit(1)
r = json.loads(l[7:]); checks = ['badTarget','localhostFound','detailOpen','portOpen','banner','closedPortHidden','pingStream']
ok = [c for c in checks if r.get(c) is True]; ok += ['ifaces'] if r.get('ifaces', 0) > 0 else []
print(f'{len(ok)}/{len(checks)+1} bestanden'); sys.exit(0 if len(ok) == len(checks)+1 else 1)"
