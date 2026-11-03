// Cyberdeck Netscan – Oberfläche
const $ = id => document.getElementById(id);
const hosts = new Map();
let sortKey = 'ip', sortDir = 1, current = null, busy = false, streamId = null;
const ipNum = ip => ip.split('.').reduce((a, b) => a * 256 + +b, 0);
const esc = s => String(s ?? '').replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));

function status(t) { $('stat').textContent = t; }
function setBusy(b) { busy = b; $('scan').disabled = b; $('pscan').disabled = b; }

async function loadIfaces() {
  const list = await ns.interfaces();
  $('ifaces').innerHTML = list.map((i, n) => `<div class="iface" data-cidr="${esc(i.cidr)}"><b>${esc(i.name)}</b> ${esc(i.ip)}<br><span class="dim">${esc(i.cidr)} · ${esc(i.mac)}</span></div>`).join('') || '<div class="dim">Kein Netzwerk gefunden</div>';
  document.querySelectorAll('.iface').forEach(el => el.onclick = () => {
    document.querySelectorAll('.iface').forEach(x => x.classList.remove('sel')); el.classList.add('sel'); $('target').value = el.dataset.cidr;
  });
  const first = document.querySelector('.iface'); if (first && !$('target').value) first.click();
}

function render() {
  const f = $('filter').value.toLowerCase();
  const rows = [...hosts.values()].filter(h => !f || [h.ip, h.name, h.mac, h.vendor].join(' ').toLowerCase().includes(f));
  rows.sort((a, b) => {
    const va = sortKey === 'ip' ? ipNum(a.ip) : sortKey === 'ms' ? a.ms : String(a[sortKey] || '').toLowerCase();
    const vb = sortKey === 'ip' ? ipNum(b.ip) : sortKey === 'ms' ? b.ms : String(b[sortKey] || '').toLowerCase();
    return (va > vb ? 1 : va < vb ? -1 : 0) * sortDir;
  });
  $('hosts').innerHTML = rows.map(h => `<tr data-ip="${h.ip}" class="${current === h.ip ? 'sel' : ''}">
    <td class="ip ${h.self ? 'self' : ''}">${h.ip}</td><td>${esc(h.name)}</td><td>${esc(h.mac)}</td><td>${esc(h.vendor)}</td>
    <td>${h.ms < 1 ? '<1' : Math.round(h.ms)} ms ${h.via === 'TCP' ? '<span class="tcp">TCP</span>' : ''}</td></tr>`).join('');
  $('empty').classList.toggle('hidden', hosts.size > 0);
  $('count').textContent = hosts.size ? `${rows.length} / ${hosts.size} Geräte` : '';
  document.querySelectorAll('#hosts tr').forEach(tr => tr.onclick = () => openDetail(tr.dataset.ip));
}
let rt; const renderSoon = () => { clearTimeout(rt); rt = setTimeout(render, 60); };

ns.onHost(h => { hosts.set(h.ip, { ...(hosts.get(h.ip) || {}), ...h }); renderSoon(); if (current === h.ip) detailInfo(); });
ns.onProgress(p => { $('bar').style.width = (100 * p.done / p.total) + '%'; $('progress').textContent = `${p.done} / ${p.total}`; });

$('scan').onclick = async () => {
  hosts.clear(); render(); setBusy(true); status('SCANNE …'); const t0 = Date.now();
  try {
    const r = await ns.sweep($('target').value, { tcp: $('tcp').checked });
    status(`${r.found} GERÄTE · ${r.total} ADRESSEN · ${((Date.now() - t0) / 1000).toFixed(1)} s${r.aborted ? ' · ABGEBROCHEN' : ''}`);
  } catch (e) { status('FEHLER'); $('progress').textContent = e.message.replace(/^Error invoking remote method '\w+': (Error: )?/, ''); }
  setBusy(false);
};
$('stop').onclick = () => ns.stop();
$('target').onkeydown = e => { if (e.key === 'Enter' && !busy) $('scan').click(); };
$('filter').oninput = render;
document.querySelectorAll('th').forEach(th => th.onclick = () => { const k = th.dataset.k; sortDir = sortKey === k ? -sortDir : 1; sortKey = k; render(); });
$('export').onclick = async () => { const p = await ns.exportCsv([...hosts.values()].sort((a, b) => ipNum(a.ip) - ipNum(b.ip))); if (p) status('GESPEICHERT: ' + p); };

function detailInfo() {
  const h = hosts.get(current) || { ip: current };
  $('dip').textContent = h.ip;
  $('dinfo').innerHTML = [h.name, h.mac && `${h.mac}${h.vendor ? ' · ' + esc(h.vendor) : ''}`].filter(Boolean).map(esc).join('<br>') || 'keine weiteren Infos';
}
function openDetail(ip) {
  current = ip; $('detail').classList.remove('hidden'); detailInfo(); render();
  const h = hosts.get(ip); $('ports').innerHTML = h && h.portList ? portRows(h.portList) : ''; $('console').textContent = '';
}
const WEB = { 80: 'http', 8080: 'http', 8000: 'http', 3000: 'http', 5000: 'http', 443: 'https', 8443: 'https', 5001: 'https', 8006: 'https', 9443: 'https' };
function portRows(list) {
  return list.map(p => `<tr><td>${p.port}/tcp</td><td>${esc(p.service)}${WEB[p.port] ? ` <a data-u="${WEB[p.port]}://${current}:${p.port}/">öffnen</a>` : ''}
    ${p.banner ? `<div class="ban">${esc(p.banner)}</div>` : ''}</td></tr>`).join('') || '<tr><td colspan="2" class="dim">keine offenen Ports gefunden</td></tr>';
}
$('ports').onclick = e => { if (e.target.dataset.u) ns.open(e.target.dataset.u); };
$('dclose').onclick = () => { current = null; $('detail').classList.add('hidden'); render(); };
$('pspec').onchange = () => $('pcustom').classList.toggle('hidden', $('pspec').value !== 'custom');
let livePorts = [];
ns.onPort(p => { livePorts.push(p); livePorts.sort((a, b) => a.port - b.port); $('ports').innerHTML = portRows(livePorts); });
$('pscan').onclick = async () => {
  const ip = current; livePorts = []; $('ports').innerHTML = '<tr><td colspan="2" class="dim">scanne …</td></tr>'; setBusy(true); status('PORTSCAN ' + ip);
  try {
    const spec = $('pspec').value === 'custom' ? $('pcustom').value : $('pspec').value;
    const list = await ns.ports(ip, spec);
    const h = hosts.get(ip) || { ip, ms: 0 }; h.portList = list; h.ports = list.map(p => p.port); hosts.set(ip, h);
    if (current === ip) $('ports').innerHTML = portRows(list);
    status(`${list.length} OFFENE PORTS AUF ${ip}`);
  } catch (e) { $('ports').innerHTML = `<tr><td colspan="2" style="color:var(--r)">${esc(e.message.replace(/^Error invoking remote method '\w+': (Error: )?/, ''))}</td></tr>`; status('FEHLER'); }
  setBusy(false);
};
async function startStream(kind) {
  await ns.stop(); $('console').textContent = `> ${kind} ${current}\n`; streamId = await ns.stream(kind, current);
}
ns.onStream(d => {
  if (d.id !== streamId) return;
  const c = $('console');
  if (d.end) c.textContent += `\n[beendet]\n`; else c.textContent += d.text;
  c.scrollTop = c.scrollHeight;
});
$('ping').onclick = () => startStream('ping');
$('trace').onclick = () => startStream('trace');
$('sstop').onclick = () => ns.stop();
loadIfaces();
