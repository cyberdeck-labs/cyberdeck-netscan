// Baut src/oui.json (MAC-Prefix -> Hersteller) aus der IEEE-Liste.
// Aufruf: node scripts/build-oui.js [oui.csv]   (ohne Datei: Download von standards-oui.ieee.org)
const fs = require('fs'), path = require('path');
async function main() {
  let csv;
  if (process.argv[2]) csv = fs.readFileSync(process.argv[2], 'utf8');
  else csv = await (await fetch('https://standards-oui.ieee.org/oui/oui.csv')).text();
  const out = {};
  for (const line of csv.split(/\r?\n/).slice(1)) {
    const m = line.match(/^MA-L,([0-9A-F]{6}),("(?:[^"]|"")*"|[^,]*)/);
    if (!m) continue;
    let name = m[2].replace(/^"|"$/g, '').replace(/""/g, '"').trim();
    name = name.replace(/,? (Co\.,? ?)?(Ltd|Inc|Corp|Corporation|GmbH|LLC|Limited|AG|S\.A\.|B\.V\.)\.?$/i, '').trim();
    out[m[1]] = name;
  }
  fs.writeFileSync(path.join(__dirname, '..', 'src', 'oui.json'), JSON.stringify(out));
  console.log('OUI-Einträge:', Object.keys(out).length);
}
main();
