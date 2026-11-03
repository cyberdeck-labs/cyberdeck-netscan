const { contextBridge, ipcRenderer } = require('electron');
const on = ch => cb => ipcRenderer.on(ch, (_e, d) => cb(d));
contextBridge.exposeInMainWorld('ns', {
  interfaces: () => ipcRenderer.invoke('interfaces'),
  sweep: (t, o) => ipcRenderer.invoke('sweep', t, o),
  ports: (ip, spec) => ipcRenderer.invoke('ports', ip, spec),
  stream: (kind, ip) => ipcRenderer.invoke('stream', kind, ip),
  stop: () => ipcRenderer.invoke('stop'),
  exportCsv: rows => ipcRenderer.invoke('export', rows),
  open: url => ipcRenderer.invoke('open', url),
  onHost: on('host'), onProgress: on('progress'), onPort: on('port'), onStream: on('stream'),
});
