function gmLog(msg) {
  const el = document.getElementById('gmStatus');
  if (el) { el.textContent = msg; }
}

async function gmFetchLocal() {
  try {
    const r = await fetch('/api/gadget/local');
    const data = await r.json();
    const tbody = document.querySelector('#gmTable tbody');
    tbody.innerHTML = '';
    if (!data.success) return;
    const items = data.items || [];
    for (const it of items) {
      const tr = document.createElement('tr');
      const size = it.size >= 0 ? (Math.round(it.size/1024/1024*100)/100 + ' MB') : '-';
      tr.innerHTML = `
        <td>${it.version}</td>
        <td>${it.arch}</td>
        <td>${it.filename ? it.filename.replace(/^lib|\.so$/g, '') : (it.path.split('\\\\').pop().split('/').pop().replace(/^lib|\.so$/g, ''))}</td>
        <td>${size}</td>
        <td><code>${it.path}</code></td>
        <td class="d-flex gap-1">
          <button class="btn btn-sm btn-outline-secondary" data-act="copy" data-ver="${it.version}" data-arch="${it.arch}" data-fn="${it.filename || ''}">Copy As</button>
          <button class="btn btn-sm btn-outline-warning" data-act="rename" data-ver="${it.version}" data-arch="${it.arch}" data-fn="${it.filename || ''}">Rename</button>
          <button class="btn btn-sm btn-outline-danger" data-act="delete" data-ver="${it.version}" data-arch="${it.arch}">Delete</button>
        </td>
      `;
      tbody.appendChild(tr);
    }
    tbody.querySelectorAll('button[data-act]').forEach(btn => {
      btn.addEventListener('click', async (e) => {
        const action = e.currentTarget.getAttribute('data-act');
        const version = e.currentTarget.getAttribute('data-ver');
        const arch = e.currentTarget.getAttribute('data-arch');
        const old_filename = e.currentTarget.getAttribute('data-fn') || '';
        if (action === 'delete') {
          if (!confirm(`Delete all cache for ${version} ${arch}?`)) return;
          const res = await fetch('/api/gadget/delete', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ version, arch })
          });
          const j = await res.json();
          if (j.success) gmFetchLocal(); else alert(j.error || 'Delete failed');
        } else if (action === 'copy' || action === 'rename') {
          const new_name = prompt('Enter new library name (allowed: letters, numbers, _ or -):');
          if (!new_name) return;
          const mode = action === 'rename' ? 'move' : 'copy';
          const res = await fetch('/api/gadget/rename', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ version, arch, old_filename, new_name, mode })
          });
          const j = await res.json();
          if (j.success) {
            alert(`${j.action || 'updated'} -> ${j.filename}`);
            gmFetchLocal();
          } else {
            alert(j.error || 'Operation failed');
          }
        }
      });
    });
  } catch {}
}

document.addEventListener('DOMContentLoaded', () => {
  const btn = document.getElementById('gmDownloadBtn');
  btn.addEventListener('click', async () => {
    const version = document.getElementById('gmVersion').value.trim();
    const arch = document.getElementById('gmArch').value;
    if (!version) { alert('Enter version, e.g., 16.7.19'); return; }
    btn.disabled = true;
    btn.innerHTML = '<span class="spinner-border spinner-border-sm"></span> Downloading...';
    try {
      const res = await fetch('/api/gadget/download', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ version, arch })
      });
      const j = await res.json();
      if (j.success) {
        alert(`Saved ${version} ${arch} (${Math.round(j.size/1024/1024*100)/100} MB)`);
        gmFetchLocal();
      } else {
        alert(j.error || 'Download failed');
      }
    } catch (e) {
      alert('Error: ' + (e && e.message ? e.message : e));
    } finally {
      btn.disabled = false;
      btn.textContent = 'Download';
    }
  });
  gmFetchLocal();
});

