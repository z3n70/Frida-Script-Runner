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
        <td>${size}</td>
        <td><code>${it.path}</code></td>
        <td>
          <button class="btn btn-sm btn-outline-danger" data-ver="${it.version}" data-arch="${it.arch}">Delete</button>
        </td>
      `;
      tbody.appendChild(tr);
    }
    tbody.querySelectorAll('button[data-ver]').forEach(btn => {
      btn.addEventListener('click', async (e) => {
        const version = e.target.getAttribute('data-ver');
        const arch = e.target.getAttribute('data-arch');
        if (!confirm(`Delete ${version} ${arch}?`)) return;
        const res = await fetch('/api/gadget/delete', {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ version, arch })
        });
        const j = await res.json();
        if (j.success) gmFetchLocal(); else alert(j.error || 'Delete failed');
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

