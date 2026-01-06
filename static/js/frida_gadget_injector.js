function giLog(message, type = 'info') {
  const out = document.getElementById('giOutput');
  const prefix = type === 'error' ? '<span class="text-danger">!</span>' : '<span class="text-success">~</span>';
  out.innerHTML += `${prefix} ${message} </br>`;
  out.scrollTop = out.scrollHeight;
}

function giLogsClear() {
  const out = document.getElementById('giOutput');
  out.innerHTML = '';
}

async function loadFridaReleasesInto(selectId) {
  const select = document.getElementById(selectId);
  const seen = new Set();
  try {
    const rLocal = await fetch('/api/gadget/local');
    const jLocal = await rLocal.json();
    if (jLocal.success) {
      const versions = Array.from(new Set((jLocal.items || []).map(x => x.version)));
      if (versions.length) {
        const og = document.createElement('optgroup');
        og.label = 'Local cache';
        versions.forEach(v => {
          if (v && !seen.has(v)) {
            seen.add(v);
            const opt = document.createElement('option');
            opt.value = v;
            opt.textContent = v + ' (local)';
            og.appendChild(opt);
          }
        });
        if (og.children.length) select.appendChild(og);
      }
    }
  } catch {}

  try {
    const r = await fetch('/api/frida/releases');
    const data = await r.json();
    if (data.success) {
      const releases = data.releases || [];
      const og2 = document.createElement('optgroup');
      og2.label = 'GitHub releases';
      releases.forEach(tag => {
        if (tag && !seen.has(tag)) {
          seen.add(tag);
          const opt = document.createElement('option');
          opt.value = tag;
          opt.textContent = tag;
          og2.appendChild(opt);
        }
      });
      if (og2.children.length) select.appendChild(og2);
    }
  } catch {}
}

function loadRepoScripts() {
  const select = document.getElementById('scriptSelect');
  fetch('/api/scripts/list')
    .then(r => r.json())
    .then(data => {
      const files = data.files || [];
      files.forEach(f => {
        const opt = document.createElement('option');
        opt.value = f;
        opt.textContent = f;
        select.appendChild(opt);
      });
    })
    .catch(() => {});
}

document.addEventListener('DOMContentLoaded', function() {
  try {
    const socket = io.connect(window.location.protocol + '//' + window.location.hostname + ':' + window.location.port);
    socket.on('fsr_log', function (data) {
      giLog(data.data);
    });
  } catch (e) {
    // socket.io may not be available in some contexts
  }
  loadFridaReleasesInto('fridaVersionSelect');
  loadRepoScripts();

  const form = document.getElementById('gadgetForm');
  const btn = document.getElementById('injectBtn');
  const resultBox = document.getElementById('giResult');
  document.getElementById('resetBtn').addEventListener('click', () => {
    form.reset();
    resultBox.innerHTML = '';
    giLogsClear();
  });

  form.addEventListener('submit', function(e) {
    e.preventDefault();
    resultBox.innerHTML = '';

    const fd = new FormData(form);
    btn.disabled = true;
    btn.innerHTML = '<i class="bi bi-hourglass-split"></i> Injecting...';
    giLog('Uploading and processing APK ...');

    fetch('/api/gadget/inject', {
      method: 'POST',
      body: fd
    })
    .then(async resp => {
      const contentType = resp.headers.get('content-type') || '';
      if (resp.ok && contentType.startsWith('application/vnd.android.package-archive')) {
        const blob = await resp.blob();
        const url = window.URL.createObjectURL(blob);
        window._fsr_lastInjectedApkBlob = blob;

        const wrap = document.createElement('div');
        wrap.className = 'd-flex gap-2';

        const dl = document.createElement('a');
        dl.href = url;
        dl.download = 'gadget-injected.apk';
        dl.textContent = 'Download injected APK';
        dl.className = 'btn btn-sm btn-primary';

        const installBtn = document.createElement('button');
        installBtn.type = 'button';
        installBtn.className = 'btn btn-sm btn-success';
        installBtn.textContent = 'Install to device';
        installBtn.addEventListener('click', async () => {
          try {
            installBtn.disabled = true;
            installBtn.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> Installing...';
            giLog('Installing injected APK to connected device ...');
            const fd2 = new FormData();
            const fileName = 'gadget-injected.apk';
            const blob2 = window._fsr_lastInjectedApkBlob;
            if (!blob2) throw new Error('No APK blob available');
            fd2.append('apkFile', blob2, fileName);
            const r = await fetch('/install-apk', { method: 'POST', body: fd2 });
            const data = await r.json().catch(() => ({}));
            if (r.ok && data && (data.success || data.message === 'success')) {
              giLog('APK installed successfully');
            } else {
              const err = (data && (data.error || data.message)) || 'Install failed';
              giLog(err, 'error');
            }
          } catch (e) {
            giLog('Install error: ' + (e && e.message ? e.message : e), 'error');
          } finally {
            installBtn.disabled = false;
            installBtn.textContent = 'Install to device';
          }
        });

        wrap.appendChild(dl);
        wrap.appendChild(installBtn);
        resultBox.innerHTML = '';
        resultBox.appendChild(wrap);
        giLog('Injection completed. APK ready to download / install');
      } else {
        const data = await resp.json().catch(() => ({}));
        const err = data.error || 'Injection failed';
        giLog(err, 'error');
        resultBox.innerHTML = `<span class="text-danger">${err}</span>`;
      }
    })
    .catch(err => {
      const msg = err && err.message ? err.message : 'Network error';
      giLog(msg, 'error');
      resultBox.innerHTML = `<span class="text-danger">${msg}</span>`;
    })
    .finally(() => {
      btn.disabled = false;
      btn.innerHTML = '<i class="bi bi-plug"></i> Inject Gadget';
    });
  });
});
