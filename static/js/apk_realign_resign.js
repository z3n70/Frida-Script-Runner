function resignLog(message, type = 'info') {
  const out = document.getElementById('resignOutput');
  const prefix = type === 'error' ? '<span class="text-danger">!</span>' : '<span class="text-success">~</span>';
  out.innerHTML += `${prefix} ${message} </br>`;
  out.scrollTop = out.scrollHeight;
}

function resignLogsClear() {
  const out = document.getElementById('resignOutput');
  out.innerHTML = '';
}

document.addEventListener('DOMContentLoaded', function() {
  try {
    const socket = io.connect(window.location.protocol + '//' + window.location.hostname + ':' + window.location.port);
    socket.on('fsr_log', function (data) { resignLog(data.data); });
  } catch (e) {}

  const form = document.getElementById('resignForm');
  const btn = document.getElementById('resignBtn');
  const resultBox = document.getElementById('resignResult');
  const ksSwitch = document.getElementById('useCustomKs');
  const ksFields = document.getElementById('customKsFields');

  ksSwitch.addEventListener('change', () => {
    ksFields.style.display = ksSwitch.checked ? 'block' : 'none';
  });

  document.getElementById('resetBtn').addEventListener('click', () => {
    form.reset();
    ksFields.style.display = 'none';
    resultBox.innerHTML = '';
    resignLogsClear();
  });

  form.addEventListener('submit', function(e) {
    e.preventDefault();
    resultBox.innerHTML = '';

    const fd = new FormData(form);
    btn.disabled = true;
    btn.innerHTML = '<i class="bi bi-hourglass-split"></i> Processing...';
    resignLog('Uploading APK for re-align & re-sign ...');

    fetch('/api/apk/realign-resign', { method: 'POST', body: fd })
      .then(async resp => {
        const contentType = resp.headers.get('content-type') || '';
        if (resp.ok && contentType.startsWith('application/vnd.android.package-archive')) {
          const blob = await resp.blob();
          const url = window.URL.createObjectURL(blob);
          window._fsr_lastResignedApkBlob = blob;

          const wrap = document.createElement('div');
          wrap.className = 'd-flex gap-2';

          const dl = document.createElement('a');
          dl.href = url;
          dl.download = 'resigned.apk';
          dl.textContent = 'Download resigned APK';
          dl.className = 'btn btn-sm btn-primary';

          const installBtn = document.createElement('button');
          installBtn.type = 'button';
          installBtn.className = 'btn btn-sm btn-success';
          installBtn.textContent = 'Install to device';
          installBtn.addEventListener('click', async () => {
            try {
              installBtn.disabled = true;
              installBtn.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> Installing...';
              resignLog('Installing APK to connected device ...');
              const fd2 = new FormData();
              const blob2 = window._fsr_lastResignedApkBlob;
              if (!blob2) throw new Error('No APK blob available');
              fd2.append('apkFile', blob2, 'resigned.apk');
              const r = await fetch('/install-apk', { method: 'POST', body: fd2 });
              const data = await r.json().catch(() => ({}));
              if (r.ok && data && (data.success || data.message === 'success')) {
                resignLog('APK installed successfully');
              } else {
                const err = (data && (data.error || data.message)) || 'Install failed';
                resignLog(err, 'error');
              }
            } catch (e) {
              resignLog('Install error: ' + (e && e.message ? e.message : e), 'error');
            } finally {
              installBtn.disabled = false;
              installBtn.textContent = 'Install to device';
            }
          });

          wrap.appendChild(dl);
          wrap.appendChild(installBtn);
          resultBox.innerHTML = '';
          resultBox.appendChild(wrap);
          resignLog('Re-align & re-sign completed. APK ready to download / install');
        } else {
          const data = await resp.json().catch(() => ({}));
          const err = data.error || 'Re-sign failed';
          resignLog(err, 'error');
          resultBox.innerHTML = `<span class="text-danger">${err}</span>`;
        }
      })
      .catch(err => {
        const msg = err && err.message ? err.message : 'Network error';
        resignLog(msg, 'error');
        resultBox.innerHTML = `<span class="text-danger">${msg}</span>`;
      })
      .finally(() => {
        btn.disabled = false;
        btn.innerHTML = '<i class="bi bi-check2-circle"></i> Re-Align & Re-Sign';
      });
  });
});

