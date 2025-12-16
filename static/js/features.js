function filterOptions(searchInputId, selectId) {
  const input = document.getElementById(searchInputId);
  const select = document.getElementById(selectId);
  const options = select ? select.options : [];

  const norm = (s) => (s || '').toString().toLowerCase().replace(/[^a-z0-9]/g, '');
  const needle = norm(input.value);

  let firstVisibleIndex = -1;
  for (let i = 0; i < options.length; i++) {
    const txtValue = options[i].text || options[i].innerText || '';
    const hay = norm(txtValue);
    const match = hay.includes(needle);
    options[i].style.display = match ? '' : 'none';
    if (match && firstVisibleIndex === -1) firstVisibleIndex = i;
  }
  if (firstVisibleIndex !== -1) {
    select.selectedIndex = firstVisibleIndex;
  }
}

function loadAndroidPackagesFeatures() {
  const select = document.getElementById('packageSelectAndroid');
  const refreshBtn = document.getElementById('refreshPackagesAndroid');
  if (!select) return;

  const previous = select.value;
  select.innerHTML = '<option disabled>Loading packages...</option>';
  if (refreshBtn) {
    refreshBtn.disabled = true;
    refreshBtn.innerHTML = '<i class="bi bi-hourglass-split"></i> Refreshing...';
  }

  // Try frida-ps list (Name - identifier) first, then fallback to installed labels.
  fetch('/get-packages')
    .then(r => r.json())
    .then(data => {
      if (!data.success || !Array.isArray(data.packages) || data.packages.length === 0) {
        throw new Error(data.error || 'Empty');
      }
      const pkgs = data.packages;
      select.innerHTML = '';
      pkgs.forEach(item => {
        const opt = document.createElement('option');
        const parts = (item || '').toString().split(' - ');
        const value = parts.length >= 2 ? parts[1] : (item || '');
        opt.value = value;
        opt.text = item; // "Name - identifier"
        select.appendChild(opt);
      });
    })
    .catch(() => {
      return fetch('/api/android/packages-with-labels')
        .then(r => r.json())
        .then(data => {
          if (!data.success) throw new Error(data.error || 'Failed to load packages');
          const pkgs = data.packages || [];
          select.innerHTML = '';
          if (pkgs.length === 0) {
            select.innerHTML = '<option disabled>No packages detected</option>';
            return;
          }
          pkgs.forEach(p => {
            const opt = document.createElement('option');
            opt.value = p.package || p;
            opt.text = p.display || p.package || p;
            select.appendChild(opt);
          });
        });
    })
    .finally(() => {
      // Try to preserve selection
      if (previous) {
        try { select.value = previous; } catch (e) {}
      }
      // Apply current search filter if any
      const input = document.getElementById('searchInputAndroid');
      if (input && input.value) {
        filterOptions('searchInputAndroid', 'packageSelectAndroid');
      }
      if (refreshBtn) {
        refreshBtn.disabled = false;
        refreshBtn.innerHTML = '<i class="bi bi-arrow-clockwise"></i> Refresh Packages';
      }
    });
}

document.addEventListener('DOMContentLoaded', function() {
  const btn = document.getElementById('refreshPackagesAndroid');
  if (btn) btn.addEventListener('click', loadAndroidPackagesFeatures);
  // Populate on first load using the refresh mechanism
  loadAndroidPackagesFeatures();
});

// apk download
document.getElementById('apkDownloadForm').addEventListener('submit', async function(e) {
    e.preventDefault();
    
    const form = e.target;
    const formData = new FormData(form);
    const submitBtn = form.querySelector('button[type="submit"]');
    
    submitBtn.disabled = true;
    submitBtn.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> Downloading...';
    
    try {
        const response = await fetch(form.action, {
            method: 'POST',
            body: formData
        });
        
        if (!response.ok) {
            const errorText = await response.text();
            throw new Error(errorText || 'Download failed');
        }
        // Determine filename from server headers first
        let serverFilename = null;
        const cd = response.headers.get('Content-Disposition');
        if (cd) {
          // Try RFC 5987 filename* then basic filename
          const fnStar = /filename\*=UTF-8''([^;]+)/i.exec(cd);
          const fnBasic = /filename\s*=\s*"?([^";]+)"?/i.exec(cd);
          if (fnStar && fnStar[1]) {
            try { serverFilename = decodeURIComponent(fnStar[1]); } catch (_) { serverFilename = fnStar[1]; }
          } else if (fnBasic && fnBasic[1]) {
            serverFilename = fnBasic[1];
          }
        }

        const blob = await response.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        
        let filename = serverFilename;
        if (!filename) {
          // Fallback: infer from content-type
          const ct = (response.headers.get('Content-Type') || '').toLowerCase();
          const customName = (formData.get('custom_name') || '').trim();
          const packageName = (formData.get('package') || '').trim();
          if (ct.includes('zip')) {
            filename = (customName ? customName.replace(/\.zip$/i, '') : packageName) + '.zip';
          } else {
            filename = (customName ? customName.replace(/\.apk$/i, '') : packageName) + '.apk';
          }
        }

        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
        a.remove();
        
    } catch (error) {
        alert('Download failed: ' + error.message);
    } finally {
        submitBtn.disabled = false;
        submitBtn.innerHTML = '<i class="bi bi-download"></i> Download APK';
    }
});

// apk install
document.getElementById('uploadForm').addEventListener('submit', function(e) {
    e.preventDefault();
    
    const form = e.target;
    const formData = new FormData(form);
    const progressBar = document.getElementById('progressBar');
    const progressContainer = document.getElementById('progressBarContainer');
    const statusMessage = document.getElementById('statusMessage');
    const installBtn = document.getElementById('installBtn');
    
    statusMessage.classList.add('d-none');
    progressContainer.classList.remove('d-none');
    progressBar.style.width = '0%';
    installBtn.disabled = true;
    
    progressBar.style.width = '10%';
    
    fetch('/install-apk', {
        method: 'POST',
        body: formData
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            progressBar.style.width = '100%';
            progressBar.classList.remove('progress-bar-animated');
            showStatus('APK installed successfully!', 'alert-success');
        } else {
            progressBar.style.width = '0%';
            showStatus('Installation failed: ' + (data.error || data.message), 'alert-danger');
        }
    })
    .catch(error => {
        progressBar.style.width = '0%';
        showStatus('Error: ' + error.message, 'alert-danger');
    })
    .finally(() => {
        installBtn.disabled = false;
    });
    
    function showStatus(message, alertClass) {
        statusMessage.textContent = message;
        statusMessage.className = `alert ${alertClass}`;
        statusMessage.classList.remove('d-none');
    }
});

//dump ipa progress bar and response berhasil well
document.getElementById('dumpIPAForm').addEventListener('submit', function(e) {
    e.preventDefault();

    const form = e.target;
    const formData = new FormData(form);
    const progressBar = document.getElementById('progressBarIOS');
    const progressContainer = document.getElementById('progressBarContainerIOS');
    const statusMessage = document.getElementById('statusMessageIOS');

    progressBar.style.width = '0%';
    progressContainer.classList.remove('d-none');
    statusMessage.classList.add('d-none');
    progressBar.classList.add('progress-bar-animated');

    let fProg = 10;
    const interval = setInterval(() => {
        fProg += 5;
        if (fProg >= 95) {
            clearInterval(interval);
        }
        progressBar.style.width = `${fProg}%`;
    }, 500);

    fetch('/dump-ipa', {
        method: 'POST',
        body: formData
    }).then(async response => {
        if (response.ok) {
            const contentType = response.headers.get('Content-Type');

            if (contentType && contentType.includes('application/json')) {
                const result = await response.json();
                progressBar.style.width = '100%';
                progressBar.classList.remove('progress-bar-animated');
                showStatus(result.message, 'alert-success');
            } else {
                // Download file IPA
                const blob = await response.blob();
                const downloadUrl = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = downloadUrl;
                a.download = formData.get('ipa_name') + '.ipa';
                document.body.appendChild(a);
                a.click();
                a.remove();
                URL.revokeObjectURL(downloadUrl);

                progressBar.style.width = '100%';
                progressBar.classList.remove('progress-bar-animated');
                // showStatus('IPA berhasil diunduh!', 'alert-success');
            }
        } else {
            const errorText = await response.text();
            showStatus(`Error: ${errorText}`, 'alert-danger');
            progressBar.style.width = '0%';
        }
    }).catch(error => {
        showStatus(`Gagal: ${error.message}`, 'alert-danger');
        progressBar.style.width = '0%';
    }).finally(() => {
        clearInterval(interval);
    });

    function showStatus(message, alertClass) {
        statusMessage.textContent = message;
        statusMessage.className = `alert ${alertClass}`;
        statusMessage.classList.remove('d-none');
    }
});

//tooltip
document.addEventListener('DOMContentLoaded', function() {
    var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(function (tooltipTriggerEl) {
      return new bootstrap.Tooltip(tooltipTriggerEl);
    });
  });
