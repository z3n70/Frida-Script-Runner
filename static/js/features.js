function filterOptions(searchInputId, selectId) {
    const input = document.getElementById(searchInputId);
    const filter = input.value.toUpperCase();
    const select = document.getElementById(selectId);
    const options = select.options;
    
    for (let i = 0; i < options.length; i++) {
      const txtValue = options[i].text || options[i].innerText;
      options[i].style.display = txtValue.toUpperCase().includes(filter) ? "" : "none";
    }
}

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
        
        const blob = await response.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        
        const customName = formData.get('custom_name');
        const packageName = formData.get('package');
        const filename = customName ? `${customName.replace(/\.apk$/i, '')}.apk` : `${packageName}.apk`;
        
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