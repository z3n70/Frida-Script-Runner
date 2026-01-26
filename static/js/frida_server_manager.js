
function fsmLog(message, type = 'info') {
  const out = document.getElementById('fsmOutput');
  const prefix = type === 'error' ? '<span class="text-danger">!</span>' : '<span class="text-success">~</span>';
  out.innerHTML += `${prefix} ${message} </br>`;
  out.scrollTop = out.scrollHeight;
}

function fsrLogsClear() {
  const out = document.getElementById('fsmOutput');
  out.innerHTML = '';
}

function loadDevices() {
  const devicesContainer = document.getElementById('devicesContainer');
  const targetSelect = document.getElementById('targetDeviceSelect');

  devicesContainer.innerHTML = '<div class="text-muted">Loading device info...</div>';
  targetSelect.innerHTML = '<option disabled selected>Loading devices...</option>';

  fetch('/api/adb/devices')
    .then(r => r.json())
    .then(data => {
      if (!data.success) throw new Error(data.error || 'Failed to load devices');
      if (!data.devices || data.devices.length === 0) {
        devicesContainer.innerHTML = '<div class="text-danger">No devices connected</div>';
        targetSelect.innerHTML = '<option disabled selected>No devices</option>';
        return;
      }

      devicesContainer.innerHTML = '';
      targetSelect.innerHTML = '';

      data.devices.forEach(d => {
        const isAndroid = !!d.device_id;
        const arch = d.architecture || (isAndroid ? 'unknown' : 'N/A');
        const titleIcon = isAndroid ? '<i class="bi bi-android text-success"></i>' : '<i class="bi bi-apple text-dark"></i>';
        const idDisp = isAndroid ? d.device_id : d.UDID;
        const model = (d.model || '').trim();
        const serial = (d.serial_number || '').trim();
        const ver = (d.versi_andro || '').trim();

        const card = document.createElement('div');
        card.className = 'card border-0 bg-light mb-2';
        card.innerHTML = `
          <div class="card-body p-2">
            <div class="row align-items-center">
              <div class="col-12">
                <small class="text-muted">${titleIcon} ${model || 'Unknown Model'}</small>
                <div class="mt-1">
                  <span class="badge bg-secondary me-2">ID: ${idDisp}</span>
                  ${isAndroid ? `<span class="badge bg-info text-dark me-2">Android: ${ver || '-'}</span>` : ''}
                  ${isAndroid ? `<span class="badge bg-warning text-dark">Arch: ${arch}</span>` : '<span class="badge bg-secondary">iOS</span>'}
                </div>
                ${isAndroid && serial ? `<div class="mt-1"><small class="text-muted">Serial: ${serial}</small></div>` : ''}
                ${isAndroid ? `
                  <div class="mt-2 small" id="status-${idDisp}">
                    Server: <span id="ver-${idDisp}">-</span> | PID: <span id="pid-${idDisp}">-</span> | Port: <span id="port-${idDisp}">-</span>
                    | <span id="run-${idDisp}" class="badge bg-secondary">Unknown</span>
                  </div>
                  <div class="mt-2 form-check form-switch">
                    <input class="form-check-input fsm-toggle" type="checkbox" id="enable-${idDisp}" data-device-id="${idDisp}">
                    <label class="form-check-label" for="enable-${idDisp}">Enabled</label>
                  </div>
                ` : ''}
              </div>
            </div>
          </div>
        `;
        devicesContainer.appendChild(card);

        if (isAndroid) {
          const opt = document.createElement('option');
          opt.value = d.device_id;
          opt.textContent = `${model || 'Android'} (${d.device_id}) → ${arch}`;
          opt.dataset.arch = arch || '';
          targetSelect.appendChild(opt);
        }
      });

      if (targetSelect.options.length === 0) {
        targetSelect.innerHTML = '<option disabled selected>No Android devices</option>';
      }

      const selected = targetSelect.options[targetSelect.selectedIndex];
      const arch = selected && selected.dataset.arch ? selected.dataset.arch : '';
      updateReleaseLabelsForArch(arch);
      fsmLog('Devices loaded');
      loadFridaStatus();
    })
    .catch(err => {
      devicesContainer.innerHTML = `<div class="text-danger">Error: ${err.message}</div>`;
      targetSelect.innerHTML = '<option disabled selected>Error</option>';
      fsmLog(`Error loading devices: ${err.message}`, 'error');
    });
}

function loadReleases() {
  const releaseSelect = document.getElementById('releaseSelect');
  releaseSelect.innerHTML = '<option disabled selected>Loading releases...</option>';

  fetch('/api/frida/releases')
    .then(r => r.json())
    .then(data => {
      if (!data.success) throw new Error(data.error || 'Failed to load releases');
      const releases = data.releases || [];
      if (releases.length === 0) {
        releaseSelect.innerHTML = '<option disabled selected>No releases found</option>';
        return;
      }
      releaseSelect.innerHTML = '';

      releases.forEach(tag => {
        const opt = document.createElement('option');
        opt.value = tag;
        opt.textContent = tag;
        releaseSelect.appendChild(opt);
      });
      const devSel = document.getElementById('targetDeviceSelect');
      const selected = devSel.options[devSel.selectedIndex];
      const arch = selected && selected.dataset.arch ? selected.dataset.arch : '';
      updateReleaseLabelsForArch(arch);
      fsmLog(`Loaded ${releases.length} releases`);
    })
    .catch(err => {
      releaseSelect.innerHTML = `<option disabled selected>Error loading releases</option>`;
      fsmLog(`Error loading releases: ${err.message}`, 'error');
    });
}

function startWithVersion() {
  const releaseSelect = document.getElementById('releaseSelect');
  const deviceSelect = document.getElementById('targetDeviceSelect');
  const btn = document.getElementById('startWithVersionBtn');

  const version = releaseSelect.value;
  const deviceId = deviceSelect.value;
  const portInput = document.getElementById('serverPortInput');
  const port = parseInt((portInput && portInput.value) ? portInput.value : '27042', 10) || 27042;
  if (!version || !deviceId) {
    alert('Please select a device and a Frida version.');
    return;
  }

  btn.disabled = true;
  btn.innerHTML = '<i class="bi bi-hourglass-split"></i> Starting...';
  fsmLog(`Starting frida-server ${version} on ${deviceId} ...`);

  fetch('/start-frida-server-version', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ device_id: deviceId, version, port })
  })
  .then(r => r.json())
  .then(data => {
    if (!data.success) throw new Error(data.error || 'Failed to start frida-server');
    fsmLog(`frida-server ${data.version || version} started on port ${data.port || port}. PID=${data.pid || '-'} Running=${data.running ? 'yes' : 'no'}`);
    loadFridaStatus();
  })
  .catch(err => {
    fsmLog(`Error starting frida-server: ${err.message}`, 'error');
  })
  .finally(() => {
    btn.disabled = false;
    btn.innerHTML = '<i class="bi bi-play-fill"></i> Start with Selected Version';
  });
}

function loadLocalFrida() {
  const box = document.getElementById('localFridaInfo');
  box.innerHTML = 'Loading local Frida info...';
  fetch('/api/frida/local')
    .then(r => r.json())
    .then(data => {
      if (!data.success) throw new Error(data.error || 'Failed to load local info');
      const client = data.client_version || 'Unknown';
      const tools = data.frida_tools_version || 'Unknown';
      const core = data.frida_py_version || 'Unknown';
      box.innerHTML = `
        <div>Client: <span class="badge bg-secondary">${client}</span></div>
        <div>frida (py core): <span class="badge bg-secondary">${core}</span></div>
        <div>frida-tools: <span class="badge bg-secondary">${tools}</span></div>
      `;
      fsmLog(`Local client ${client}, py ${core}, tools ${tools}`);
    })
    .catch(err => {
      box.innerHTML = `<span class="text-danger">Error: ${err.message}</span>`;
      fsmLog(`Error loading local frida info: ${err.message}`, 'error');
    });
}

function setDockerClientVersion() {
  const releaseSelect = document.getElementById('releaseSelect');
  const version = releaseSelect.value;
  const btn = document.getElementById('setDockerVersionBtn');
  if (!version) {
    alert('Please choose a Frida version first.');
    return;
  }
  btn.disabled = true;
  btn.innerHTML = '<i class="bi bi-hourglass-split"></i> Applying...';
  fsmLog(`Setting Docker Frida client to ${version} ...`);
  fetch('/api/frida/set-client-version', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ version })
  })
  .then(r => r.json())
  .then(data => {
    if (!data.success) throw new Error(data.error || 'Failed to set client version');
    fsmLog(`Docker client updated to ${data.client_version}`);
    loadLocalFrida();
  })
  .catch(err => {
    fsmLog(`Error updating Docker client: ${err.message}`, 'error');
  })
  .finally(() => {
    btn.disabled = false;
    btn.innerHTML = '<i class="bi bi-box"></i> Set Docker Client Version';
  });
}

function updateReleaseLabelsForArch(arch) {
  const releaseSelect = document.getElementById('releaseSelect');
  Array.from(releaseSelect.options).forEach(opt => {
    if (!opt.value || opt.disabled) return;
    const tag = opt.value;
    const suffix = arch ? ` → android-${arch}` : '';
    opt.textContent = `${tag}${suffix}`;
  });
}

document.addEventListener('DOMContentLoaded', function() {
  document.getElementById('refreshDevicesBtn').addEventListener('click', loadDevices);
  document.getElementById('refreshReleasesBtn').addEventListener('click', loadReleases);
  document.getElementById('startWithVersionBtn').addEventListener('click', startWithVersion);
  document.getElementById('setDockerVersionBtn').addEventListener('click', setDockerClientVersion);

  document.getElementById('targetDeviceSelect').addEventListener('change', function() {
    const selected = this.options[this.selectedIndex];
    const arch = selected && selected.dataset.arch ? selected.dataset.arch : '';
    updateReleaseLabelsForArch(arch);
  });

  loadDevices();
  loadReleases();
  loadLocalFrida();
});

function loadFridaStatus() {
  fetch('/frida-server-status')
    .then(r => r.json())
    .then(status => {
      if (!status || status.error) return;
      Object.keys(status).forEach(devId => {
        const s = status[devId];
        const verEl = document.getElementById(`ver-${devId}`);
        const pidEl = document.getElementById(`pid-${devId}`);
        const portEl = document.getElementById(`port-${devId}`);
        const runEl = document.getElementById(`run-${devId}`);
        const toggle = document.getElementById(`enable-${devId}`);
        if (verEl) verEl.textContent = s && s.version ? s.version : '-';
        if (pidEl) pidEl.textContent = s && s.pid ? s.pid : '-';
        if (portEl) portEl.textContent = s && s.port ? s.port : '-';
        if (runEl) {
          runEl.className = s && s.running ? 'badge bg-success' : 'badge bg-danger';
          runEl.textContent = s && s.running ? 'Running' : 'Stopped';
        }
        if (toggle) {
          toggle.checked = !!(s && s.running);
        }
      });
    })
    .catch(() => {});
}

// Toggle enable/disable per device
document.addEventListener('change', function(e) {
  if (e.target.classList.contains('fsm-toggle')) {
    const checkbox = e.target;
    const deviceId = checkbox.getAttribute('data-device-id');
    const portInput = document.getElementById('serverPortInput');
    const port = parseInt((portInput && portInput.value) ? portInput.value : '27042', 10) || 27042;
    if (checkbox.checked) {
      fsmLog(`Enabling frida-server on ${deviceId} (port ${port})...`);
      fetch('/start-frida-server', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ device_id: deviceId, force_download: false, port })
      })
      .then(r => r.json())
      .then(d => {
        if (!d || d.error) throw new Error(d.error || 'Failed to start');
        fsmLog(`Started on ${deviceId}. PID=${d.pid || '-'} Port=${d.port || port}`);
        loadFridaStatus();
      })
      .catch(err => {
        checkbox.checked = false;
        fsmLog(`Error enabling on ${deviceId}: ${err.message}`, 'error');
      });
    } else {
      fsmLog(`Disabling frida-server on ${deviceId}...`);
      fetch('/stop-frida-server', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ device_id: deviceId })
      })
      .then(r => r.json())
      .then(d => {
        if (!d || d.error) throw new Error(d.error || 'Failed to stop');
        fsmLog(`Stopped on ${deviceId}.`);
        loadFridaStatus();
      })
      .catch(err => {
        checkbox.checked = true;
        fsmLog(`Error disabling on ${deviceId}: ${err.message}`, 'error');
      });
    }
  }
});

