// Simple logger to the page-local FSR logs box
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

      // Render device cards
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
              </div>
            </div>
          </div>
        `;
        devicesContainer.appendChild(card);

        if (isAndroid) {
          const opt = document.createElement('option');
          opt.value = d.device_id;
          opt.textContent = `${model || 'Android'} (${d.device_id}) — ${arch}`;
          opt.dataset.arch = arch || '';
          targetSelect.appendChild(opt);
        }
      });

      if (targetSelect.options.length === 0) {
        targetSelect.innerHTML = '<option disabled selected>No Android devices</option>';
      }

      // Trigger release label update according to selected device arch
      const selected = targetSelect.options[targetSelect.selectedIndex];
      const arch = selected && selected.dataset.arch ? selected.dataset.arch : '';
      updateReleaseLabelsForArch(arch);
      fsmLog('Devices loaded');
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
        // Label will be post-processed with arch info
        opt.textContent = tag;
        releaseSelect.appendChild(opt);
      });
      // After loading, add arch suffix if device selected
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
    body: JSON.stringify({ device_id: deviceId, version })
  })
  .then(r => r.json())
  .then(data => {
    if (!data.success) throw new Error(data.error || 'Failed to start frida-server');
    fsmLog(`frida-server ${version} started. Running=${data.running ? 'yes' : 'no'}`);
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
    const suffix = arch ? ` — android-${arch}` : '';
    opt.textContent = `${tag}${suffix}`;
  });
}

document.addEventListener('DOMContentLoaded', function() {
  document.getElementById('refreshDevicesBtn').addEventListener('click', loadDevices);
  document.getElementById('refreshReleasesBtn').addEventListener('click', loadReleases);
  document.getElementById('startWithVersionBtn').addEventListener('click', startWithVersion);
  document.getElementById('setDockerVersionBtn').addEventListener('click', setDockerClientVersion);

  // Update labels when device selection changes
  document.getElementById('targetDeviceSelect').addEventListener('change', function() {
    const selected = this.options[this.selectedIndex];
    const arch = selected && selected.dataset.arch ? selected.dataset.arch : '';
    updateReleaseLabelsForArch(arch);
  });

  loadDevices();
  loadReleases();
  loadLocalFrida();
});
