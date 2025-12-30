// var socket = io.connect("http://" + document.domain + ":" + location.port);
var socket = io.connect(window.location.protocol + '//' + window.location.hostname + ':' + window.location.port);

var logOutput = document.getElementById("outputFrida");
var runButton = document.getElementById("runBtn");
var stopButton = document.getElementById("stopBtn");
var fixButton = document.getElementById("fixBtn");

runButton.disabled = false;
stopButton.disabled = true;
fixButton.style.display = "none";

socket.on('connected', function(data){
  console.log(data)
})
socket.on("output", function (data) {
  var outputList = document.getElementById("output-list");
  var listItem = document.createElement("pre");
  listItem.appendChild(document.createTextNode(`${data.data}`));
  outputList.appendChild(listItem);
});

socket.on("fsr_log", function (data) {
  var outputContainer = document.getElementById("outputContainer");
  outputContainer.innerHTML += `<span class="text-info">~</span> ${data.data} </br>`;
  outputContainer.scrollTop = outputContainer.scrollHeight;
});

// Send input to running Frida process
function sendFridaInput() {
  const inputEl = document.getElementById('fridaCommandInput');
  if (!inputEl) return;
  const value = inputEl.value.trim();
  if (value.length === 0) return;

  fetch('/send-frida-input', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ input: value })
  })
  .then(res => res.json())
  .then(data => {
    if (!data.success) {
      appendContent(`Failed to send to Frida: ${data.error || 'Unknown error'}`);
    }
  })
  .catch(err => {
    appendContent(`Failed to send to Frida: ${err.message}`);
  })
  .finally(() => {
    inputEl.value = '';
  });
}

// Clear FSR logs function
function clearFSRLogs() {
  var outputContainer = document.getElementById("outputContainer");
  outputContainer.innerHTML = "";
}

// Load packages function
function loadPackages() {
  const packageSelect = document.getElementById("packageSelect");
  const refreshButton = document.querySelector('button[onclick="loadPackages()"]');
  
  // Show loading state
  packageSelect.innerHTML = '<option disabled>Loading packages...</option>';
  refreshButton.disabled = true;
  refreshButton.innerHTML = '<i class="bi bi-hourglass-split"></i> Loading...';
  
  fetch('/get-packages')
    .then(response => response.json())
    .then(data => {
      if (data.success) {
        // Clear existing options
        packageSelect.innerHTML = '';
        
        if (data.packages && data.packages.length > 0) {
          // Add packages
          data.packages.forEach(package => {
            const option = document.createElement('option');
            // Package format: "PID - com.example.app"
            // Extract the package identifier (part after " - ")
            const packageParts = package.split(' - ');
            if (packageParts.length >= 2) {
              option.value = packageParts[1]; // Get package identifier
            } else {
              option.value = package; // Fallback to full string
            }
            option.textContent = package;
            packageSelect.appendChild(option);
          });
          
          // Show success message
          appendContent(`Successfully loaded ${data.packages.length} packages`);
        } else {
          packageSelect.innerHTML = '<option disabled>No packages found</option>';
          appendContent('No packages found on device');
        }
      } else {
        packageSelect.innerHTML = '<option disabled>Error loading packages</option>';
        appendContent(`Error: ${data.error}`);
      }
    })
    .catch(error => {
      console.error('Error:', error);
      packageSelect.innerHTML = '<option disabled>Error loading packages</option>';
      appendContent(`Error loading packages: ${error.message}`);
    })
    .finally(() => {
      // Reset button state
      refreshButton.disabled = false;
      refreshButton.innerHTML = '<i class="bi bi-arrow-clockwise"></i> Refresh Packages';
    });
}

// Load packages with retry mechanism
function loadPackagesWithRetry(maxRetries = 3, delay = 2000) {
  let retryCount = 0;
  
  function attemptLoad() {
    const packageSelect = document.getElementById("packageSelect");
    
    fetch('/get-packages')
      .then(response => response.json())
      .then(data => {
        if (data.success && data.packages && data.packages.length > 0) {
          // Success - load packages
          packageSelect.innerHTML = '';
          data.packages.forEach(package => {
            const option = document.createElement('option');
            // Package format: "PID - com.example.app"
            // Extract the package identifier (part after " - ")
            const packageParts = package.split(' - ');
            if (packageParts.length >= 2) {
              option.value = packageParts[1]; // Get package identifier
            } else {
              option.value = package; // Fallback to full string
            }
            option.textContent = package;
            packageSelect.appendChild(option);
          });
          appendContent(`Successfully loaded ${data.packages.length} packages`);
        } else if (retryCount < maxRetries) {
          // Retry if Frida server might still be starting
          retryCount++;
          appendContent(`Attempt ${retryCount}/${maxRetries}: Frida server may still be starting, retrying in ${delay/1000}s...`);
          setTimeout(attemptLoad, delay);
        } else {
          // Max retries reached
          packageSelect.innerHTML = '<option disabled>No packages found after retries</option>';
          appendContent(`Failed to load packages after ${maxRetries} attempts. Please check Frida server status.`);
        }
      })
      .catch(error => {
        if (retryCount < maxRetries) {
          retryCount++;
          appendContent(`Attempt ${retryCount}/${maxRetries}: Error loading packages, retrying in ${delay/1000}s...`);
          setTimeout(attemptLoad, delay);
        } else {
          packageSelect.innerHTML = '<option disabled>Error loading packages</option>';
          appendContent(`Failed to load packages after ${maxRetries} attempts: ${error.message}`);
        }
      });
  }
  
  attemptLoad();
}

// Restart Frida server function
function restartFridaServer() {
  // Get the first connected device
  const fridaStatusCards = document.querySelectorAll('.card-body');
  let deviceId = null;
  
  for (const card of fridaStatusCards) {
    const button = card.querySelector('button');
    if (button && button.getAttribute('data-device-id')) {
      deviceId = button.getAttribute('data-device-id');
      break;
    }
  }
  
  if (!deviceId) {
    appendContent('No device found to restart Frida server');
    return;
  }
  
  const restartButton = document.querySelector('button[onclick="restartFridaServer()"]');
  restartButton.disabled = true;
  restartButton.innerHTML = '<i class="bi bi-hourglass-split"></i> Restarting...';
  
  fetch('/restart-frida-server', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      device_id: deviceId
    })
  })
  .then(response => response.json())
  .then(data => {
    if (data.success) {
      appendContent(`Frida server restarted successfully: ${data.message}`);
      
      // Update status
      const statusCard = document.querySelector(`[data-device-id="${deviceId}"]`);
      if (statusCard) {
        const cardBody = statusCard.closest('.card-body');
        const statusBadges = cardBody.querySelectorAll('.badge');
        statusBadges[1].className = 'badge bg-success';
        statusBadges[1].innerHTML = '<i class="bi bi-play-circle"></i> Running';
        
        const button = cardBody.querySelector('button');
        if (button) {
          button.className = 'btn btn-sm btn-danger stop-frida-server';
          button.innerHTML = '<i class="bi bi-stop-fill"></i> Stop';
          button.setAttribute('data-device-id', deviceId);
        }
      }
      
      // Auto-refresh packages after restart
      setTimeout(() => {
        loadPackagesWithRetry();
      }, 3000);
    } else {
      throw new Error(data.error || 'Failed to restart Frida server');
    }
  })
  .catch(error => {
    console.error('Error:', error);
    appendContent(`Error restarting Frida server: ${error.message}`);
  })
  .finally(() => {
    restartButton.disabled = false;
    restartButton.innerHTML = '<i class="bi bi-arrow-clockwise"></i> Restart Frida Server';
  });
}

function toggleCustomScript() {
  var customScriptCheckbox = document.getElementById("customScriptCheckbox");
  var useCustomScriptInput = document.getElementById("useCustomScript");

  if (customScriptCheckbox.checked) {
    customScriptCheckbox.value = "1";
  } else {
    customScriptCheckbox.value = "0";
  }
}

function filterOptions() {
  var input, filter, select, option, i, txtValue;
  input = document.getElementById("searchInput");
  filter = input.value.toUpperCase();
  select = document.getElementById("packageSelect");
  options = select.getElementsByTagName("option");

  for (i = 0; i < options.length; i++) {
    txtValue = options[i].textContent || options[i].innerText;
    if (txtValue.toUpperCase().indexOf(filter) > -1) {
      options[i].style.display = "";
    } else {
      options[i].style.display = "none";
    }
  }
}

var bypassScript = document.getElementById("selectedScript");
bypassScript.addEventListener("change", function () {
  updateTextArea();
});

function updateTextArea() {
  var select = document.getElementById("selectedScript");
  var scriptContentTextArea = document.getElementById("scriptContent");
  var selectedScript = select.options[select.selectedIndex].value;

  fetch(`/get-script-content?script=${selectedScript}`)
    .then((response) => {
      if (!response.ok) {
        throw new Error("Script content not found");
      }
      return response.text();
    })
    .then((data) => (scriptContentTextArea.value = data))
    .catch((error) => {
      scriptContentTextArea.value = `Error loading script content: ${error.message}`;
      console.error(error);
    });
}

stopButton.addEventListener("click", function (event) {
  event.preventDefault();
  stopButton.disabled = true;
  runButton.disabled = false;
  fixButton.style.display = "none";
  // Clear logs without removing input controls
  var outputFridaEl = document.getElementById("outputFrida");
  var outputListEl = document.getElementById("output-list");
  if (outputFridaEl) outputFridaEl.innerHTML = "";
  if (outputListEl) outputListEl.innerHTML = "";
  // Clear the inline pre without duplicating IDs
  logOutput.innerHTML = '';
  fetch("/stop-frida")
    .then((response) => response.text())
    .then((data) => {
      document.getElementById(
        "outputContainer"
      ).innerHTML += `</br><pre class="wraptext"> ${data}</pre>`;
    })
    .catch((error) => console.error(error));
});

fixButton.addEventListener("click", function (event) {
  event.preventDefault();
  fixButton.disabled = true;
  fixButton.innerHTML = '<i class="bi bi-hourglass-split"></i> Fixing...';
  
  fetch("/fix-script", {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    }
  })
  .then(response => response.json())
  .then(data => {
    if (data.success) {
      // Update the script content textarea with the fixed script
      if (data.fixed_script) {
        const scriptContentTextarea = document.getElementById("scriptContent");
        if (scriptContentTextarea) {
          scriptContentTextarea.value = data.fixed_script;
          console.log("Updated script content with fixed script");
          // Also enable the custom script checkbox since we now have custom content
          const useCustomScript = document.getElementById("customScriptCheckbox");
          if (useCustomScript) {
            useCustomScript.checked = true;
            console.log("Enabled custom script checkbox");
          } else {
            console.log("Custom script checkbox not found (ID: customScriptCheckbox)");
          }
        } else {
          console.log("Script content textarea not found (ID: scriptContent)");
        }
      } else {
        console.log("No fixed_script in response");
      }
      
      document.getElementById("outputContainer").innerHTML += 
        `</br><pre class="wraptext text-success"> ✅ ${data.message}</pre>`;
    } else {
      document.getElementById("outputContainer").innerHTML += 
        `</br><pre class="wraptext text-danger"> ❌ Fix failed: ${data.error}</pre>`;
    }
  })
  .catch(error => {
    console.error(error);
    document.getElementById("outputContainer").innerHTML += 
      `</br><pre class="wraptext text-danger"> ❌ Fix request failed: ${error.message}</pre>`;
  })
  .finally(() => {
    fixButton.disabled = false;
    fixButton.innerHTML = '<i class="bi bi-tools"></i> Fix Script';
  });
});
// function stopFrida() {
//     preventDefault();
//     stopButton.disabled = true;
//     runButton.disabled = false;
//     logOutput.innerHTML = '<ul id="output-list"></ul>';
//     fetch('/stop-frida')
//         .then(response => response.text())
//         .then(data => {
//             document.getElementById("outputContainer").innerHTML += '<div class="alert alert-info mt-4"><h2>Result:</h2><p>' + data + '</p></div>';
//         })
//         .catch(error => console.error(error));
// }

runButton.addEventListener("click", function (event) {
  event.preventDefault();
  runButton.disabled = true;
  stopButton.disabled = false;
  fixButton.style.display = "inline-block";
  // Reset logs without removing input controls
  var outputFridaEl = document.getElementById("outputFrida");
  var outputListEl = document.getElementById("output-list");
  if (outputFridaEl) outputFridaEl.innerHTML = "";
  if (outputListEl) outputListEl.innerHTML = "";
  runFrida();
});

function runFrida() {
  const form = document.querySelector("form");
  const outputContainer = document.getElementById("outputContainer");
  logOutput.innerHTML = '</br><pre class="wraptext"></pre>';

  const formData = new FormData(form);
  const packageValue = formData.get('package');
  
  // Debug: Show what package is selected
  console.log('Selected package:', packageValue);
  appendContent(`Selected package: ${packageValue}`);
  
  if (packageValue.includes('----') || !packageValue || packageValue === 'undefined'){
    alert('Please select a valid package');
    runButton.disabled = false;
    stopButton.disabled = true;
    fixButton.style.display = "none";
    return
  }
  fetch("/run-frida", {
    method: "POST",
    body: formData,
  })
    .then((response) => response.json())
    .then((data) => {
      const content = data.result || data.error || "Unknown error occurred";
      appendContent(content);
    })
    .catch((error) => {
      console.error(error);
      runButton.disabled = false;
      stopButton.disabled = true;
      fixButton.style.display = "none";
      appendContent(
        `</br><span class="text-success">~</span><pre class="wraptext">Error: ${error.message}</pre>`
      );
    });
}
function appendContent(content) {
  const outputContainer = document.getElementById("outputContainer");
  outputContainer.innerHTML += `<span class="text-success">~</span> ${content} </br>`;
  outputContainer.scrollTop = outputContainer.scrollHeight;
}
// modal(); pada codeshare search
document.addEventListener("DOMContentLoaded", function () {
  const mainInput = document.getElementById("codeshareSearchInput");
  const modalInput = document.getElementById("modalSearchInput");
  const modalResultsDiv = document.getElementById("modalResults");
  const modalEl = document.getElementById("codeshareResultsModal");
  const bsModal = new bootstrap.Modal(modalEl);

  function performSearch(keyword) {
    if (!keyword) {
      modalResultsDiv.innerHTML = "<p>No search keyword.</p>";
      return;
    }

    fetch(`/codeshare/search?keyword=${encodeURIComponent(keyword)}`)
      .then(res => res.json())
      .then(data => {
        modalResultsDiv.innerHTML = "";

        if (data.length === 0) {
          modalResultsDiv.innerHTML = "<p>No results found.</p>";
          return;
        }

        const list = document.createElement("ul");
        list.className = "list-group";

        data.forEach(item => {
          const li = document.createElement("li");
          li.className = "list-group-item";
          li.style.cursor = "pointer";
          li.innerHTML = `<h5>${item.title}</h5><a href="${item.source}" target="_blank" class="text-decoration-none d-block small text-muted">${item.source}</a><p>${item.preview}</p>`;
          li.onclick = () => {document.getElementById("scriptContent").value = item.script;
            bsModal.hide();
            setTimeout(() => {
              document.querySelectorAll(".modal-backdrop").forEach(el => el.remove());
              document.body.classList.remove("modal-open");
            }, 300); 
          };
          list.appendChild(li);
        });
        modalResultsDiv.appendChild(list);
      });
  }

  mainInput.addEventListener("input", function () {
    const keyword = mainInput.value.trim();
    if (keyword.length === 0) return;

    bsModal.show();
    modalInput.value = keyword;
    performSearch(keyword);
  });

  modalInput.addEventListener("input", function () {
    const keyword = modalInput.value.trim();
    performSearch(keyword);
  });

  // Frida Server Management
  // Add event listeners for Frida server buttons
  document.addEventListener('click', function(e) {
    if (e.target.classList.contains('start-frida-server') || e.target.closest('.start-frida-server')) {
      const button = e.target.classList.contains('start-frida-server') ? e.target : e.target.closest('.start-frida-server');
      const deviceId = button.getAttribute('data-device-id');
      startFridaServer(deviceId, button);
    }
    
    if (e.target.classList.contains('stop-frida-server') || e.target.closest('.stop-frida-server')) {
      const button = e.target.classList.contains('stop-frida-server') ? e.target : e.target.closest('.stop-frida-server');
      const deviceId = button.getAttribute('data-device-id');
      stopFridaServer(deviceId, button);
    }
  });

  // Function to start Frida server
  function startFridaServer(deviceId, button) {
    button.disabled = true;
    button.innerHTML = '<i class="bi bi-hourglass-split"></i> Starting...';
    
    // Check if force download is enabled
    const forceDownloadCheckbox = document.getElementById(`force-download-${deviceId}`);
    const forceDownload = forceDownloadCheckbox ? forceDownloadCheckbox.checked : false;
    
    fetch('/start-frida-server', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        device_id: deviceId,
        force_download: forceDownload
      })
    })
    .then(response => response.json())
    .then(data => {
      if (data.success) {
        // Update the button to show stop option
        const cardBody = button.closest('.card-body');
        const statusBadges = cardBody.querySelectorAll('.badge');
        statusBadges[1].className = 'badge bg-success';
        statusBadges[1].innerHTML = '<i class="bi bi-play-circle"></i> Running';
        
        // Update installed status if we have server name
        if (data.frida_server_name) {
          statusBadges[0].innerHTML = `<i class="bi bi-check-circle"></i> ${data.frida_server_name}`;
        }
        
        button.className = 'btn btn-sm btn-danger stop-frida-server';
        button.innerHTML = '<i class="bi bi-stop-fill"></i> Stop';
        button.setAttribute('data-device-id', deviceId);
        
        // Show success message
        appendContent(`Frida server started successfully: ${data.message}`);
        
        // Auto-refresh packages after a short delay with retry mechanism
        setTimeout(() => {
          loadPackagesWithRetry();
        }, 2000);
      } else {
        throw new Error(data.error || 'Failed to start Frida server');
      }
    })
    .catch(error => {
      console.error('Error:', error);
      button.disabled = false;
      button.innerHTML = '<i class="bi bi-play-fill"></i> Start';
      appendContent(`Error starting Frida server: ${error.message}`);
    });
  }

  // Function to stop Frida server
  function stopFridaServer(deviceId, button) {
    button.disabled = true;
    button.innerHTML = '<i class="bi bi-hourglass-split"></i> Stopping...';
    
    fetch('/stop-frida-server', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        device_id: deviceId
      })
    })
    .then(response => response.json())
    .then(data => {
      if (data.success) {
        // Update the button to show start option
        const cardBody = button.closest('.card-body');
        const statusBadges = cardBody.querySelectorAll('.badge');
        
        // Update running status badge to show "Stopped"
        statusBadges[1].className = 'badge bg-danger';
        statusBadges[1].innerHTML = '<i class="bi bi-stop-circle"></i> Stopped';
        
        // Update button to show "Start" option
        button.className = 'btn btn-sm btn-success start-frida-server';
        button.innerHTML = '<i class="bi bi-play-fill"></i> Start';
        button.setAttribute('data-device-id', deviceId);
        
        // Show success message
        appendContent(`Frida server stopped successfully: ${data.message}`);
        
        // Add visual feedback
        console.log('Status updated: Frida server stopped');
      } else {
        throw new Error(data.error || 'Failed to stop Frida server');
      }
    })
    .catch(error => {
      console.error('Error:', error);
      button.disabled = false;
      button.innerHTML = '<i class="bi bi-stop-fill"></i> Stop';
      appendContent(`Error stopping Frida server: ${error.message}`);
    });
  }

  // Refresh Frida server status periodically
  function refreshFridaStatus() {
    fetch('/frida-server-status')
      .then(response => response.json())
      .then(data => {
        if (data.error) {
          console.error('Error refreshing Frida status:', data.error);
          return;
        }
        
        // Update status for each device
        Object.keys(data).forEach(deviceId => {
          const status = data[deviceId];
          const statusCard = document.querySelector(`[data-device-id="${deviceId}"]`);
          if (statusCard) {
            const cardBody = statusCard.querySelector('.card-body');
            const statusBadges = cardBody.querySelectorAll('.badge');
            
            // Update installed status
            statusBadges[0].className = status.installed ? 'badge bg-success me-2' : 'badge bg-warning me-2';
            statusBadges[0].innerHTML = status.installed ? 
              `<i class="bi bi-check-circle"></i> ${status.frida_server_name || 'Installed'}` : 
              '<i class="bi bi-exclamation-triangle"></i> Not Installed';
            
            // Update running status
            statusBadges[1].className = status.running ? 'badge bg-success' : 'badge bg-danger';
            statusBadges[1].innerHTML = status.running ? 
              '<i class="bi bi-play-circle"></i> Running' : 
              '<i class="bi bi-stop-circle"></i> Stopped';
            
            // Update button
            const button = cardBody.querySelector('button');
            if (button) {
              if (status.running) {
                button.className = 'btn btn-sm btn-danger stop-frida-server';
                button.innerHTML = '<i class="bi bi-stop-fill"></i> Stop';
              } else {
                button.className = 'btn btn-sm btn-success start-frida-server';
                button.innerHTML = '<i class="bi bi-play-fill"></i> Start';
              }
              button.disabled = false;
            }
            
            // Debug log
            console.log(`Status refresh for ${deviceId}: Running=${status.running}, Installed=${status.installed}`);
          } else {
            console.warn(`Status card not found for device: ${deviceId}`);
          }
        });
      })
      .catch(error => {
        console.error('Error refreshing Frida status:', error);
      });
  }

  // Refresh status every 10 seconds
  setInterval(refreshFridaStatus, 10000);
  
  // Manual refresh function - can be called from console or button
  window.manualRefreshStatus = function() {
    console.log('Manual status refresh triggered');
    
    // Use force refresh endpoint for more reliable status
    fetch('/force-refresh-status', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      }
    })
    .then(response => response.json())
    .then(data => {
      if (data.error) {
        console.error('Error refreshing Frida status:', data.error);
        return;
      }
      
      // Update status for each device
      Object.keys(data).forEach(deviceId => {
        const status = data[deviceId];
        const statusCard = document.querySelector(`[data-device-id="${deviceId}"]`);
        if (statusCard) {
          const cardBody = statusCard.querySelector('.card-body');
          const statusBadges = cardBody.querySelectorAll('.badge');
          
          // Update installed status
          statusBadges[0].className = status.installed ? 'badge bg-success me-2' : 'badge bg-warning me-2';
          statusBadges[0].innerHTML = status.installed ? 
            `<i class="bi bi-check-circle"></i> ${status.frida_server_name || 'Installed'}` : 
            '<i class="bi bi-exclamation-triangle"></i> Not Installed';
          
          // Update running status
          statusBadges[1].className = status.running ? 'badge bg-success' : 'badge bg-danger';
          statusBadges[1].innerHTML = status.running ? 
            '<i class="bi bi-play-circle"></i> Running' : 
            '<i class="bi bi-stop-circle"></i> Stopped';
          
          // Update button
          const button = cardBody.querySelector('button');
          if (button) {
            if (status.running) {
              button.className = 'btn btn-sm btn-danger stop-frida-server';
              button.innerHTML = '<i class="bi bi-stop-fill"></i> Stop';
            } else {
              button.className = 'btn btn-sm btn-success start-frida-server';
              button.innerHTML = '<i class="bi bi-play-fill"></i> Start';
            }
            button.disabled = false;
          }
          
          console.log(`Manual refresh for ${deviceId}: Running=${status.running}, Installed=${status.installed}`);
        } else {
          console.warn(`Status card not found for device: ${deviceId}`);
        }
      });
      
      appendContent('Status refreshed manually');
    })
    .catch(error => {
      console.error('Error refreshing Frida status:', error);
      appendContent(`Error refreshing status: ${error.message}`);
    });
  };
  
  // Initial status refresh
  refreshFridaStatus();
});

// Device auto-refresh management (similar to adb-gui)
let deviceRefreshInterval = null;
const DEVICE_REFRESH_INTERVAL = 2000; // 2 seconds like adb-gui

function loadConnectedDevices(silent = false) {
  const devicesContainer = document.getElementById('devicesContainer');
  if (!devicesContainer) return;
  
  if (!silent) {
    devicesContainer.innerHTML = '<div class="text-muted small">Loading devices...</div>';
  }
  
  // Use check-device-status for comprehensive device detection (Android + iOS)
  fetch('/check-device-status')
    .then(res => res.json())
    .then(data => {
      if (data.error) {
        devicesContainer.innerHTML = '<p class="text-danger mb-0">Failed to load devices</p>';
        if (!silent) {
          console.error('Failed to load devices:', data.error);
        }
        return;
      }
      
      if (!data.connected || data.device_count === 0) {
        devicesContainer.innerHTML = '<p class="text-danger mb-0">No device connected</p><small class="text-muted">Make sure your device is connected via USB and USB debugging is enabled.</small>';
        return;
      }
      
      let html = '';
      
      data.devices.forEach(device => {
        if (device.type === 'Android') {
          const deviceName = device.model || 'Android Device';
          html += `<p class="mb-1"><i class="bi bi-android text-success"></i> <strong>${deviceName}</strong></p>`;
          html += `<p class="mb-1 small text-muted">Serial: ${device.serial_number || device.device_id || 'N/A'}</p>`;
          if (device.android_version && device.android_version !== 'N/A') {
            html += `<p class="mb-1 small text-muted">Android: ${device.android_version}</p>`;
          }
          html += `<span class="badge bg-success"><i class="bi bi-check-circle"></i> Connected</span>`;
          html += `</div>`;
        } else if (device.type === 'iOS') {
          const deviceName = device.model || 'iOS Device';
          html += `<p class="mb-1"><i class="bi bi-apple text-dark"></i> <strong>${deviceName}</strong></p>`;
          html += `<p class="mb-1 small text-muted">UDID: ${device.udid || 'N/A'}</p>`;
          html += `<span class="badge bg-success"><i class="bi bi-check-circle"></i> Connected</span>`;
          html += `</div>`;
        }
      });
      
      devicesContainer.innerHTML = html;
    })
    .catch(err => {
      // Fallback to adb-gui/devices endpoint for Android only
      fetch('/adb-gui/devices')
        .then(res => res.json())
        .then(data => {
          if (!data.success || data.devices.length === 0) {
            devicesContainer.innerHTML = '<p class="text-danger mb-0">No device connected</p><small class="text-muted">Make sure your device is connected via USB and USB debugging is enabled.</small>';
            return;
          }
          
          const connectedDevices = data.devices.filter(d => d.state === 'device');
          let html = '';
          
          if (connectedDevices.length > 0) {
            connectedDevices.forEach(device => {
              const deviceName = device.product || device.model || device.serial || 'Device';
              html += `<p class="mb-1"><i class="bi bi-android text-success"></i> <strong>${deviceName}</strong></p>`;
              html += `<p class="mb-1 small text-muted">Serial: ${device.serial}</p>`;
              html += `<span class="badge bg-success"><i class="bi bi-check-circle"></i> Connected</span>`;
              html += `</div>`;
            });
          } else {
            data.devices.forEach(device => {
              const deviceName = device.product || device.model || device.serial || 'Device';
              let stateBadge = '';
              let stateText = '';
              
              if (device.state === 'offline') {
                stateBadge = 'bg-warning';
                stateText = 'Offline';
              } else if (device.state === 'unauthorized') {
                stateBadge = 'bg-danger';
                stateText = 'Unauthorized';
              } else {
                stateBadge = 'bg-secondary';
                stateText = device.state;
              }
              
              html += `<p class="mb-1"><i class="bi bi-android text-muted"></i> <strong>${deviceName}</strong></p>`;
              html += `<p class="mb-1 small text-muted">Serial: ${device.serial}</p>`;
              html += `<span class="badge ${stateBadge}"><i class="bi bi-exclamation-triangle"></i> ${stateText}</span>`;
              html += `</div>`;
            });
          }
          
          devicesContainer.innerHTML = html;
        })
        .catch(err2 => {
          devicesContainer.innerHTML = '<p class="text-danger mb-0">Error loading devices</p>';
          if (!silent) {
            console.error('Error loading devices:', err2);
          }
        });
    });
}

function startDeviceAutoRefresh() {
  stopDeviceAutoRefresh();
  
  deviceRefreshInterval = setInterval(() => {
    loadConnectedDevices(true); // Silent refresh
  }, DEVICE_REFRESH_INTERVAL);
}

function stopDeviceAutoRefresh() {
  if (deviceRefreshInterval) {
    clearInterval(deviceRefreshInterval);
    deviceRefreshInterval = null;
  }
}

// Initialize device auto-refresh when DOM is ready
document.addEventListener('DOMContentLoaded', function() {
  const devicesContainer = document.getElementById('devicesContainer');
  if (devicesContainer) {
    // Initial load
    loadConnectedDevices();
    // Start auto-refresh every 2 seconds (like adb-gui)
    startDeviceAutoRefresh();
  }
});

// Stop auto-refresh when page is hidden, resume when visible
document.addEventListener('visibilitychange', function() {
  if (document.hidden) {
    stopDeviceAutoRefresh();
  } else {
    const devicesContainer = document.getElementById('devicesContainer');
    if (devicesContainer) {
      startDeviceAutoRefresh();
    }
  }
});

// Hook up interactive Frida input controls when DOM is ready
document.addEventListener('DOMContentLoaded', function() {
  const sendBtn = document.getElementById('sendFridaInputBtn');
  const inputEl = document.getElementById('fridaCommandInput');
  if (sendBtn) {
    sendBtn.addEventListener('click', function() {
      sendFridaInput();
    });
  }
  if (inputEl) {
    inputEl.addEventListener('keydown', function(e) {
      if (e.key === 'Enter') {
        e.preventDefault();
        sendFridaInput();
      }
    });
  }
});

// Toggle Auto Generate Script Input
function toggleAutoGenerateInput() {
  const selectedScript = document.getElementById('selectedScript');
  const autoGenerateDiv = document.getElementById('autoGenerateDiv');
  
  if (selectedScript.value === 'auto_generate') {
    autoGenerateDiv.style.display = 'block';
  } else {
    autoGenerateDiv.style.display = 'none';
  }
}

// Generate Frida Script using AI
function generateFridaScript() {
  const promptText = document.getElementById('autoGeneratePrompt').value.trim();
  const scriptContentArea = document.getElementById('scriptContent');
  const generateButton = document.querySelector('button[onclick="generateFridaScript()"]');
  
  if (!promptText) {
    alert('Please enter a description of what you want to hook or bypass.');
    return;
  }
  
  // Show loading state
  generateButton.disabled = true;
  generateButton.innerHTML = '<i class="bi bi-hourglass-split"></i> Generating...';
  scriptContentArea.value = 'Generating Frida script, please wait...';
  
  // Send request to backend for script generation
  fetch('/generate-frida-script', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      prompt: promptText
    })
  })
  .then(response => response.json())
  .then(data => {
    if (data.success) {
      scriptContentArea.value = data.script;
      appendContent('✅ Frida script generated successfully');
    } else {
      scriptContentArea.value = '// Error generating script\n// ' + (data.error || 'Unknown error occurred');
      appendContent('❌ Error generating script: ' + (data.error || 'Unknown error'));
    }
  })
  .catch(error => {
    console.error('Error generating script:', error);
    scriptContentArea.value = '// Error generating script\n// Network error or server unavailable';
    appendContent('❌ Network error while generating script');
  })
  .finally(() => {
    // Reset button state
    generateButton.disabled = false;
    generateButton.innerHTML = '<i class="bi bi-cpu"></i> Generate Script';
  });
}
