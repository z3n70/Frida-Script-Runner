// SSL Pinning Detection Frontend JavaScript

document.addEventListener('DOMContentLoaded', function() {
    const form = document.getElementById('sslpindetectForm');
    const analyzeBtn = document.getElementById('analyzeBtn');
    const progressBarContainer = document.getElementById('progressBarContainer');
    const progressBar = document.getElementById('progressBar');
    const statusMessage = document.getElementById('statusMessage');
    const resultsSection = document.getElementById('resultsSection');
    const packageSelect = document.getElementById('packageSelect');
    const packageSearch = document.getElementById('packageSearch');
    const refreshPackagesBtn = document.getElementById('refreshPackagesBtn');
    const uploadMode = document.getElementById('uploadMode');
    const packageMode = document.getElementById('packageMode');
    const modeUpload = document.getElementById('modeUpload');
    const modePackage = document.getElementById('modePackage');

    let allPackages = [];
    modeUpload.addEventListener('change', function() {
        if (this.checked) {
            uploadMode.style.display = 'block';
            packageMode.style.display = 'none';
            document.getElementById('apkFile').required = true;
            packageSelect.required = false;
        }
    });

    modePackage.addEventListener('change', function() {
        if (this.checked) {
            uploadMode.style.display = 'none';
            packageMode.style.display = 'block';
            document.getElementById('apkFile').required = false;
            packageSelect.required = true;
            loadPackages();
        }
    });

    if (modePackage.checked) {
        loadPackages();
    }

    refreshPackagesBtn.addEventListener('click', function() {
        loadPackages();
    });

    packageSearch.addEventListener('input', function() {
        filterPackages(this.value.trim().toLowerCase());
    });

    function filterPackages(searchTerm) {
        if (!allPackages || allPackages.length === 0) {
            return;
        }

        packageSelect.innerHTML = '';
        
        if (searchTerm === '') {
            allPackages.forEach(pkg => {
                const option = document.createElement('option');
                option.value = pkg;
                option.textContent = pkg;
                packageSelect.appendChild(option);
            });
        } else {
            const filtered = allPackages.filter(pkg => 
                pkg.toLowerCase().includes(searchTerm)
            );
            
            if (filtered.length === 0) {
                const option = document.createElement('option');
                option.value = '';
                option.textContent = 'No packages found';
                option.disabled = true;
                packageSelect.appendChild(option);
            } else {
                filtered.forEach(pkg => {
                    const option = document.createElement('option');
                    option.value = pkg;
                    option.textContent = pkg;
                    packageSelect.appendChild(option);
                });
            }
        }
    }

    async function loadPackages() {
        packageSelect.innerHTML = '<option value="">Loading packages...</option>';
        packageSelect.disabled = true;
        refreshPackagesBtn.disabled = true;
        packageSearch.disabled = true;
        packageSearch.value = '';

        try {
            const response = await fetch('/sslpindec/packages');
            const result = await response.json();

            if (result.success && result.packages && result.packages.length > 0) {
                allPackages = result.packages;
                
                packageSelect.innerHTML = '';
                allPackages.forEach(pkg => {
                    const option = document.createElement('option');
                    option.value = pkg;
                    option.textContent = pkg;
                    packageSelect.appendChild(option);
                });
                showStatus(`Loaded ${result.packages.length} packages`, 'success');
            } else {
                allPackages = [];
                packageSelect.innerHTML = '<option value="">No packages found</option>';
                showStatus(result.error || 'No packages found. Make sure your Android device is connected.', 'warning');
            }
        } catch (error) {
            allPackages = [];
            packageSelect.innerHTML = '<option value="">Error loading packages</option>';
            showStatus('Error loading packages: ' + error.message, 'danger');
        } finally {
            packageSelect.disabled = false;
            refreshPackagesBtn.disabled = false;
            packageSearch.disabled = false;
        }
    }

    form.addEventListener('submit', async function(e) {
        e.preventDefault();
        
        const formData = new FormData(form);
        const analysisMode = formData.get('analysisMode');
        const apkFile = document.getElementById('apkFile').files[0];
        const packageName = document.getElementById('packageSelect').value;
        
        if (analysisMode === 'upload') {
            if (!apkFile) {
                showStatus('Please select an APK file', 'danger');
                return;
            }
        } else if (analysisMode === 'package') {
            if (!packageName) {
                showStatus('Please select a package', 'danger');
                return;
            }
            formData.append('package_name', packageName);
        }

        analyzeBtn.disabled = true;
        analyzeBtn.innerHTML = '<span class="spinner-border spinner-border-sm me-2"></span>Analyzing...';
        progressBarContainer.classList.remove('d-none');
        progressBar.style.width = '0%';
        statusMessage.classList.add('d-none');
        resultsSection.style.display = 'none';

        let progress = 0;
        const progressInterval = setInterval(() => {
            progress += 10;
            if (progress <= 90) {
                progressBar.style.width = progress + '%';
            }
        }, 500);

        try {
            const response = await fetch('/sslpindec/analyze', {
                method: 'POST',
                body: formData
            });

            clearInterval(progressInterval);
            progressBar.style.width = '100%';

            const result = await response.json();

            if (result.success) {
                displayResults(result);
                const modeText = analysisMode === 'upload' ? 'APK upload' : `package ${packageName}`;
                showStatus(`Analysis completed successfully for ${modeText}!`, 'success');
            } else {
                showStatus('Analysis failed: ' + (result.error || 'Unknown error'), 'danger');
            }
        } catch (error) {
            clearInterval(progressInterval);
            showStatus('Error: ' + error.message, 'danger');
        } finally {
            analyzeBtn.disabled = false;
            analyzeBtn.innerHTML = '<i class="bi bi-search"></i> Analyze APK';
            setTimeout(() => {
                progressBarContainer.classList.add('d-none');
            }, 1000);
        }
    });

    function showStatus(message, type) {
        statusMessage.textContent = message;
        statusMessage.className = `alert alert-${type} mt-3`;
        statusMessage.classList.remove('d-none');
    }

    function displayResults(result) {
        document.getElementById('totalMatches').textContent = result.total_matches || 0;
        document.getElementById('patternTypes').textContent = Object.keys(result.pattern_counts || {}).length;
        document.getElementById('apkName').textContent = result.apk_path ? 
            result.apk_path.split('/').pop() : '-';

        const patternCountsDiv = document.getElementById('patternCounts');
        patternCountsDiv.innerHTML = '';
        
        if (result.pattern_counts && Object.keys(result.pattern_counts).length > 0) {
            for (const [pattern, count] of Object.entries(result.pattern_counts)) {
                const badge = document.createElement('span');
                badge.className = 'badge bg-primary me-2 mb-2';
                badge.style.fontSize = '0.9rem';
                badge.innerHTML = `${pattern} <span class="badge bg-light text-dark">${count}</span>`;
                patternCountsDiv.appendChild(badge);
            }
        } else {
            patternCountsDiv.innerHTML = '<p class="text-muted">No patterns detected</p>';
        }

        const matchesTableBody = document.getElementById('matchesTableBody');
        matchesTableBody.innerHTML = '';

        if (result.matches && result.matches.length > 0) {
            result.matches.forEach((match, index) => {
                const row = document.createElement('tr');
                
                const patternCell = document.createElement('td');
                patternCell.innerHTML = `<span class="badge bg-info">${match.pattern}</span>`;
                
                const fileCell = document.createElement('td');
                const fileName = match.file.split('/').pop();
                fileCell.innerHTML = `<code class="small">${fileName}</code>`;
                fileCell.title = match.file;
                
                const lineCell = document.createElement('td');
                lineCell.textContent = match.line;
                
                const codeCell = document.createElement('td');
                codeCell.innerHTML = `<code class="small text-truncate d-block" style="max-width: 300px;">${escapeHtml(match.code)}</code>`;
                
                const actionsCell = document.createElement('td');
                if (match.context) {
                    const viewBtn = document.createElement('button');
                    viewBtn.className = 'btn btn-sm btn-outline-primary';
                    viewBtn.innerHTML = '<i class="bi bi-eye"></i> View Context';
                    viewBtn.onclick = () => showCodeContext(match.context, match.file, match.line);
                    actionsCell.appendChild(viewBtn);
                }
                
                row.appendChild(patternCell);
                row.appendChild(fileCell);
                row.appendChild(lineCell);
                row.appendChild(codeCell);
                row.appendChild(actionsCell);
                
                matchesTableBody.appendChild(row);
            });
        } else {
            const row = document.createElement('tr');
            const cell = document.createElement('td');
            cell.colSpan = 5;
            cell.className = 'text-center text-muted';
            cell.textContent = 'No matches found';
            row.appendChild(cell);
            matchesTableBody.appendChild(row);
        }

        resultsSection.style.display = 'block';
        resultsSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }

    function showCodeContext(context, file, line) {
        const modal = new bootstrap.Modal(document.getElementById('codePreviewModal'));
        const content = document.getElementById('codePreviewContent');
        
        document.getElementById('codePreviewModalLabel').textContent = 
            `Code Context - ${file.split('/').pop()} (Line ${line})`;
        
        content.textContent = context;
        modal.show();
    }

    function escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
});

