// SSL Pinning Detection Frontend JavaScript

document.addEventListener('DOMContentLoaded', function() {
    const form = document.getElementById('sslpindetectForm');
    const analyzeBtn = document.getElementById('analyzeBtn');
    const progressBarContainer = document.getElementById('progressBarContainer');
    const progressBar = document.getElementById('progressBar');
    const statusMessage = document.getElementById('statusMessage');
    const resultsSection = document.getElementById('resultsSection');

    form.addEventListener('submit', async function(e) {
        e.preventDefault();
        
        const formData = new FormData(form);
        const apkFile = document.getElementById('apkFile').files[0];
        
        if (!apkFile) {
            showStatus('Please select an APK file', 'danger');
            return;
        }

        // Reset UI
        analyzeBtn.disabled = true;
        analyzeBtn.innerHTML = '<span class="spinner-border spinner-border-sm me-2"></span>Analyzing...';
        progressBarContainer.classList.remove('d-none');
        progressBar.style.width = '0%';
        statusMessage.classList.add('d-none');
        resultsSection.style.display = 'none';

        // Simulate progress
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
                showStatus('Analysis completed successfully!', 'success');
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
        // Update summary
        document.getElementById('totalMatches').textContent = result.total_matches || 0;
        document.getElementById('patternTypes').textContent = Object.keys(result.pattern_counts || {}).length;
        document.getElementById('apkName').textContent = result.apk_path ? 
            result.apk_path.split('/').pop() : '-';

        // Display pattern counts
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

        // Display detailed matches
        const matchesTableBody = document.getElementById('matchesTableBody');
        matchesTableBody.innerHTML = '';

        if (result.matches && result.matches.length > 0) {
            result.matches.forEach((match, index) => {
                const row = document.createElement('tr');
                
                // Pattern
                const patternCell = document.createElement('td');
                patternCell.innerHTML = `<span class="badge bg-info">${match.pattern}</span>`;
                
                // File
                const fileCell = document.createElement('td');
                const fileName = match.file.split('/').pop();
                fileCell.innerHTML = `<code class="small">${fileName}</code>`;
                fileCell.title = match.file;
                
                // Line
                const lineCell = document.createElement('td');
                lineCell.textContent = match.line;
                
                // Code preview
                const codeCell = document.createElement('td');
                codeCell.innerHTML = `<code class="small text-truncate d-block" style="max-width: 300px;">${escapeHtml(match.code)}</code>`;
                
                // Actions
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

        // Show results section
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

