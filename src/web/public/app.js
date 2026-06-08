// src/web/public/app.js

// ── State ─────────────────────────────────────────────────────────────────

let allFindings = [];        // full unfiltered result from the API
let filteredFindings = [];   // what's currently shown in the table
let activeFilters = {
  severity: new Set(),       // empty = show all
  search: '',
};
let sortState = { col: 'severity', dir: 'desc' };
let expandedRow = null;      // index of currently expanded row

// Severity sort order (higher = worse)
const SEVERITY_ORDER = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };
const SEVERITY_ICONS = {
  critical: '✖', high: '●', medium: '▲', low: '◆', info: '·'
};

// ── DOM references ────────────────────────────────────────────────────────

const uploadArea    = document.getElementById('upload-area');
const fileInput     = document.getElementById('file-input');
const selectedFile  = document.getElementById('selected-file');
const selectedName  = document.getElementById('selected-name');
const btnScan       = document.getElementById('btn-scan');
const loadingEl     = document.getElementById('loading');
const errorBox      = document.getElementById('error-box');
const errorMsg      = document.getElementById('error-msg');
const summaryBar    = document.getElementById('summary-bar');
const findingsSection = document.getElementById('findings-section');
const findingsBody  = document.getElementById('findings-body');
const findingsCount = document.getElementById('findings-count');
const searchBox     = document.getElementById('search-box');
const noResults     = document.getElementById('no-results');

// ── File upload handling ──────────────────────────────────────────────────

uploadArea.addEventListener('click', () => fileInput.click());

uploadArea.addEventListener('dragover', (e) => {
  e.preventDefault();
  uploadArea.classList.add('dragover');
});

uploadArea.addEventListener('dragleave', () => {
  uploadArea.classList.remove('dragover');
});

uploadArea.addEventListener('drop', (e) => {
  e.preventDefault();
  uploadArea.classList.remove('dragover');
  const file = e.dataTransfer.files[0];
  if (file) setSelectedFile(file);
});

fileInput.addEventListener('change', () => {
  if (fileInput.files[0]) setSelectedFile(fileInput.files[0]);
});

function setSelectedFile(file) {
  fileInput._selectedFile = file;
  selectedName.textContent = `${file.name} (${formatBytes(file.size)})`;
  selectedFile.classList.add('visible');
  btnScan.disabled = false;
}

function formatBytes(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

// ── Scan submission ───────────────────────────────────────────────────────

btnScan.addEventListener('click', async () => {
  const file = fileInput._selectedFile || fileInput.files[0];
  if (!file) return;

  // Build form data
  const formData = new FormData();
  formData.append('file', file);

  const severity = document.getElementById('filter-severity').value;
  const category = document.getElementById('filter-category').value;
  const includeAll = document.getElementById('filter-include-all').checked;

  if (severity) formData.append('severity', severity);
  if (category) formData.append('category', category);
  if (includeAll) formData.append('includeAll', 'true');

  // Show loading state
  setLoading(true);
  hideError();
  clearResults();

  try {
    const response = await fetch('/api/scan', {
      method: 'POST',
      body: formData,
    });

    const data = await response.json();

    if (!response.ok) {
      throw new Error(data.error || `Server error: ${response.status}`);
    }

    renderResults(data);

  } catch (err) {
    showError(err.message);
  } finally {
    setLoading(false);
  }
});

// ── Render results ────────────────────────────────────────────────────────

function renderResults(data) {
  allFindings = data.findings;
  filteredFindings = [...allFindings];

  // Render summary bar
  renderSummaryBar(data.summary, data.meta);

  // Render table
  applyFiltersAndRender();

  findingsSection.classList.add('visible');
}

function renderSummaryBar(summary, meta) {
  summaryBar.innerHTML = '';
  summaryBar.classList.add('visible');

  const severities = ['critical', 'high', 'medium', 'low', 'info'];
  for (const sev of severities) {
    const count = summary.bySeverity[sev];
    if (count === 0) continue;

    const chip = document.createElement('div');
    chip.className = `summary-chip ${sev} active`;
    chip.dataset.severity = sev;
    chip.innerHTML = `${SEVERITY_ICONS[sev]} ${sev} <strong>${count}</strong>`;
    chip.addEventListener('click', () => toggleSeverityFilter(sev, chip));
    summaryBar.appendChild(chip);
  }

  // Meta info on the right
  const metaEl = document.createElement('div');
  metaEl.className = 'summary-meta';
  metaEl.textContent = `${meta.filesScanned} files scanned in ${meta.durationMs}ms`;
  summaryBar.appendChild(metaEl);
}

function toggleSeverityFilter(severity, chip) {
  if (activeFilters.severity.has(severity)) {
    activeFilters.severity.delete(severity);
    chip.classList.remove('inactive');
    chip.classList.add('active');
  } else {
    activeFilters.severity.add(severity);
    chip.classList.remove('active');
    chip.classList.add('inactive');
  }
  applyFiltersAndRender();
}

function applyFiltersAndRender() {
  // Apply severity filter (activeFilters.severity = set of HIDDEN severities)
  filteredFindings = allFindings.filter(f => {
    if (activeFilters.severity.has(f.severity)) return false;
    if (activeFilters.search) {
      const q = activeFilters.search.toLowerCase();
      return (
        f.ruleName.toLowerCase().includes(q) ||
        f.filePath.toLowerCase().includes(q) ||
        f.ruleId.toLowerCase().includes(q) ||
        f.message.toLowerCase().includes(q)
      );
    }
    return true;
  });

  // Apply sort
  filteredFindings.sort((a, b) => {
    const dir = sortState.dir === 'asc' ? 1 : -1;
    if (sortState.col === 'severity') {
      return dir * (SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);
    }
    if (sortState.col === 'file') {
      return dir * a.filePath.localeCompare(b.filePath);
    }
    if (sortState.col === 'rule') {
      return dir * a.ruleName.localeCompare(b.ruleName);
    }
    return 0;
  });

  renderTable();
  findingsCount.textContent = `${filteredFindings.length} finding${filteredFindings.length !== 1 ? 's' : ''}`;
}

function renderTable() {
  findingsBody.innerHTML = '';
  expandedRow = null;

  if (filteredFindings.length === 0) {
    noResults.style.display = 'block';
    return;
  }
  noResults.style.display = 'none';

  filteredFindings.forEach((finding, index) => {
    const row = document.createElement('tr');
    row.innerHTML = `
      <td><span class="badge ${finding.severity}">${SEVERITY_ICONS[finding.severity]} ${finding.severity}</span></td>
      <td>${escapeHtml(finding.ruleName)}</td>
      <td>
        <span class="file-path">
          ${escapeHtml(finding.filePath)}<span class="line-num">:${finding.line}</span>
        </span>
      </td>
      <td><span class="badge" style="background:none;border:1px solid var(--border)">${finding.category}</span></td>
      <td><span class="confidence ${finding.confidence}">${finding.confidence}</span></td>
    `;
    row.addEventListener('click', () => toggleExpand(index));
    findingsBody.appendChild(row);
  });
}

function toggleExpand(index) {
  // If clicking the already-open row, close it
  if (expandedRow === index) {
    closeExpanded();
    return;
  }

  // Close any existing expanded row first
  closeExpanded();

  const finding = filteredFindings[index];
  const rows = findingsBody.querySelectorAll('tr:not(.expanded-row)');
  const targetRow = rows[index];

  // Create the expanded detail row
  const expandedTr = document.createElement('tr');
  expandedTr.className = 'expanded-row';
  expandedTr.innerHTML = `
    <td colspan="5">
      <div class="expanded-content">
        <div class="rule-id">${escapeHtml(finding.ruleId)} · matched: ${escapeHtml(finding.redactedText)}</div>
        ${finding.codeSnippet ? renderCodeSnippet(finding.codeSnippet) : ''}
        <div class="remediation">${escapeHtml(finding.remediation)}</div>
      </div>
    </td>
  `;

  targetRow.after(expandedTr);
  expandedRow = index;
}

function closeExpanded() {
  const existing = findingsBody.querySelector('.expanded-row');
  if (existing) existing.remove();
  expandedRow = null;
}

function renderCodeSnippet(snippet) {
  const lines = snippet.split('\n');
  const rendered = lines.map(line => {
    const isMatch = line.trimStart().startsWith('→');
    const escaped = escapeHtml(line);
    return isMatch
      ? `<span class="match-line">${escaped}</span>`
      : escaped;
  }).join('\n');

  return `<div class="code-snippet">${rendered}</div>`;
}

// ── Search ────────────────────────────────────────────────────────────────

searchBox.addEventListener('input', (e) => {
  activeFilters.search = e.target.value.trim();
  applyFiltersAndRender();
});

// ── Table sorting ─────────────────────────────────────────────────────────

document.querySelectorAll('.findings-table th[data-sort]').forEach(th => {
  th.addEventListener('click', () => {
    const col = th.dataset.sort;
    if (sortState.col === col) {
      sortState.dir = sortState.dir === 'asc' ? 'desc' : 'asc';
    } else {
      sortState.col = col;
      sortState.dir = 'desc';
    }
    applyFiltersAndRender();
  });
});

// ── UI helpers ────────────────────────────────────────────────────────────

function setLoading(isLoading) {
  btnScan.disabled = isLoading;
  loadingEl.classList.toggle('visible', isLoading);
}

function showError(message) {
  errorMsg.textContent = message;
  errorBox.classList.add('visible');
}

function hideError() {
  errorBox.classList.remove('visible');
}

function clearResults() {
  summaryBar.classList.remove('visible');
  findingsSection.classList.remove('visible');
  allFindings = [];
  filteredFindings = [];
  activeFilters.severity = new Set();
  activeFilters.search = '';
  searchBox.value = '';
}

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}