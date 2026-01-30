const scanBtn = document.getElementById('scan-btn');
const resultsDiv = document.getElementById('results');
const summaryDiv = document.getElementById('summary');
const safeCount = document.getElementById('safe-count');
const warnCount = document.getElementById('warn-count');
const dangerCount = document.getElementById('danger-count');

scanBtn.addEventListener('click', () => {
  scanBtn.disabled = true;
  scanBtn.textContent = 'Scanning...';
  resultsDiv.innerHTML = '';

  chrome.runtime.sendMessage({ action: 'scanExtensions' }, (response) => {
    scanBtn.disabled = false;
    scanBtn.textContent = 'Scan Extensions';

    if (!response || !response.extensions) {
      resultsDiv.innerHTML = '<p class="placeholder">Failed to scan extensions.</p>';
      return;
    }

    const exts = response.extensions;
    if (exts.length === 0) {
      resultsDiv.innerHTML = '<p class="placeholder">No other extensions found.</p>';
      return;
    }

    let safe = 0, warn = 0, danger = 0, blocklisted = 0;

    for (const ext of exts) {
      const { level, reasons } = ext.analysis;
      if (level === 'safe') safe++;
      else if (level === 'warn') warn++;
      else if (level === 'blocklist') { blocklisted++; danger++; }
      else danger++;

      const iconUrl = ext.icons && ext.icons.length > 0
        ? ext.icons[ext.icons.length - 1].url
        : '';

      const riskClass = level === 'blocklist' ? 'blocklist' : level;
      const riskIcon = level === 'safe' ? '&#10003;' : level === 'warn' ? '&#9888;' : '&#10007;';
      const blocklistBadge = level === 'blocklist' ? '<span class="badge-blocklist">BLOCKLISTED</span> ' : '';
      const unlistedBadge = reasons.some(r => r === 'Not found in Chrome Web Store')
        ? '<span class="badge-unlisted">NOT IN STORE</span> '
        : '';

      const item = document.createElement('div');
      item.className = 'ext-item';
      item.innerHTML = `
        ${iconUrl ? `<img class="ext-icon" src="${iconUrl}" alt="">` : '<div class="ext-icon"></div>'}
        <div class="ext-info">
          <div class="ext-name">${blocklistBadge}${unlistedBadge}${escapeHtml(ext.name)} <span style="color:#666;font-weight:400">v${escapeHtml(ext.version)}</span></div>
          <div class="ext-detail">${ext.enabled ? 'Enabled' : 'Disabled'} &middot; ${escapeHtml(ext.installType)}</div>
          <div class="ext-risk risk-${riskClass}">
            ${riskIcon}
            ${reasons.map(r => linkifyReason(r)).join('<br>')}
          </div>
        </div>
      `;
      resultsDiv.appendChild(item);
    }

    safeCount.textContent = `${safe} Safe`;
    warnCount.textContent = `${warn} Warnings`;
    dangerCount.textContent = `${danger} Dangerous`;
    summaryDiv.classList.remove('hidden');
  });
});

function escapeHtml(str) {
  const div = document.createElement('div');
  div.textContent = str || '';
  return div.innerHTML;
}

function linkifyReason(str) {
  const urlPattern = /(https?:\/\/[^\s]+)/g;
  const parts = str.split(urlPattern);
  return parts.map(part => {
    if (/^https?:\/\//.test(part)) {
      return `<a class="reason-link" href="${escapeHtml(part)}" target="_blank" rel="noopener noreferrer">${escapeHtml(part)}</a>`;
    }
    return escapeHtml(part);
  }).join('');
}
