// Suspicious permission patterns that may indicate malicious behavior
const DANGEROUS_PERMISSIONS = [
  'webRequestBlocking',
  'debugger',
  'proxy',
  'vpnProvider',
  'nativeMessaging',
];

const HIGH_RISK_PERMISSIONS = [
  'webRequest',
  'cookies',
  'history',
  'bookmarks',
  'clipboardRead',
  'clipboardWrite',
  'contentSettings',
  'privacy',
  'downloads',
  'browsingData',
];

const SUSPICIOUS_HOST_PATTERNS = [
  '<all_urls>',
  '*://*/*',
  'http://*/*',
  'https://*/*',
];

/**
 * Analyze an extension's risk level based on its permissions and metadata.
 * Returns { level: 'safe'|'warn'|'danger', reasons: string[] }
 */
function analyzeExtension(ext) {
  const reasons = [];
  let score = 0;

  // Check dangerous permissions
  const perms = ext.permissions || [];
  for (const perm of perms) {
    if (DANGEROUS_PERMISSIONS.includes(perm)) {
      score += 3;
      reasons.push(`Dangerous permission: ${perm}`);
    } else if (HIGH_RISK_PERMISSIONS.includes(perm)) {
      score += 1;
      reasons.push(`Sensitive permission: ${perm}`);
    }
  }

  // Check host permissions for overly broad access
  const hostPerms = ext.hostPermissions || [];
  for (const host of hostPerms) {
    if (SUSPICIOUS_HOST_PATTERNS.includes(host)) {
      score += 2;
      reasons.push(`Broad host access: ${host}`);
    }
  }

  // Not from the Chrome Web Store
  if (ext.installType === 'development' || ext.installType === 'sideload') {
    score += 2;
    reasons.push(`Install type: ${ext.installType} (not from store)`);
  }

  // Extension disabled by the user is less of a concern
  if (!ext.enabled) {
    score = Math.max(0, score - 1);
  }

  let level = 'safe';
  if (score >= 5) level = 'danger';
  else if (score >= 2) level = 'warn';

  if (reasons.length === 0) {
    reasons.push('No suspicious indicators found');
  }

  return { level, reasons, score };
}

// Listen for messages from popup
chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (msg.action === 'scanExtensions') {
    chrome.management.getAll((extensions) => {
      // Filter out self and themes
      const results = extensions
        .filter((ext) => ext.type === 'extension' && ext.id !== chrome.runtime.id)
        .map((ext) => ({
          id: ext.id,
          name: ext.name,
          version: ext.version,
          enabled: ext.enabled,
          installType: ext.installType,
          description: ext.description,
          icons: ext.icons,
          permissions: ext.permissions,
          hostPermissions: ext.hostPermissions,
          analysis: analyzeExtension(ext),
        }))
        .sort((a, b) => b.analysis.score - a.analysis.score);

      sendResponse({ extensions: results });
    });
    return true; // async response
  }
});
