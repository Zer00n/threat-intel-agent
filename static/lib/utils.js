export function defang(value, type) {
  if (type === 'ipv4' || type === 'ipv6' || type === 'domain') {
    return value.replace(/\./g, '[.]');
  }
  if (type === 'url') {
    return value.replace(/http/g, 'hxxp').replace(/\./g, '[.]');
  }
  return value;
}

export function refang(value) {
  return value.replace(/\[\.\]/g, '.').replace(/hxxp/g, 'http');
}

export function formatDate(iso) {
  if (!iso) return '';
  const d = new Date(iso);
  return d.toLocaleString('zh-CN', { dateStyle: 'medium', timeStyle: 'short' });
}

export function formatDuration(seconds) {
  if (!seconds) return '';
  if (seconds < 60) return `${seconds}s`;
  return `${Math.floor(seconds / 60)}m ${seconds % 60}s`;
}

export function statusBadge(status) {
  const map = {
    running: ['running', 'Running'],
    completed: ['completed', 'Done'],
    failed: ['failed', 'Failed'],
    stopped: ['stopped', 'Stopped'],
    interrupted: ['interrupted', 'Interrupted'],
    timeout: ['failed', 'Timeout'],
    budget_exceeded: ['warning', 'Budget'],
  };
  const [cls, label] = map[status] || ['info', status];
  return `<span class="status-dot status-${cls}"></span> ${label}`;
}

export function confidenceBadge(confidence) {
  const cls = { High: 'success', Medium: 'warning', Low: 'error' }[confidence] || 'info';
  return `<span class="badge badge-${cls}">${confidence}</span>`;
}

export function tlpBadge(tlp) {
  const cls = { GREEN: 'green', AMBER: 'amber', RED: 'red', WHITE: 'info' }[tlp] || 'info';
  return `<span class="badge badge-${cls}">TLP: ${tlp}</span>`;
}

export function iocChip(ioc) {
  const cls = { ipv4: 'ipv4', ipv6: 'ipv4', domain: 'domain', url: 'url', md5: 'hash', sha1: 'hash', sha256: 'hash' }[ioc.ioc_type] || 'domain';
  return `<span class="chip chip-${cls}" data-ioc='${JSON.stringify(ioc)}' title="${ioc.context || ''}">${ioc.ioc_type}: ${ioc.value_defanged}</span>`;
}

export function showToast(message, type = 'success') {
  const container = document.getElementById('toast-container');
  const toast = document.createElement('div');
  toast.className = `toast toast-${type}`;
  toast.textContent = message;
  container.appendChild(toast);
  setTimeout(() => toast.remove(), 3000);
}

export async function copyToClipboard(text) {
  try {
    await navigator.clipboard.writeText(text);
    showToast('Copied to clipboard');
  } catch {
    showToast('Copy failed', 'error');
  }
}
