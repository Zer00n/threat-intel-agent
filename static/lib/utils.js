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
  if (seconds < 60) return `${seconds}秒`;
  return `${Math.floor(seconds / 60)}分 ${seconds % 60}秒`;
}

export function statusBadge(status) {
  const map = {
    running: ['running', '运行中'],
    completed: ['completed', '已完成'],
    failed: ['failed', '失败'],
    stopped: ['stopped', '已停止'],
    interrupted: ['interrupted', '已中断'],
    timeout: ['failed', '超时'],
    budget_exceeded: ['warning', '预算超限'],
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
  const icons = { success: '✓', error: '!', info: 'i' };
  const toast = document.createElement('div');
  toast.className = `ti-toast ti-toast--${type}`;
  toast.innerHTML = `
    <span class="ti-toast__icon">${icons[type] || 'i'}</span>
    <div class="ti-toast__body">
      <div class="ti-toast__msg">${message}</div>
    </div>
    <button class="ti-toast__close" onclick="this.parentElement.remove()">✕</button>
  `;
  container.appendChild(toast);
  setTimeout(() => toast.remove(), 3000);
}

export async function copyToClipboard(text) {
  try {
    if (navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(text);
    } else {
      const ta = document.createElement('textarea');
      ta.value = text;
      ta.style.cssText = 'position:fixed;opacity:0;left:-9999px';
      document.body.appendChild(ta);
      ta.select();
      document.execCommand('copy');
      document.body.removeChild(ta);
    }
    showToast('已复制到剪贴板');
  } catch {
    showToast('复制失败', 'error');
  }
}
