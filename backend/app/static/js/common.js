/* Honeypot Orchestrator — shared UI helpers */
(() => {
  'use strict';

  const HP = (window.HP = window.HP || {});

  class ApiError extends Error {
    constructor(message, status = 0, data = null) {
      super(message);
      this.name = 'ApiError';
      this.status = status;
      this.data = data;
    }
  }
  HP.ApiError = ApiError;

  HP.escapeHtml = (value) =>
    String(value ?? '').replace(/[&<>"']/g, (ch) => ({
      '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
    }[ch]));

  HP.parseDate = (value) => {
    if (!value) return null;
    if (value instanceof Date) return value;
    if (typeof value === 'number') {
      const ms = value > 1e12 ? value : value * 1000;
      return new Date(ms);
    }
    let text = String(value).trim();
    if (/^\d{4}-\d{2}-\d{2} \d/.test(text)) text = text.replace(' ', 'T');
    if (!/(Z|[+-]\d{2}:?\d{2})$/.test(text)) text += 'Z';
    const date = new Date(text);
    return Number.isNaN(date.getTime()) ? null : date;
  };

  HP.dateTime = (value) => {
    const date = HP.parseDate(value);
    if (!date) return '—';
    return new Intl.DateTimeFormat('ru-RU', {
      day: '2-digit', month: '2-digit', year: 'numeric',
      hour: '2-digit', minute: '2-digit', second: '2-digit'
    }).format(date);
  };

  HP.dateShort = (value) => {
    const date = HP.parseDate(value);
    if (!date) return '—';
    return new Intl.DateTimeFormat('ru-RU', {
      day: '2-digit', month: 'short', hour: '2-digit', minute: '2-digit'
    }).format(date);
  };

  HP.timeShort = (value) => {
    const date = HP.parseDate(value);
    if (!date) return '—';
    return new Intl.DateTimeFormat('ru-RU', {
      hour: '2-digit', minute: '2-digit', second: '2-digit'
    }).format(date);
  };

  HP.hourLabel = (value) => {
    const date = HP.parseDate(value);
    if (!date) return '';
    return new Intl.DateTimeFormat('ru-RU', { hour: '2-digit', minute: '2-digit' }).format(date);
  };

  HP.relative = (value) => {
    const date = HP.parseDate(value);
    if (!date) return '—';
    const diff = Date.now() - date.getTime();
    if (diff < 0) return 'в будущем';
    const sec = Math.floor(diff / 1000);
    if (sec < 15) return 'только что';
    if (sec < 60) return `${sec} сек назад`;
    const min = Math.floor(sec / 60);
    if (min < 60) return `${min} мин назад`;
    const hours = Math.floor(min / 60);
    if (hours < 24) return `${hours} ч назад`;
    const days = Math.floor(hours / 24);
    if (days < 30) return `${days} дн назад`;
    return HP.dateShort(value);
  };

  HP.number = (value) => new Intl.NumberFormat('ru-RU').format(Number(value) || 0);

  HP.clock = () => new Intl.DateTimeFormat('ru-RU', {
    hour: '2-digit', minute: '2-digit', second: '2-digit'
  }).format(new Date());

  HP.dateStamp = () => new Intl.DateTimeFormat('ru-RU', {
    weekday: 'short', day: '2-digit', month: 'long'
  }).format(new Date());

  HP.severity = {
    low: { label: 'Низкий', className: 'badge-low', color: '#34d399', rank: 1 },
    medium: { label: 'Средний', className: 'badge-medium', color: '#fbbf24', rank: 2 },
    high: { label: 'Высокий', className: 'badge-high', color: '#fb923c', rank: 3 },
    critical: { label: 'Критический', className: 'badge-critical', color: '#fb7185', rank: 4 }
  };
  HP.severityMeta = (value) => HP.severity[String(value || '').toLowerCase()] || {
    label: value || 'Неизвестно', className: 'badge-neutral', color: '#94a3b8', rank: 0
  };

  HP.status = {
    running: { label: 'Работает', className: 'status-running', color: '#34d399' },
    stopped: { label: 'Остановлена', className: 'status-stopped', color: '#94a3b8' },
    creating: { label: 'Создание', className: 'status-creating', color: '#fbbf24' },
    error: { label: 'Ошибка', className: 'status-error', color: '#fb7185' }
  };
  HP.statusMeta = (value) => HP.status[String(value || '').toLowerCase()] || {
    label: value || 'Неизвестно', className: 'badge-neutral', color: '#94a3b8'
  };

  HP.roles = {
    superadmin: { label: 'Superadmin', className: 'role-superadmin' },
    admin: { label: 'Администратор', className: 'role-admin' },
    analyst: { label: 'Аналитик', className: 'role-analyst' },
    viewer: { label: 'Наблюдатель', className: 'role-viewer' }
  };
  HP.roleMeta = (value) => HP.roles[value] || { label: value || '—', className: 'badge-neutral' };

  HP.honeypotTypes = {
    cowrie_ssh: { label: 'Cowrie SSH', short: 'SSH' },
    custom_web: { label: 'Веб-ловушка', short: 'WEB' },
    custom_1c: { label: '1С веб-клиент', short: '1C' },
    ssh: { label: 'SSH', short: 'SSH' },
    http: { label: 'HTTP', short: 'HTTP' },
    smb: { label: 'SMB', short: 'SMB' },
    ftp: { label: 'FTP', short: 'FTP' },
    generic: { label: 'Универсальная', short: 'GEN' }
  };
  HP.typeMeta = (value) => HP.honeypotTypes[value] || { label: value || '—', short: 'HP' };

  const eventLabels = {
    'ssh.login_failed': 'SSH: неудачный вход',
    'http.request': 'HTTP-запрос',
    'smb.scan': 'SMB-сканирование',
    'container.log': 'Лог контейнера',
    'test.event': 'Тестовое событие',
    'auth.login': 'Вход в систему',
    'auth.login.failed': 'Неудачный вход'
  };
  HP.eventLabel = (value) => eventLabels[value] || value || 'Событие';

  HP.buildQuery = (params) => {
    const query = new URLSearchParams();
    Object.entries(params || {}).forEach(([key, value]) => {
      if (value !== undefined && value !== null && String(value).trim() !== '') {
        query.set(key, value);
      }
    });
    const text = query.toString();
    return text ? `?${text}` : '';
  };

  HP.api = async (path, options = {}) => {
    const { method = 'GET', body, headers = {}, signal } = options;
    const init = {
      method,
      credentials: 'same-origin',
      headers: { Accept: 'application/json', ...headers }
    };
    if (body !== undefined) {
      init.headers['Content-Type'] = 'application/json';
      init.body = typeof body === 'string' ? body : JSON.stringify(body);
    }
    if (signal) init.signal = signal;

    let response;
    try {
      response = await fetch(path, init);
    } catch (error) {
      if (error.name === 'AbortError') throw error;
      throw new ApiError('Сервер недоступен. Проверьте, запущен ли backend.', 0);
    }

    const contentType = response.headers.get('content-type') || '';
    let data = null;
    if (contentType.includes('application/json')) {
      data = await response.json().catch(() => null);
    }

    if (!response.ok) {
      const message = (data && (data.message || data.error)) || `Ошибка ${response.status}`;
      throw new ApiError(message, response.status, data);
    }
    return data;
  };

  HP.debounce = (fn, wait = 300) => {
    let timer = null;
    return (...args) => {
      clearTimeout(timer);
      timer = setTimeout(() => fn.apply(null, args), wait);
    };
  };

  HP.sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

  HP.copy = async (text) => {
    try {
      await navigator.clipboard.writeText(String(text));
      return true;
    } catch (_) {
      try {
        const area = document.createElement('textarea');
        area.value = String(text);
        area.style.position = 'fixed';
        area.style.opacity = '0';
        document.body.appendChild(area);
        area.select();
        const ok = document.execCommand('copy');
        area.remove();
        return ok;
      } catch (__) {
        return false;
      }
    }
  };

  HP.downloadJSON = (data, filename = 'export.json') => {
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
  };

  /* ---------------- Toasts ---------------- */
  const toastIcons = {
    success: 'i-check',
    error: 'i-alert',
    warning: 'i-alert',
    info: 'i-info'
  };
  const toastTitles = {
    success: 'Готово',
    error: 'Ошибка',
    warning: 'Внимание',
    info: 'Информация'
  };

  HP.toast = (message, type = 'info', title = null) => {
    const stack = document.getElementById('toast-stack');
    if (!stack) return;

    const tone = ['success', 'error', 'warning', 'info'].includes(type) ? type : 'info';
    const element = document.createElement('div');
    element.className = `toast toast-${tone}`;

    const icon = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    icon.setAttribute('class', 'mt-0.5 h-5 w-5 flex-none');
    const use = document.createElementNS('http://www.w3.org/2000/svg', 'use');
    use.setAttribute('href', `#${toastIcons[tone]}`);
    icon.appendChild(use);

    const body = document.createElement('div');
    body.className = 'min-w-0 flex-1';
    const heading = document.createElement('div');
    heading.className = 'toast-title';
    heading.textContent = title || toastTitles[tone];
    const text = document.createElement('div');
    text.className = 'toast-message';
    text.textContent = String(message ?? '');
    body.append(heading, text);

    const close = document.createElement('button');
    close.type = 'button';
    close.className = 'ml-1 flex-none text-slate-500 transition hover:text-slate-200';
    close.innerHTML = '<svg class="h-4 w-4"><use href="#i-x"></use></svg>';
    close.setAttribute('aria-label', 'Закрыть');

    element.append(icon, body, close);
    stack.appendChild(element);

    while (stack.children.length > 4) stack.firstElementChild.remove();

    let timer = null;
    const dismiss = () => {
      if (!element.isConnected || element.classList.contains('removing')) return;
      element.classList.add('removing');
      setTimeout(() => element.remove(), 230);
    };
    close.addEventListener('click', dismiss);
    timer = setTimeout(dismiss, 5200);
    element.addEventListener('mouseenter', () => clearTimeout(timer));
    element.addEventListener('mouseleave', () => { timer = setTimeout(dismiss, 1800); });
  };

  /* ---------------- Confirm dialog ---------------- */
  let confirmResolver = null;

  const closeConfirm = (result) => {
    const modal = document.getElementById('hp-confirm');
    if (!modal) return;
    modal.classList.add('hidden');
    modal.classList.remove('flex');
    document.body.style.overflow = '';
    if (confirmResolver) {
      confirmResolver(result);
      confirmResolver = null;
    }
  };

  HP.confirm = (options = {}) => {
    const {
      title = 'Подтвердите действие',
      message = '',
      confirmText = 'Подтвердить',
      cancelText = 'Отмена',
      danger = true
    } = options;

    const modal = document.getElementById('hp-confirm');
    if (!modal) return Promise.resolve(window.confirm(message || title));

    if (confirmResolver) closeConfirm(false);

    const titleEl = document.getElementById('hp-confirm-title');
    const messageEl = document.getElementById('hp-confirm-message');
    const okBtn = document.getElementById('hp-confirm-ok');
    const cancelBtn = document.getElementById('hp-confirm-cancel');

    titleEl.textContent = title;
    messageEl.textContent = message;
    okBtn.textContent = confirmText;
    cancelBtn.textContent = cancelText;
    okBtn.className = danger ? 'btn btn-danger' : 'btn btn-primary';

    modal.classList.remove('hidden');
    modal.classList.add('flex');
    document.body.style.overflow = 'hidden';
    setTimeout(() => cancelBtn.focus(), 20);

    return new Promise((resolve) => {
      confirmResolver = resolve;
      okBtn.onclick = () => closeConfirm(true);
      cancelBtn.onclick = () => closeConfirm(false);
      modal.onclick = (event) => {
        if (event.target === modal) closeConfirm(false);
      };
    });
  };

  document.addEventListener('keydown', (event) => {
    if (event.key !== 'Escape') return;
    const modal = document.getElementById('hp-confirm');
    if (modal && !modal.classList.contains('hidden')) closeConfirm(false);
  });

  /* ---------------- Auto clock ---------------- */
  const tickClocks = () => {
    document.querySelectorAll('[data-hp-clock]').forEach((node) => {
      node.textContent = HP.clock();
    });
  };
  document.addEventListener('DOMContentLoaded', () => {
    tickClocks();
    setInterval(tickClocks, 1000);
  });
})();
