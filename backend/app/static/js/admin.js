/* Honeypot Orchestrator — Admin Panel core */
/* global io, HP */

function adminApp() {
  const core = {
    authChecked: false,
    sidebarOpen: false,
    refreshing: false,
    tab: 'overview',
    tick: 0,

    loginForm: { username: '', password: '' },
    showPassword: false,
    loginLoading: false,
    loginError: '',

    user: null,
    ws: null,
    wsConnected: false,

    stats: {
      counts: { total: 0, '24h': 0, '7d': 0, '30d': 0 },
      severity_distribution: [],
      top_src_ip: [],
      top_event_types: [],
      top_mitre: [],
      timeline_24h: [],
      geo_points: [],
      top_countries: []
    },

    honeypots: [],
    hpLoading: false,
    users: [],
    usersLoading: false,
    siemConfigs: [],
    siemLoading: false,
    siemTesting: {},
    siemTestOutput: '',
    audit: { items: [], total: 0, page: 1, pages: 0 },
    auditLoading: false,
    auditFilters: { action: '', user_id: '', resource_type: '' },
    liveEvents: [],

    health: {
      status: 'ok',
      checks: { app: true, mongo: true, rabbitmq: true, redis: true }
    },

    hpModal: false,
    hpSaving: false,
    hpError: '',
    hpForm: { name: '', type: 'custom_web', image_name: '', location: '', description: '', ports: [] },

    userModal: false,
    userSaving: false,
    userError: '',
    userForm: { id: '', username: '', email: '', password: '', role: 'viewer', is_active: true },

    siemModal: false,
    siemSaving: false,
    siemError: '',
    siemForm: {
      id: '', siem_type: 'sopka', host: '', port: 514,
      protocol: 'syslog_udp', format: 'CEF', honeypot_id: '', api_key: '', is_active: true
    },

    init() {
      setInterval(() => { this.tick += 1; }, 30000);
      setInterval(() => {
        if (this.user && this.tab === 'overview') this.loadStats(true);
      }, 45000);
      setInterval(() => { if (this.user) this.checkHealth(); }, 30000);

      window.addEventListener('resize', HP.debounce(() => this.resizeAdminCharts(), 150));

      this.$watch('tab', () => this.$nextTick(() => this.onTabChange()));
      this.$watch('hpModal', () => this.syncModalLock());
      this.$watch('userModal', () => this.syncModalLock());
      this.$watch('siemModal', () => this.syncModalLock());

      this.checkSession();
    },

    async request(path, options = {}) {
      return HP.api(path, options);
    },

    showError(error, title = 'Ошибка') {
      if (!error) return;
      if (error.status === 401) {
        if (this.user) {
          this.user = null;
          this.hpModal = false;
          this.userModal = false;
          this.siemModal = false;
          this.syncModalLock();
          this.disconnectSocket();
          HP.toast('Сессия истекла. Войдите снова.', 'warning', 'Авторизация');
        }
        return;
      }
      HP.toast(error.message || String(error), 'error', title);
    },

    async checkSession() {
      try {
        const data = await HP.api('/api/v1/auth/me');
        this.user = data.user;
        this.authChecked = true;
        await this.loadAll();
        this.connectSocket();
        this.$nextTick(() => this.renderAdminCharts());
      } catch (error) {
        if (error.status !== 401) {
          HP.toast(error.message, 'warning', 'Проверка сессии');
        }
      } finally {
        this.authChecked = true;
      }
    },

    async doLogin() {
      this.loginError = '';
      if (!this.loginForm.username || !this.loginForm.password) {
        this.loginError = 'Введите имя пользователя и пароль';
        return;
      }
      this.loginLoading = true;
      try {
        const data = await HP.api('/api/v1/auth/login', {
          method: 'POST',
          body: this.loginForm
        });
        this.user = data.user;
        this.loginForm.password = '';
        this.loginForm.username = '';
        this.tab = 'overview';
        this.authChecked = true;
        await this.loadAll();
        this.connectSocket();
        this.$nextTick(() => this.renderAdminCharts());
        HP.toast(`Добро пожаловать, ${this.user.username}`, 'success', 'Доступ разрешён');
      } catch (error) {
        this.loginError = error.status === 401
          ? 'Неверное имя пользователя или пароль'
          : (error.message || 'Не удалось войти');
      } finally {
        this.loginLoading = false;
      }
    },

    async doLogout() {
      try {
        await HP.api('/api/v1/auth/logout', { method: 'POST' });
      } catch (_) {
        /* cookie может быть уже невалидной */
      }
      this.disconnectSocket();
      this.user = null;
      this.authChecked = true;
      this.tab = 'overview';
      this.honeypots = [];
      this.users = [];
      this.siemConfigs = [];
      this.audit = { items: [], total: 0, page: 1, pages: 0 };
      this.liveEvents = [];
      this.hpModal = false;
      this.userModal = false;
      this.siemModal = false;
      this.syncModalLock();
      HP.toast('Сессия завершена', 'info', 'Выход');
    },

    navItems() {
      const items = [
        { id: 'overview', label: 'Обзор', icon: 'i-grid', badge: '' },
        {
          id: 'honeypots', label: 'Ловушки', icon: 'i-server',
          badge: this.honeypots.length ? String(this.honeypots.length) : ''
        }
      ];
      if (this.canManage()) {
        items.push({
          id: 'siem', label: 'SIEM / SOPKA', icon: 'i-send',
          badge: this.siemConfigs.some((cfg) => cfg.is_active) ? 'ON' : ''
        });
      }
      if (this.isSuperadmin()) {
        items.push({ id: 'users', label: 'Пользователи', icon: 'i-users', badge: this.users.length ? String(this.users.length) : '' });
        items.push({ id: 'audit', label: 'Аудит', icon: 'i-file', badge: '' });
      }
      return items;
    },

    pageTitle() {
      return {
        overview: 'Обзор',
        honeypots: 'Ловушки',
        siem: 'SIEM / SOPKA',
        users: 'Пользователи',
        audit: 'Журнал аудита'
      }[this.tab] || 'Admin Panel';
    },

    go(tab) {
      const allowed = this.navItems().map((item) => item.id);
      if (!allowed.includes(tab)) return;
      this.tab = tab;
      this.sidebarOpen = false;
    },

    onTabChange() {
      if (this.tab === 'overview') {
        this.renderAdminCharts();
        setTimeout(() => this.resizeAdminCharts(), 60);
      }
      if (this.tab === 'honeypots' && !this.honeypots.length) this.loadHoneypots();
      if (this.tab === 'siem' && this.canManage() && !this.siemConfigs.length) this.loadSiem();
      if (this.tab === 'users' && this.isSuperadmin() && !this.users.length) this.loadUsers();
      if (this.tab === 'audit' && this.isSuperadmin()) this.loadAudit(this.audit.page || 1);
    },

    canManage() {
      return ['admin', 'superadmin'].includes(this.user?.role);
    },

    isSuperadmin() {
      return this.user?.role === 'superadmin';
    },

    userInitials() {
      return String(this.user?.username || 'OP').slice(0, 2).toUpperCase();
    },

    runningHoneypots() {
      return this.honeypots.filter((hp) => hp.status === 'running').length;
    },

    stoppedHoneypots() {
      return this.honeypots.filter((hp) => hp.status === 'stopped').length;
    },

    criticalCount() {
      const found = this.stats.severity_distribution.find((item) => item.severity === 'critical');
      return found ? Number(found.count) : 0;
    },

    rel(value) {
      void this.tick;
      return HP.relative(value);
    },

    infraChecks() {
      const checks = this.health.checks || {};
      return [
        { key: 'api', label: 'Flask API', ok: !!checks.app },
        { key: 'mongo', label: 'MongoDB', ok: !!checks.mongo },
        { key: 'rabbit', label: 'RabbitMQ', ok: !!checks.rabbitmq },
        { key: 'redis', label: 'Redis', ok: !!checks.redis }
      ];
    },

    formatPorts(ports) {
      if (!ports) return '—';
      if (Array.isArray(ports)) return `${ports.length} порт(ов)`;
      const entries = Object.entries(ports);
      if (!entries.length) return '—';
      return entries.map(([container, host]) => `${container}→${host}`).join(', ');
    },

    typeGradient(type) {
      const gradients = {
        cowrie_ssh: 'linear-gradient(135deg,rgba(52,211,153,.28),rgba(34,211,238,.08))',
        custom_web: 'linear-gradient(135deg,rgba(34,211,238,.28),rgba(59,130,246,.08))',
        custom_1c: 'linear-gradient(135deg,rgba(139,92,246,.3),rgba(34,211,238,.08))',
        smb: 'linear-gradient(135deg,rgba(251,191,36,.26),rgba(251,113,133,.08))',
        ftp: 'linear-gradient(135deg,rgba(251,113,133,.24),rgba(139,92,246,.08))'
      };
      return gradients[type] || 'linear-gradient(135deg,rgba(148,163,184,.22),rgba(34,211,238,.06))';
    },

    async checkHealth() {
      try {
        this.health = await HP.api('/api/v1/health');
      } catch (_) {
        this.health = { status: 'degraded', checks: { app: false, mongo: false, rabbitmq: false, redis: false } };
      }
    },

    async refreshAll() {
      if (!this.user || this.refreshing) return;
      this.refreshing = true;
      await this.loadAll();
      this.$nextTick(() => this.renderAdminCharts());
      this.refreshing = false;
      HP.toast('Данные обновлены', 'success', 'Обновление');
    },

    connectSocket() {
      if (this.ws || typeof io !== 'function') return;
      const socket = io('/live', {
        path: '/socket.io',
        transports: ['websocket', 'polling'],
        reconnection: true,
        reconnectionDelay: 1500
      });
      socket.on('connect', () => { this.wsConnected = true; });
      socket.on('disconnect', () => { this.wsConnected = false; });
      socket.on('new_event', (event) => this.onNewEvent(event));
      this.ws = socket;
    },

    disconnectSocket() {
      if (this.ws) {
        try { this.ws.disconnect(); } catch (_) {}
      }
      this.ws = null;
      this.wsConnected = false;
    },

    onNewEvent(event) {
      if (!event) return;
      this.liveEvents.unshift(event);
      this.liveEvents = this.liveEvents.slice(0, 40);
      if (event.severity === 'critical') {
        HP.toast(`${HP.eventLabel(event.event_type)} · ${event.src_ip || 'internal'}`, 'error', 'Критическое событие');
      }
      if (!this._refreshStatsDebounced) {
        this._refreshStatsDebounced = HP.debounce(() => this.loadStats(true), 1200);
      }
      this._refreshStatsDebounced();
    },

    syncModalLock() {
      const open = this.hpModal || this.userModal || this.siemModal;
      document.body.style.overflow = open ? 'hidden' : '';
    }
  };

  return Object.assign(
    core,
    window.AdminActions || {},
    window.AdminCharts || {}
  );
}
