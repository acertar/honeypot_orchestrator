/* Honeypot Orchestrator — Admin actions */
/* global HP */

window.AdminActions = {
  /* ---------------- Data loading ---------------- */
  async loadAll() {
    const tasks = [
      this.loadStats(true),
      this.loadHoneypots(),
      this.loadRecentEvents(),
      this.checkHealth()
    ];
    if (this.canManage()) tasks.push(this.loadSiem());
    if (this.isSuperadmin()) {
      tasks.push(this.loadUsers());
      tasks.push(this.loadAudit(1));
    }
    await Promise.allSettled(tasks);
    this.$nextTick(() => this.renderAdminCharts());
  },

  async loadStats(silent = false) {
    try {
      const stats = await this.request('/api/v1/events/stats');
      this.stats = {
        ...this.stats,
        ...stats,
        counts: stats.counts || this.stats.counts,
        severity_distribution: stats.severity_distribution || [],
        top_src_ip: stats.top_src_ip || [],
        top_event_types: stats.top_event_types || [],
        top_mitre: stats.top_mitre || [],
        timeline_24h: stats.timeline_24h || [],
        geo_points: stats.geo_points || [],
        top_countries: stats.top_countries || []
      };
      if (this.tab === 'overview') this.$nextTick(() => this.renderAdminCharts());
    } catch (error) {
      if (!silent) this.showError(error, 'Статистика');
    }
  },

  async loadHoneypots() {
    this.hpLoading = true;
    try {
      const data = await this.request('/api/v1/honeypots/?limit=200');
      this.honeypots = data.items || [];
    } catch (error) {
      this.showError(error, 'Ловушки');
    } finally {
      this.hpLoading = false;
    }
  },

  async loadRecentEvents() {
    try {
      const data = await this.request('/api/v1/events/?limit=10');
      if (!this.liveEvents.length) this.liveEvents = data.items || [];
    } catch (_) {
      /* необязательный блок */
    }
  },

  async loadUsers() {
    if (!this.isSuperadmin()) return;
    this.usersLoading = true;
    try {
      const data = await this.request('/api/v1/users?limit=200');
      this.users = data.items || [];
    } catch (error) {
      this.showError(error, 'Пользователи');
    } finally {
      this.usersLoading = false;
    }
  },

  async loadSiem() {
    if (!this.canManage()) return;
    this.siemLoading = true;
    try {
      const data = await this.request('/api/v1/siem/configs');
      this.siemConfigs = data.items || [];
    } catch (error) {
      this.showError(error, 'SIEM');
    } finally {
      this.siemLoading = false;
    }
  },

  async loadAudit(page = 1) {
    if (!this.isSuperadmin()) return;
    this.auditLoading = true;
    try {
      const query = HP.buildQuery({
        page: Math.max(1, Number(page) || 1),
        limit: 20,
        ...this.auditFilters
      });
      const data = await this.request(`/api/v1/audit${query}`);
      this.audit = data;
    } catch (error) {
      this.showError(error, 'Аудит');
    } finally {
      this.auditLoading = false;
    }
  },

  applyAuditFilters() {
    this.loadAudit(1);
  },

  resetAuditFilters() {
    this.auditFilters = { action: '', user_id: '', resource_type: '' };
    this.loadAudit(1);
  },

  auditGo(page) {
    const target = Math.min(Math.max(1, page), Math.max(1, this.audit.pages || 1));
    if (target === this.audit.page) return;
    this.loadAudit(target);
  },

  auditPageWindow() {
    const total = Math.max(1, this.audit.pages || 1);
    let start = Math.max(1, Number(this.audit.page || 1) - 2);
    const end = Math.min(total, start + 4);
    start = Math.max(1, end - 4);
    const pages = [];
    for (let p = start; p <= end; p += 1) pages.push(p);
    return pages;
  },

  exportAudit() {
    HP.downloadJSON(
      { exported_at: new Date().toISOString(), filters: this.auditFilters, items: this.audit.items },
      `audit-page-${this.audit.page || 1}.json`
    );
    HP.toast('Журнал аудита выгружен', 'success', 'Экспорт');
  },

  /* ---------------- Honeypots ---------------- */
  openHoneypotModal() {
    if (!this.canManage()) return;
    this.hpError = '';
    this.hpForm = {
      name: '',
      type: 'custom_web',
      image_name: 'nginx:alpine',
      location: 'DMZ',
      description: '',
      ports: [{ container: '80', host: '8080', protocol: 'tcp' }]
    };
    this.hpModal = true;
    this.syncModalLock();
  },

  closeHoneypotModal() {
    if (this.hpSaving) return;
    this.hpModal = false;
    this.syncModalLock();
  },

  applyHoneypotPreset() {
    const presets = {
      cowrie_ssh: { image: 'cowrie/cowrie', ports: [['2222', '2222']] },
      custom_web: { image: 'nginx:alpine', ports: [['80', '8080']] },
      custom_1c: { image: 'httpd:2.4', ports: [['80', '8081']] },
      ssh: { image: 'cowrie/cowrie', ports: [['2222', '2222']] },
      http: { image: 'nginx:alpine', ports: [['80', '8080']] },
      smb: { image: 'dperson/samba', ports: [['445', '1445'], ['139', '1139']] },
      ftp: { image: 'fauria/vsftpd', ports: [['21', '2121']] },
      generic: { image: 'alpine:latest', ports: [['80', '8080']] }
    };
    const preset = presets[this.hpForm.type];
    if (!preset) return;
    this.hpForm.image_name = preset.image;
    this.hpForm.ports = preset.ports.map(([container, host]) => ({
      container, host, protocol: 'tcp'
    }));
  },

  addPortRow() {
    this.hpForm.ports.push({ container: '', host: '', protocol: 'tcp' });
  },

  removePortRow(index) {
    if (this.hpForm.ports.length <= 1) return;
    this.hpForm.ports.splice(index, 1);
  },

  buildExposedPorts() {
    const result = {};
    for (const port of this.hpForm.ports) {
      const container = String(port.container || '').trim();
      const host = String(port.host || '').trim();
      if (!container && !host) continue;
      if (!/^\d+$/.test(container) || !/^\d+$/.test(host)) {
        throw new Error('Порты должны быть целыми числами');
      }
      const protocol = port.protocol === 'udp' ? 'udp' : 'tcp';
      result[`${container}/${protocol}`] = Number(host);
    }
    return result;
  },

  async saveHoneypot() {
    this.hpError = '';
    const name = (this.hpForm.name || '').trim();
    if (!/^[a-zA-Z0-9][a-zA-Z0-9_.-]{2,63}$/.test(name)) {
      this.hpError = 'Имя: 3-64 символа, латиница/цифры/._-';
      return;
    }
    if (!this.hpForm.image_name) {
      this.hpError = 'Укажите образ контейнера';
      return;
    }

    let ports;
    try {
      ports = this.buildExposedPorts();
    } catch (error) {
      this.hpError = error.message;
      return;
    }

    this.hpSaving = true;
    try {
      await this.request('/api/v1/honeypots/', {
        method: 'POST',
        body: {
          name,
          type: this.hpForm.type,
          image_name: this.hpForm.image_name,
          exposed_ports: ports,
          location: this.hpForm.location || '',
          description: this.hpForm.description || ''
        }
      });
      this.hpModal = false;
      this.syncModalLock();
      this.tab = 'honeypots';
      HP.toast(`Ловушка ${name} развёрнута`, 'success', 'Podman');
      await Promise.allSettled([this.loadHoneypots(), this.loadStats(true)]);
    } catch (error) {
      this.hpError = error.message || 'Не удалось создать ловушку';
      if (error.status === 401) this.showError(error);
    } finally {
      this.hpSaving = false;
    }
  },

  async stopHoneypot(hp) {
    const confirmed = await HP.confirm({
      title: 'Остановить ловушку?',
      message: `Контейнер «${hp.name}» будет остановлен. События сохранятся.`,
      confirmText: 'Остановить',
      danger: false
    });
    if (!confirmed) return;
    try {
      await this.request(`/api/v1/honeypots/${hp.id}/stop`, { method: 'POST' });
      HP.toast(`Ловушка ${hp.name} остановлена`, 'success');
      await this.loadHoneypots();
    } catch (error) {
      this.showError(error, 'Остановка ловушки');
    }
  },

  async deleteHoneypot(hp) {
    const confirmed = await HP.confirm({
      title: 'Удалить ловушку?',
      message: `Контейнер «${hp.name}» будет остановлен и удалён. Исторические события останутся в MongoDB.`,
      confirmText: 'Удалить',
      danger: true
    });
    if (!confirmed) return;
    try {
      await this.request(`/api/v1/honeypots/${hp.id}`, { method: 'DELETE' });
      HP.toast(`Ловушка ${hp.name} удалена`, 'success');
      await Promise.allSettled([this.loadHoneypots(), this.loadStats(true)]);
    } catch (error) {
      this.showError(error, 'Удаление ловушки');
    }
  },

  /* ---------------- Users ---------------- */
  isSelf(user) {
    return !!user && user.id === this.user?.id;
  },

  openUserModal(user = null) {
    if (!this.isSuperadmin()) return;
    this.userError = '';
    this.userForm = user
      ? {
          id: user.id,
          username: user.username,
          email: user.email || '',
          password: '',
          role: user.role || 'viewer',
          is_active: !!user.is_active
        }
      : { id: '', username: '', email: '', password: '', role: 'viewer', is_active: true };
    this.userModal = true;
    this.syncModalLock();
  },

  closeUserModal() {
    if (this.userSaving) return;
    this.userModal = false;
    this.syncModalLock();
  },

  async saveUser() {
    this.userError = '';
    const f = this.userForm;
    if (!f.id && !/^[a-zA-Z0-9_.-]{3,64}$/.test(f.username || '')) {
      this.userError = 'Username: 3-64 символа (латиница/цифры/._-)';
      return;
    }
    if (!f.email || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(f.email)) {
      this.userError = 'Укажите корректный email';
      return;
    }
    if (!f.id && (!f.password || f.password.length < 8)) {
      this.userError = 'Пароль должен содержать минимум 8 символов';
      return;
    }
    if (f.password && f.password.length < 8) {
      this.userError = 'Новый пароль должен содержать минимум 8 символов';
      return;
    }

    this.userSaving = true;
    try {
      const body = {
        email: f.email,
        role: f.role,
        is_active: !!f.is_active
      };
      if (f.password) body.password = f.password;
      if (!f.id) {
        body.username = f.username;
        await this.request('/api/v1/users/', { method: 'POST', body });
      } else {
        await this.request(`/api/v1/users/${f.id}`, { method: 'PUT', body });
      }
      this.userModal = false;
      this.syncModalLock();
      HP.toast(f.id ? 'Пользователь обновлён' : 'Пользователь создан', 'success');
      await this.loadUsers();
    } catch (error) {
      this.userError = error.message || 'Не удалось сохранить пользователя';
      if (error.status === 401) this.showError(error);
    } finally {
      this.userSaving = false;
    }
  },

  async deleteUser(user) {
    if (this.isSelf(user)) {
      HP.toast('Нельзя удалить собственную учётную запись', 'warning');
      return;
    }
    const confirmed = await HP.confirm({
      title: 'Удалить пользователя?',
      message: `Учётная запись «${user.username}» будет удалена без возможности восстановления.`,
      confirmText: 'Удалить',
      danger: true
    });
    if (!confirmed) return;
    try {
      await this.request(`/api/v1/users/${user.id}`, { method: 'DELETE' });
      HP.toast(`Пользователь ${user.username} удалён`, 'success');
      await this.loadUsers();
    } catch (error) {
      this.showError(error, 'Удаление пользователя');
    }
  },

  /* ---------------- SIEM ---------------- */
  openSiemModal(config = null) {
    if (!this.canManage()) return;
    this.siemError = '';
    this.siemForm = config
      ? {
          id: config.id,
          siem_type: config.siem_type,
          host: config.host,
          port: Number(config.port),
          protocol: config.protocol,
          format: config.format,
          honeypot_id: config.honeypot_id || '',
          api_key: '',
          is_active: !!config.is_active
        }
      : {
          id: '',
          siem_type: 'sopka',
          host: '',
          port: 514,
          protocol: 'syslog_udp',
          format: 'CEF',
          honeypot_id: '',
          api_key: '',
          is_active: true
        };
    this.siemModal = true;
    this.syncModalLock();
  },

  closeSiemModal() {
    if (this.siemSaving) return;
    this.siemModal = false;
    this.syncModalLock();
  },

  async saveSiem() {
    this.siemError = '';
    const f = this.siemForm;
    if (!f.host) {
      this.siemError = 'Укажите host SIEM';
      return;
    }
    const port = Number(f.port);
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      this.siemError = 'Порт должен быть в диапазоне 1-65535';
      return;
    }

    this.siemSaving = true;
    try {
      const body = {
        siem_type: f.siem_type,
        host: f.host,
        port,
        protocol: f.protocol,
        format: f.format,
        honeypot_id: f.honeypot_id || null,
        is_active: !!f.is_active
      };
      if (f.api_key) body.api_key = f.api_key;
      if (f.id) {
        await this.request(`/api/v1/siem/configs/${f.id}`, { method: 'PUT', body });
      } else {
        await this.request('/api/v1/siem/configs', { method: 'POST', body });
      }
      this.siemModal = false;
      this.syncModalLock();
      HP.toast(f.id ? 'Конфигурация обновлена' : 'Конфигурация создана', 'success');
      await this.loadSiem();
    } catch (error) {
      this.siemError = error.message || 'Не удалось сохранить конфигурацию';
      if (error.status === 401) this.showError(error);
    } finally {
      this.siemSaving = false;
    }
  },

  async testSiem(config) {
    this.siemTesting = { ...this.siemTesting, [config.id]: true };
    try {
      const result = await this.request(`/api/v1/siem/configs/${config.id}/test`, { method: 'POST' });
      this.siemTestOutput = result.message || '';
      HP.toast('Тестовый CEF отправлен в SIEM', 'success', 'SIEM');
      await this.loadSiem();
    } catch (error) {
      this.siemTestOutput = error.data?.message || error.message || '';
      this.showError(error, 'Тест SIEM');
    } finally {
      this.siemTesting = { ...this.siemTesting, [config.id]: false };
    }
  },

  copySiemTest() {
    HP.copy(this.siemTestOutput).then((ok) => {
      HP.toast(ok ? 'CEF скопирован' : 'Не удалось скопировать', ok ? 'success' : 'error');
    });
  },

  async deleteSiem(config) {
    const confirmed = await HP.confirm({
      title: 'Удалить SIEM-конфигурацию?',
      message: `Интеграция ${String(config.siem_type).toUpperCase()} ${config.host}:${config.port} будет удалена.`,
      confirmText: 'Удалить',
      danger: true
    });
    if (!confirmed) return;
    try {
      await this.request(`/api/v1/siem/configs/${config.id}`, { method: 'DELETE' });
      HP.toast('SIEM-конфигурация удалена', 'success');
      await this.loadSiem();
    } catch (error) {
      this.showError(error, 'Удаление SIEM');
    }
  }
};
