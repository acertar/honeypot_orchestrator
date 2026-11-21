/* Honeypot Orchestrator — SOC Dashboard */
/* global echarts, io, HP */

const DASHBOARD_CHARTS = {};

function dashboardChart(key, element) {
  if (!element) return null;
  const existing = DASHBOARD_CHARTS[key];
  if (existing && !existing.isDisposed()) return existing;
  const chart = echarts.init(element, null, { renderer: 'canvas' });
  DASHBOARD_CHARTS[key] = chart;
  return chart;
}

function dashboardApp() {
  return {
    tab: 'overview',
    sidebarOpen: false,
    refreshing: false,
    tick: 0,
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
    events: [],
    eventsTotal: 0,
    page: 1,
    pages: 0,
    limit: 10,
    filters: { src_ip: '', severity: '', event_type: '', honeypot_id: '' },
    eventTypes: [],
    loadingEvents: false,
    honeypots: [],
    hpLoading: false,
    liveEvents: [],
    ws: null,
    wsConnected: false,
    health: {
      status: 'ok',
      checks: { app: true, mongo: true, rabbitmq: true, redis: true }
    },
    eventModal: false,
    selectedEvent: null,
    mapLoaded: false,

    init() {
      this.loadAll();
      this.connectSocket();
      this.checkHealth();

      this.$watch('tab', () => this.$nextTick(() => this.onTabChange()));
      this.$watch('eventModal', (open) => {
        document.body.style.overflow = open ? 'hidden' : '';
      });

      setInterval(() => {
        this.tick += 1;
      }, 30000);

      setInterval(() => {
        if (this.tab === 'overview' || this.tab === 'map') this.loadStats(true);
      }, 45000);

      setInterval(() => this.checkHealth(), 30000);

      window.addEventListener(
        'resize',
        HP.debounce(() => this.resizeCharts(), 150)
      );

      this.$nextTick(() => this.renderCharts());
    },

    navItems() {
      return [
        { id: 'overview', label: 'Обзор', icon: 'i-grid', badge: '' },
        { id: 'events', label: 'События', icon: 'i-activity', badge: this.eventsTotal ? HP.number(this.eventsTotal) : '' },
        { id: 'honeypots', label: 'Ловушки', icon: 'i-server', badge: this.honeypots.length ? String(this.honeypots.length) : '' },
        { id: 'map', label: 'Карта атак', icon: 'i-globe', badge: this.stats.geo_points.length ? String(this.stats.geo_points.length) : '' }
      ];
    },

    pageTitle() {
      return {
        overview: 'Обзор SOC',
        events: 'Журнал событий',
        honeypots: 'Ловушки',
        map: 'Карта атак'
      }[this.tab] || 'SOC Dashboard';
    },

    go(tab) {
      this.tab = tab;
      this.sidebarOpen = false;
    },

    onTabChange() {
      if (this.tab === 'overview') {
        this.renderCharts();
        setTimeout(() => this.resizeCharts(), 60);
      }
      if (this.tab === 'map') {
        this.renderMap();
        setTimeout(() => this.resizeCharts(), 60);
      }
      if (this.tab === 'events' && !this.events.length) this.loadEvents();
      if (this.tab === 'honeypots' && !this.honeypots.length) this.loadHoneypots();
    },

    rel(value) {
      void this.tick;
      return HP.relative(value);
    },

    runningHoneypots() {
      return this.honeypots.filter((hp) => hp.status === 'running').length;
    },

    criticalCount() {
      const found = this.stats.severity_distribution.find((item) => item.severity === 'critical');
      return found ? Number(found.count) : 0;
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

    mitrePct(count) {
      const values = this.stats.top_mitre.map((item) => Number(item.count) || 0);
      const max = Math.max(...values, 1);
      return Math.max(8, Math.round((Number(count) || 0) / max * 100));
    },

    countryPct(count) {
      const values = this.stats.top_countries.map((item) => Number(item.count) || 0);
      const max = Math.max(...values, 1);
      return Math.max(6, Math.round((Number(count) || 0) / max * 100));
    },

    async loadAll() {
      await Promise.allSettled([
        this.loadStats(),
        this.loadEvents(),
        this.loadHoneypots(),
        this.checkHealth()
      ]);
      this.$nextTick(() => this.renderCharts());
    },

    async loadStats(silent = false) {
      try {
        const stats = await HP.api('/api/v1/events/stats');
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
        this.eventTypes = [...new Set([
          ...this.eventTypes,
          ...this.stats.top_event_types.map((item) => item.event_type)
        ])].filter(Boolean);

        if (this.tab === 'overview') this.$nextTick(() => this.renderCharts());
        if (this.tab === 'map') this.$nextTick(() => this.renderMap());
      } catch (error) {
        if (!silent) HP.toast(error.message, 'error', 'Статистика');
      }
    },

    async loadEvents() {
      this.loadingEvents = true;
      try {
        const query = HP.buildQuery({
          page: this.page,
          limit: this.limit,
          ...this.filters
        });
        const data = await HP.api(`/api/v1/events/${query}`);
        this.events = data.items || [];
        this.eventsTotal = data.total || 0;
        this.pages = data.pages || 0;
        if (this.page > 1 && this.page > this.pages && this.pages > 0) {
          this.page = this.pages;
          return this.loadEvents();
        }
        if (!this.liveEvents.length) {
          this.liveEvents = this.events.slice(0, 8);
        }
      } catch (error) {
        HP.toast(error.message, 'error', 'События');
      } finally {
        this.loadingEvents = false;
      }
    },

    async loadHoneypots() {
      this.hpLoading = true;
      try {
        const data = await HP.api('/api/v1/honeypots/?limit=200');
        this.honeypots = data.items || [];
      } catch (error) {
        HP.toast(error.message, 'error', 'Ловушки');
      } finally {
        this.hpLoading = false;
      }
    },

    async checkHealth() {
      try {
        this.health = await HP.api('/api/v1/health');
      } catch (_) {
        this.health = {
          status: 'degraded',
          checks: { app: false, mongo: false, rabbitmq: false, redis: false }
        };
      }
    },

    async refreshAll() {
      this.refreshing = true;
      await this.loadAll();
      this.refreshing = false;
      HP.toast('Данные обновлены', 'success', 'Обновление');
    },

    applyFilters() {
      this.page = 1;
      this.loadEvents();
    },

    resetFilters() {
      this.filters = { src_ip: '', severity: '', event_type: '', honeypot_id: '' };
      this.page = 1;
      this.loadEvents();
    },

    goPage(page) {
      const target = Math.min(Math.max(1, page), Math.max(1, this.pages));
      if (target === this.page) return;
      this.page = target;
      this.loadEvents();
    },

    pageWindow() {
      const total = Math.max(1, this.pages);
      let start = Math.max(1, this.page - 2);
      const end = Math.min(total, start + 4);
      start = Math.max(1, end - 4);
      const pages = [];
      for (let p = start; p <= end; p += 1) pages.push(p);
      return pages;
    },

    exportEvents() {
      HP.downloadJSON(
        { exported_at: new Date().toISOString(), filters: this.filters, items: this.events },
        `honeypot-events-page-${this.page}.json`
      );
      HP.toast('Текущая страница выгружена в JSON', 'success', 'Экспорт');
    },

    openEvent(event) {
      this.selectedEvent = event;
      this.eventModal = true;
    },

    payloadJson() {
      try {
        return JSON.stringify(this.selectedEvent?.payload ?? {}, null, 2);
      } catch (_) {
        return '{}';
      }
    },

    copyPayload() {
      HP.copy(this.payloadJson()).then((ok) => {
        HP.toast(ok ? 'Payload скопирован' : 'Не удалось скопировать', ok ? 'success' : 'error');
      });
    },

    copyRaw() {
      HP.copy(this.selectedEvent?.raw_log || '').then((ok) => {
        HP.toast(ok ? 'Raw log скопирован' : 'Не удалось скопировать', ok ? 'success' : 'error');
      });
    },

    /* ---------------- WebSocket ---------------- */
    connectSocket() {
      if (typeof io !== 'function') {
        HP.toast('Socket.IO клиент не загрузился', 'warning', 'Realtime');
        return;
      }
      const socket = io('/live', {
        path: '/socket.io',
        transports: ['websocket', 'polling'],
        reconnection: true,
        reconnectionDelay: 1500
      });

      socket.on('connect', () => {
        this.wsConnected = true;
      });

      socket.on('disconnect', () => {
        this.wsConnected = false;
      });

      socket.on('new_event', (event) => this.onNewEvent(event));
      this.ws = socket;
    },

    onNewEvent(event) {
      if (!event) return;
      this.liveEvents.unshift(event);
      this.liveEvents = this.liveEvents.slice(0, 40);

      if (this.tab === 'events' && this.page === 1 && this.matchesFilters(event)) {
        this.events.unshift(event);
        this.events = this.events.slice(0, this.limit);
        this.eventsTotal += 1;
      }

      if (event.severity === 'critical') {
        HP.toast(
          `${HP.eventLabel(event.event_type)} · ${event.src_ip || 'internal'}`,
          'error',
          'Критическое событие'
        );
      }

      this.refreshStatsSoon();
    },

    matchesFilters(event) {
      const f = this.filters;
      if (f.severity && event.severity !== f.severity) return false;
      if (f.src_ip && !String(event.src_ip || '').includes(f.src_ip)) return false;
      if (f.event_type && event.event_type !== f.event_type) return false;
      if (f.honeypot_id && event.honeypot_id !== f.honeypot_id) return false;
      return true;
    },

    refreshStatsSoon() {
      if (!this._refreshStatsDebounced) {
        this._refreshStatsDebounced = HP.debounce(() => this.loadStats(true), 1200);
      }
      this._refreshStatsDebounced();
    },

    /* ---------------- Charts ---------------- */
    chartBase() {
      return {
        backgroundColor: 'transparent',
        textStyle: { fontFamily: 'Manrope, sans-serif', color: '#94a3b8' },
        animationDuration: 650,
        tooltip: {
          backgroundColor: 'rgba(7,11,20,.96)',
          borderColor: 'rgba(148,163,184,.2)',
          borderWidth: 1,
          padding: [10, 12],
          textStyle: { color: '#e2e8f0', fontSize: 11, fontFamily: 'Manrope, sans-serif' },
          extraCssText: 'border-radius:12px;box-shadow:0 18px 40px -18px rgba(0,0,0,.9);'
        }
      };
    },

    renderCharts() {
      if (typeof echarts === 'undefined') return;
      this.renderTimeline();
      this.renderSeverity();
      this.renderTopIps();
      this.renderEventTypes();
      setTimeout(() => this.resizeCharts(), 80);
    },

    renderTimeline() {
      const element = this.$refs.timelineChart;
      const chart = dashboardChart('timeline', element);
      if (!chart) return;

      const data = this.stats.timeline_24h || [];
      const labels = data.map((item) => HP.hourLabel(item.hour));
      const values = data.map((item) => Number(item.count) || 0);

      chart.setOption({
        ...this.chartBase(),
        grid: { left: 42, right: 18, top: 20, bottom: 32 },
        tooltip: {
          ...this.chartBase().tooltip,
          trigger: 'axis',
          axisPointer: { type: 'line', lineStyle: { color: 'rgba(34,211,238,.35)' } },
          formatter: (params) => {
            const point = params[0] || {};
            return `<div style="font-size:10px;color:#64748b">${HP.escapeHtml(point.axisValue || '')}</div>
              <div style="margin-top:4px;font-weight:700;color:#e2e8f0">${HP.escapeHtml(String(point.value ?? 0))} событий</div>`;
          }
        },
        xAxis: {
          type: 'category',
          boundaryGap: false,
          data: labels,
          axisLine: { lineStyle: { color: 'rgba(148,163,184,.12)' } },
          axisTick: { show: false },
          axisLabel: { color: '#5f7089', fontSize: 9, interval: 2 }
        },
        yAxis: {
          type: 'value',
          minInterval: 1,
          axisLabel: { color: '#5f7089', fontSize: 9 },
          splitLine: { lineStyle: { color: 'rgba(148,163,184,.07)' } }
        },
        series: [{
          name: 'События',
          type: 'line',
          smooth: true,
          symbol: 'none',
          data: values,
          lineStyle: { width: 2, color: '#22d3ee', shadowColor: 'rgba(34,211,238,.45)', shadowBlur: 12 },
          areaStyle: {
            color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
              { offset: 0, color: 'rgba(34,211,238,.30)' },
              { offset: 1, color: 'rgba(34,211,238,.01)' }
            ])
          }
        }]
      }, true);
    },

    renderSeverity() {
      const element = this.$refs.severityChart;
      const chart = dashboardChart('severity', element);
      if (!chart) return;

      const raw = this.stats.severity_distribution || [];
      const total = raw.reduce((sum, item) => sum + Number(item.count || 0), 0);
      const data = raw.map((item) => {
        const meta = HP.severityMeta(item.severity);
        return { value: Number(item.count) || 0, name: meta.label, itemStyle: { color: meta.color } };
      });

      chart.setOption({
        ...this.chartBase(),
        title: {
          text: HP.number(total),
          subtext: 'событий',
          left: 'center',
          top: '33%',
          textStyle: { color: '#f8fafc', fontSize: 26, fontWeight: 800, fontFamily: 'Manrope' },
          subtextStyle: { color: '#64748b', fontSize: 10, fontFamily: 'Manrope' }
        },
        tooltip: {
          ...this.chartBase().tooltip,
          trigger: 'item',
          formatter: (params) => `<div style="font-weight:700;color:#e2e8f0">${HP.escapeHtml(params.name)}</div>
            <div style="margin-top:2px;color:#94a3b8">${HP.number(params.value)} · ${params.percent}%</div>`
        },
        series: [{
          type: 'pie',
          radius: ['62%', '82%'],
          center: ['50%', '43%'],
          avoidLabelOverlap: true,
          padAngle: 4,
          itemStyle: { borderColor: '#080d18', borderWidth: 3, borderRadius: 6 },
          label: { show: false },
          emphasis: { scale: true, scaleSize: 5 },
          data
        }]
      }, true);
    },

    renderTopIps() {
      const element = this.$refs.ipChart;
      const chart = dashboardChart('ips', element);
      if (!chart) return;

      const raw = (this.stats.top_src_ip || []).slice(0, 7).slice().reverse();
      const categories = raw.map((item) => item.src_ip);
      const values = raw.map((item) => Number(item.count) || 0);

      chart.setOption({
        ...this.chartBase(),
        grid: { left: 112, right: 26, top: 8, bottom: 12 },
        tooltip: {
          ...this.chartBase().tooltip,
          trigger: 'axis',
          axisPointer: { type: 'shadow', shadowStyle: { color: 'rgba(34,211,238,.05)' } },
          formatter: (params) => `<div style="font-weight:700;color:#e2e8f0">${HP.escapeHtml(params[0]?.axisValue || '')}</div>
            <div style="margin-top:2px;color:#94a3b8">${HP.number(params[0]?.value || 0)} событий</div>`
        },
        xAxis: { type: 'value', show: false },
        yAxis: {
          type: 'category',
          data: categories,
          axisLine: { show: false },
          axisTick: { show: false },
          axisLabel: { color: '#7c8ca5', fontSize: 9, fontFamily: 'JetBrains Mono' }
        },
        series: [{
          type: 'bar',
          data: values,
          barWidth: 9,
          itemStyle: {
            borderRadius: [0, 6, 6, 0],
            color: new echarts.graphic.LinearGradient(0, 0, 1, 0, [
              { offset: 0, color: 'rgba(34,211,238,.25)' },
              { offset: 1, color: '#22d3ee' }
            ])
          },
          label: { show: true, position: 'right', color: '#94a3b8', fontSize: 9, fontFamily: 'JetBrains Mono' }
        }]
      }, true);
    },

    renderEventTypes() {
      const element = this.$refs.typeChart;
      const chart = dashboardChart('types', element);
      if (!chart) return;

      const raw = (this.stats.top_event_types || []).slice(0, 7).slice().reverse();
      const categories = raw.map((item) => HP.eventLabel(item.event_type));
      const values = raw.map((item) => Number(item.count) || 0);

      chart.setOption({
        ...this.chartBase(),
        grid: { left: 100, right: 28, top: 8, bottom: 12 },
        tooltip: {
          ...this.chartBase().tooltip,
          trigger: 'axis',
          axisPointer: { type: 'shadow', shadowStyle: { color: 'rgba(139,92,246,.06)' } },
          formatter: (params) => `<div style="font-weight:700;color:#e2e8f0">${HP.escapeHtml(params[0]?.axisValue || '')}</div>
            <div style="margin-top:2px;color:#94a3b8">${HP.number(params[0]?.value || 0)} событий</div>`
        },
        xAxis: { type: 'value', show: false },
        yAxis: {
          type: 'category',
          data: categories,
          axisLine: { show: false },
          axisTick: { show: false },
          axisLabel: { color: '#7c8ca5', fontSize: 9 }
        },
        series: [{
          type: 'bar',
          data: values,
          barWidth: 9,
          itemStyle: {
            borderRadius: [0, 6, 6, 0],
            color: new echarts.graphic.LinearGradient(0, 0, 1, 0, [
              { offset: 0, color: 'rgba(139,92,246,.25)' },
              { offset: 1, color: '#8b5cf6' }
            ])
          },
          label: { show: true, position: 'right', color: '#94a3b8', fontSize: 9, fontFamily: 'JetBrains Mono' }
        }]
      }, true);
    },

    async renderMap() {
      if (typeof echarts === 'undefined') return;
      const element = this.$refs.mapChart;
      if (!element) return;

      if (!this.mapLoaded) {
        try {
          const response = await fetch('/static/data/world.json');
          if (!response.ok) throw new Error('map data');
          const geoJson = await response.json();
          echarts.registerMap('world', geoJson);
          this.mapLoaded = true;
        } catch (error) {
          HP.toast('Не удалось загрузить карту мира', 'error', 'Карта');
          return;
        }
      }

      const chart = dashboardChart('map', element);
      if (!chart) return;

      const points = (this.stats.geo_points || []).map((point) => ({
        name: point.country || 'Unknown',
        value: [Number(point.lon), Number(point.lat), Number(point.count) || 1, point.city || '', point.country || ''],
        symbolSize: Math.min(24, 7 + Math.sqrt(Number(point.count) || 1) * 3)
      }));

      chart.setOption({
        ...this.chartBase(),
        backgroundColor: 'transparent',
        tooltip: {
          ...this.chartBase().tooltip,
          trigger: 'item',
          formatter: (params) => {
            const value = params.value || [];
            return `<div style="font-weight:700;color:#e2e8f0">${HP.escapeHtml(value[4] || params.name || '')}</div>
              <div style="color:#94a3b8;margin-top:2px">${HP.escapeHtml(value[3] || '')}</div>
              <div style="color:#fb7185;margin-top:4px;font-weight:700">${HP.number(value[2] || 0)} событий</div>`;
          }
        },
        geo: {
          map: 'world',
          roam: false,
          zoom: 1.16,
          silent: true,
          itemStyle: {
            areaColor: '#0b1526',
            borderColor: 'rgba(56,189,248,.16)',
            borderWidth: 0.7
          },
          emphasis: {
            itemStyle: { areaColor: '#12233d' },
            label: { show: false }
          }
        },
        series: [{
          name: 'Источники атак',
          type: 'effectScatter',
          coordinateSystem: 'geo',
          data: points,
          rippleEffect: { brushType: 'stroke', scale: 2.8, period: 4 },
          itemStyle: {
            color: '#fb7185',
            shadowBlur: 12,
            shadowColor: 'rgba(251,113,133,.75)'
          },
          label: {
            show: points.length <= 8,
            position: 'right',
            formatter: (params) => params.value[4] || '',
            color: '#94a3b8',
            fontSize: 9
          },
          labelLayout: { hideOverlap: true },
          emphasis: { scale: 1.3 }
        }]
      }, true);
      setTimeout(() => chart.resize(), 60);
    },

    resizeCharts() {
      Object.values(DASHBOARD_CHARTS).forEach((chart) => {
        if (chart && !chart.isDisposed()) chart.resize();
      });
    }
  };
}
