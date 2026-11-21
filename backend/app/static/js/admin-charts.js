/* Honeypot Orchestrator — Admin charts */
/* global echarts, HP */

const ADMIN_CHARTS = {};

function adminChart(key, element) {
  if (!element) return null;
  const existing = ADMIN_CHARTS[key];
  if (existing && !existing.isDisposed()) return existing;
  const chart = echarts.init(element, null, { renderer: 'canvas' });
  ADMIN_CHARTS[key] = chart;
  return chart;
}

window.AdminCharts = {
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

  renderAdminCharts() {
    if (typeof echarts === 'undefined') return;
    this.renderAdminTimeline();
    this.renderAdminSeverity();
    setTimeout(() => this.resizeAdminCharts(), 80);
  },

  renderAdminTimeline() {
    const element = this.$refs.adminTimelineChart;
    const chart = adminChart('timeline', element);
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
        axisPointer: { type: 'line', lineStyle: { color: 'rgba(139,92,246,.4)' } },
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
        lineStyle: { width: 2, color: '#8b5cf6', shadowColor: 'rgba(139,92,246,.45)', shadowBlur: 12 },
        areaStyle: {
          color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
            { offset: 0, color: 'rgba(139,92,246,.32)' },
            { offset: 1, color: 'rgba(139,92,246,.01)' }
          ])
        }
      }]
    }, true);
  },

  renderAdminSeverity() {
    const element = this.$refs.adminSeverityChart;
    const chart = adminChart('severity', element);
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
        top: '34%',
        textStyle: { color: '#f8fafc', fontSize: 25, fontWeight: 800, fontFamily: 'Manrope' },
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
        center: ['50%', '44%'],
        avoidLabelOverlap: true,
        padAngle: 4,
        itemStyle: { borderColor: '#080d18', borderWidth: 3, borderRadius: 6 },
        label: { show: false },
        emphasis: { scale: true, scaleSize: 5 },
        data
      }]
    }, true);
  },

  resizeAdminCharts() {
    Object.values(ADMIN_CHARTS).forEach((chart) => {
      if (chart && !chart.isDisposed()) chart.resize();
    });
  }
};
