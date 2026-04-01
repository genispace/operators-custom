'use strict';

/**
 * 消息列表 Artifact 内联天气卡片（与 WeatherWidget 布局一致，内联样式以便远程 eval 不受 Tailwind 扫描影响）。
 * props: { event, compact?, config?: { locale, theme } }
 * i18n: plugin/locales/*.json — npm run build:plugins prepends __PLUGIN_I18N + __gsPluginT.
 */

function tt(p, k) {
  return __gsPluginT(__PLUGIN_I18N, p, k);
}

function round(v) {
  return v != null && !isNaN(v) ? Math.round(Number(v)) : '--';
}

function weatherEmoji(code) {
  if (code == null) return '☁️';
  if (code === 0) return '☀️';
  if (code <= 3) return '⛅';
  if (code <= 48) return '🌫️';
  if (code <= 67) return '🌧️';
  if (code <= 77) return '❄️';
  if (code <= 86) return '🌨️';
  return '⛈️';
}

function unwrapSuccessEnvelope(obj) {
  var cur = obj;
  while (cur && typeof cur === 'object' && cur.success === true && cur.data != null && typeof cur.data === 'object' && !Array.isArray(cur.data)) {
    cur = cur.data;
  }
  return cur;
}

function parseWeatherPayload(raw) {
  if (raw == null) return { kind: 'none' };
  var obj = raw;
  if (typeof raw === 'string') {
    try {
      obj = JSON.parse(raw);
    } catch (_e) {
      return { kind: 'none' };
    }
  }
  if (!obj || typeof obj !== 'object') return { kind: 'none' };
  if (Array.isArray(obj) && obj[0] && obj[0].text) return parseWeatherPayload(obj[0].text);
  if (obj.data && Array.isArray(obj.data) && obj.data[0] && obj.data[0].text) return parseWeatherPayload(obj.data[0].text);
  var inner = obj.result && obj.result.content && obj.result.content[0];
  if (inner && inner.text) return parseWeatherPayload(inner.text);
  inner = obj.data && obj.data.result && obj.data.result.content && obj.data.result.content[0];
  if (inner && inner.text) return parseWeatherPayload(inner.text);

  if (obj.operatorId != null || obj.methodId != null) {
    if (obj.data != null && typeof obj.data === 'object' && !Array.isArray(obj.data)) {
      obj = obj.data;
    }
  }

  obj = unwrapSuccessEnvelope(obj);

  if (obj && typeof obj === 'object' && obj.ok === false) {
    return {
      kind: 'business_error',
      code: obj.error_code || 'UNKNOWN',
      message: obj.error_message || '',
      details: obj.error_details && typeof obj.error_details === 'object' ? obj.error_details : null
    };
  }
  if (obj && typeof obj === 'object' && obj.current && typeof obj.current === 'object' && obj.ok !== false) {
    return { kind: 'ok', body: obj };
  }
  return { kind: 'none' };
}

function errHintKey(code) {
  if (code === 'INVALID_INPUT' || code === 'NOT_FOUND' || code === 'UPSTREAM_ERROR') return 'err_hint_' + code;
  return 'err_hint_generic';
}

function parseFromEvent(event) {
  var r = event && event.metadata && event.metadata.result;
  if (!r) return { kind: 'none' };
  if (r.success === false) {
    return { kind: 'tool_failed', message: (r.error && String(r.error)) || 'Tool failed' };
  }
  var content = r.result && r.result.content && r.result.content[0];
  if (!content || !content.text) return { kind: 'none' };
  var parsed;
  try {
    parsed = JSON.parse(content.text);
  } catch (_e) {
    return { kind: 'none' };
  }
  return parseWeatherPayload(parsed);
}

function formatDay(p, dateStr) {
  try {
    var d = new Date(dateStr + 'T00:00:00');
    var today = new Date();
    today.setHours(0, 0, 0, 0);
    var diff = (d.getTime() - today.getTime()) / 86400000;
    var locIx = __gsPluginLocaleIndex(p, __PLUGIN_I18N);
    if (String(locIx || '').toLowerCase().split('-')[0] === 'zh') {
      if (diff >= 0 && diff < 1) return '今天';
      if (diff >= 1 && diff < 2) return '明天';
      return d.toLocaleDateString('zh-CN', { weekday: 'short' });
    }
    if (diff >= 0 && diff < 1) return 'Today';
    if (diff >= 1 && diff < 2) return 'Tomorrow';
    return d.toLocaleDateString('en-US', { weekday: 'short' });
  } catch (_e) {
    return dateStr;
  }
}

function tempPercent(val, gMin, gMax) {
  if (gMax === gMin) return 50;
  return ((val - gMin) / (gMax - gMin)) * 100;
}

function detailChip(React, Lucide, dark, iconName, label, value) {
  var Icon = Lucide[iconName] || Lucide.Circle;
  var muted = dark ? 'rgba(148,163,184,0.95)' : 'rgba(100,116,139,0.95)';
  var fg = dark ? '#f1f5f9' : '#0f172a';
  return React.createElement(
    'div',
    {
      style: {
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        gap: 4,
        padding: '6px 4px',
        borderRadius: 8,
        background: dark ? 'rgba(255,255,255,0.06)' : 'rgba(0,0,0,0.04)'
      }
    },
    React.createElement('div', { style: { color: muted } }, React.createElement(Icon, { size: 14, strokeWidth: 1.75 })),
    React.createElement('span', { style: { fontSize: 10, color: muted, lineHeight: 1 } }, label),
    React.createElement('span', { style: { fontSize: 12, fontWeight: 600, color: fg, fontVariantNumeric: 'tabular-nums', lineHeight: 1 } }, value)
  );
}

module.exports.default = function WeatherForecastArtifactWidget(props) {
  var React = require('react');
  var Lucide = require('lucide-react');
  var dark = props.config && props.config.theme === 'dark';
  var muted = dark ? '#94a3b8' : '#64748b';
  var fg = dark ? '#e2e8f0' : '#334155';
  var border = dark ? 'rgba(255,255,255,0.12)' : 'rgba(0,0,0,0.08)';

  var parsed = parseFromEvent(props.event);

  if (parsed.kind === 'tool_failed') {
    return React.createElement(
      'div',
      { style: { fontSize: 12, color: dark ? '#fca5a5' : '#b91c1c', padding: '4px 0' } },
      parsed.message
    );
  }

  if (parsed.kind === 'business_error') {
    var hint = tt(props, errHintKey(parsed.code));
    var detailsStr = '';
    try {
      detailsStr = parsed.details ? JSON.stringify(parsed.details) : '';
    } catch (_e) {
      detailsStr = '';
    }
    var amberBg = dark ? 'rgba(120,53,15,0.35)' : '#fffbeb';
    var amberBorder = dark ? 'rgba(251,191,36,0.4)' : '#fcd34d';
    var amberText = dark ? '#fde68a' : '#92400e';
    return React.createElement(
      'div',
      {
        style: {
          borderRadius: 12,
          padding: 12,
          border: '1px solid ' + amberBorder,
          background: amberBg,
          color: amberText,
          fontSize: 12
        }
      },
      React.createElement('div', { style: { fontWeight: 700, marginBottom: 6 } }, tt(props, 'err_title')),
      React.createElement('div', { style: { fontSize: 11, marginBottom: 4 } }, tt(props, 'err_code_label') + ': ' + String(parsed.code)),
      React.createElement('div', { style: { marginBottom: 8, lineHeight: 1.45, whiteSpace: 'pre-wrap' } }, parsed.message || hint),
      React.createElement('div', { style: { fontSize: 11, opacity: 0.95 } }, hint),
      detailsStr
        ? React.createElement('pre', {
            style: {
              marginTop: 8,
              marginBottom: 0,
              padding: 8,
              borderRadius: 6,
              fontSize: 10,
              background: dark ? 'rgba(0,0,0,0.25)' : 'rgba(255,255,255,0.7)',
              color: dark ? '#e2e8f0' : '#334155'
            }
          }, tt(props, 'err_details') + ': ' + detailsStr)
        : null
    );
  }

  if (parsed.kind !== 'ok' || !parsed.body || !parsed.body.current) {
    return React.createElement('div', { style: { fontSize: 13, color: muted, padding: '4px 0' } }, tt(props, 'no_data'));
  }

  var d = parsed.body;
  var cur = d.current;
  var loc = d.location || {};
  var daily = d.daily || [];
  var today = daily[0];

  var allMins = daily.map(function (x) { return x.temp_min; }).filter(function (x) { return x != null; });
  var allMaxs = daily.map(function (x) { return x.temp_max; }).filter(function (x) { return x != null; });
  var gMin = allMins.length ? Math.min.apply(null, allMins) : 0;
  var gMax = allMaxs.length ? Math.max.apply(null, allMaxs) : 30;

  var locLine = [loc.name, loc.admin && loc.admin !== loc.name ? loc.admin : null].filter(Boolean).join(', ') || '—';

  return React.createElement(
    'div',
    { style: { userSelect: 'none', fontFamily: 'system-ui, sans-serif' } },
    React.createElement(
      'div',
      { style: { display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 12, marginBottom: 16 } },
      React.createElement(
        'div',
        { style: { minWidth: 0 } },
        React.createElement('p', { style: { fontSize: 11, color: muted, margin: '0 0 4px 0', lineHeight: 1.2 } }, locLine),
        React.createElement(
          'div',
          { style: { display: 'flex', alignItems: 'baseline', gap: 4 } },
          React.createElement(
            'span',
            { style: { fontSize: 30, fontWeight: 200, fontVariantNumeric: 'tabular-nums', letterSpacing: '-0.02em', color: fg, lineHeight: 1 } },
            String(round(cur.temperature)) + '°'
          )
        ),
        React.createElement('p', { style: { fontSize: 12, color: muted, margin: '4px 0 0 0' } }, cur.weather_description || ''),
        today
          ? React.createElement(
              'p',
              { style: { fontSize: 11, color: muted, margin: '6px 0 0 0', opacity: 0.85 } },
              tt(props, 'high_low') + ': ' + String(round(today.temp_max)) + '° / ' + String(round(today.temp_min)) + '°'
            )
          : null
      ),
      React.createElement(
        'div',
        { style: { flexShrink: 0, marginTop: 2, lineHeight: 1, opacity: 0.95 } },
        React.createElement('span', { style: { fontSize: 40, lineHeight: 1 } }, weatherEmoji(cur.weather_code))
      )
    ),
    React.createElement(
      'div',
      { style: { display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 8, marginBottom: 16 } },
      detailChip(React, Lucide, dark, 'Thermometer', tt(props, 'feels_like'), String(round(cur.apparent_temperature)) + '°'),
      detailChip(React, Lucide, dark, 'Droplets', tt(props, 'humidity'), (cur.humidity != null ? cur.humidity : '--') + '%'),
      detailChip(React, Lucide, dark, 'Wind', tt(props, 'wind'), String(round(cur.wind_speed)) + ' ' + (cur.wind_speed_unit || 'km/h'))
    ),
    daily.length > 0
      ? React.createElement(
          'div',
          { style: { borderTop: '1px solid ' + border, paddingTop: 12 } },
          React.createElement(
            'div',
            { style: { display: 'flex', flexDirection: 'column', gap: 8 } },
            daily.map(function (day, idx) {
              var lo = day.temp_min != null ? day.temp_min : gMin;
              var hi = day.temp_max != null ? day.temp_max : gMax;
              var barLeft = tempPercent(lo, gMin, gMax);
              var barRight = 100 - tempPercent(hi, gMin, gMax);
              return React.createElement(
                'div',
                {
                  key: day.date || idx,
                  style: {
                    display: 'grid',
                    alignItems: 'center',
                    gap: 8,
                    gridTemplateColumns: '2.8rem 1.25rem 1.5rem 1fr 1.5rem',
                    fontSize: 12,
                    color: fg
                  }
                },
                React.createElement(
                  'span',
                  { style: { fontVariantNumeric: 'tabular-nums', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', fontWeight: idx === 0 ? 600 : 400, color: idx === 0 ? fg : muted } },
                  formatDay(props, day.date)
                ),
                React.createElement(
                  'div',
                  { style: { display: 'flex', justifyContent: 'center', alignItems: 'center', color: muted } },
                  React.createElement('span', { style: { fontSize: 16, lineHeight: 1 } }, weatherEmoji(day.weather_code))
                ),
                React.createElement('span', { style: { textAlign: 'right', fontVariantNumeric: 'tabular-nums', color: muted, fontSize: 11 } }, String(round(lo)) + '°'),
                React.createElement(
                  'div',
                  { style: { height: 4, borderRadius: 999, background: dark ? 'rgba(255,255,255,0.1)' : 'rgba(0,0,0,0.08)', position: 'relative', overflow: 'hidden' } },
                  React.createElement('div', {
                    style: {
                      position: 'absolute',
                      top: 0,
                      bottom: 0,
                      left: barLeft + '%',
                      right: barRight + '%',
                      borderRadius: 999,
                      background: 'linear-gradient(90deg,#60a5fa,#fbbf24,#fb923c)'
                    }
                  })
                ),
                React.createElement('span', { style: { fontVariantNumeric: 'tabular-nums', fontWeight: 600, textAlign: 'right' } }, String(round(hi)) + '°')
              );
            })
          )
        )
      : null,
    d.timezone
      ? React.createElement('p', { style: { fontSize: 10, color: muted, marginTop: 8, marginBottom: 0 } }, d.timezone)
      : null
  );
};
