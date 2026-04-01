'use strict';

// i18n: plugin/locales/*.json — npm run build:plugins prepends __PLUGIN_I18N + __gsPluginT.

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

/**
 * 从 props.data 解析：业务错误（ok===false）、成功天气体、或历史嵌套 JSON。
 * 返回 { kind: 'ok', body } | { kind: 'business_error', code, message, details } | { kind: 'none' }。
 */
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

module.exports.default = function WeatherRemote(props) {
  var React = require('react');
  var R = React;
  var dark = props.config && props.config.theme === 'dark';
  var parsed = parseWeatherPayload(props.data);

  if (props.error || !props.success) {
    return R.createElement(
      'div',
      { style: { borderRadius: 16, padding: 20, background: dark ? 'rgba(127,29,29,0.3)' : '#fef2f2', color: dark ? '#fecaca' : '#b91c1c', fontSize: 14 } },
      props.error || 'Error'
    );
  }

  if (parsed.kind === 'business_error') {
    var amberBg = dark ? 'rgba(120,53,15,0.35)' : '#fffbeb';
    var amberBorder = dark ? 'rgba(251,191,36,0.4)' : '#fcd34d';
    var amberText = dark ? '#fde68a' : '#92400e';
    var hint = tt(props, errHintKey(parsed.code));
    var detailsStr = '';
    try {
      detailsStr = parsed.details ? JSON.stringify(parsed.details, null, 0) : '';
    } catch (_e) {
      detailsStr = '';
    }
    return R.createElement(
      'div',
      {
        style: {
          borderRadius: 16,
          padding: 20,
          border: '1px solid ' + amberBorder,
          background: amberBg,
          color: amberText,
          fontSize: 14,
          fontFamily: 'system-ui,sans-serif'
        }
      },
      R.createElement('div', { style: { fontWeight: 700, marginBottom: 8, fontSize: 15 } }, tt(props, 'err_title')),
      R.createElement('div', { style: { fontSize: 12, opacity: 0.95, marginBottom: 6 } }, tt(props, 'err_code_label') + ': ' + String(parsed.code)),
      R.createElement('div', { style: { marginBottom: 10, lineHeight: 1.5, whiteSpace: 'pre-wrap' } }, parsed.message || hint),
      R.createElement('div', { style: { fontSize: 12, opacity: 0.9, lineHeight: 1.45 } }, hint),
      detailsStr
        ? R.createElement(
            'pre',
            {
              style: {
                marginTop: 12,
                marginBottom: 0,
                padding: 10,
                borderRadius: 8,
                fontSize: 11,
                overflow: 'auto',
                background: dark ? 'rgba(0,0,0,0.25)' : 'rgba(255,255,255,0.7)',
                color: dark ? '#e2e8f0' : '#334155'
              }
            },
            tt(props, 'err_details') + ': ' + detailsStr
          )
        : null
    );
  }

  if (parsed.kind !== 'ok' || !parsed.body || !parsed.body.current) {
    return R.createElement('div', { style: { padding: 20, color: dark ? '#94a3b8' : '#64748b', fontSize: 14 } }, tt(props, 'no_data'));
  }

  var d = parsed.body;
  var cur = d.current;
  var loc = d.location || {};
  var daily = d.daily || [];
  var today = daily[0];
  var C = { card: dark ? '#0f172a' : '#fff', border: dark ? 'rgba(255,255,255,0.1)' : '#e2e8f0', muted: dark ? '#94a3b8' : '#64748b' };

  var allMins = daily.map(function (x) { return x.temp_min; }).filter(function (x) { return x != null; });
  var allMaxs = daily.map(function (x) { return x.temp_max; }).filter(function (x) { return x != null; });
  var gMin = allMins.length ? Math.min.apply(null, allMins) : 0;
  var gMax = allMaxs.length ? Math.max.apply(null, allMaxs) : 30;

  function tempPct(val) {
    if (gMax === gMin) return 50;
    return ((val - gMin) / (gMax - gMin)) * 100;
  }

  function detailCard(title, value, sub) {
    return R.createElement(
      'div',
      {
        style: {
          borderRadius: 14,
          padding: 12,
          border: '1px solid ' + C.border,
          background: dark ? 'rgba(255,255,255,0.03)' : '#f8fafc'
        }
      },
      R.createElement('div', { style: { fontSize: 11, color: C.muted, marginBottom: 4 } }, title),
      R.createElement('div', { style: { fontSize: 18, fontWeight: 700, color: dark ? '#f1f5f9' : '#0f172a' } }, value),
      sub ? R.createElement('div', { style: { fontSize: 10, color: C.muted, marginTop: 4 } }, sub) : null
    );
  }

  return R.createElement(
    'div',
    { style: { fontFamily: 'system-ui,sans-serif', display: 'flex', flexDirection: 'column', gap: 16 } },
    R.createElement(
      'div',
      {
        style: {
          position: 'relative',
          borderRadius: 16,
          overflow: 'hidden',
          padding: 24,
          color: '#fff',
          background: 'linear-gradient(135deg, #0ea5e9 0%, #6366f1 50%, #8b5cf6 100%)'
        }
      },
      R.createElement('div', { style: { fontSize: 13, opacity: 0.9, marginBottom: 8 } }, '📍 ' + [loc.name, loc.country].filter(Boolean).join(', ')),
      R.createElement(
        'div',
        { style: { display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' } },
        R.createElement(
          'div',
          null,
          R.createElement('div', { style: { fontSize: 56, fontWeight: 200, lineHeight: 1 } }, round(cur.temperature) + '°'),
          R.createElement('div', { style: { fontSize: 14, opacity: 0.9, marginTop: 8 } }, cur.weather_description || ''),
          today
            ? R.createElement(
                'div',
                { style: { fontSize: 12, opacity: 0.75, marginTop: 4 } },
                tt(props, 'high_low') + ': ' + round(today.temp_max) + '° / ' + round(today.temp_min) + '°'
              )
            : null
        ),
        R.createElement('div', { style: { fontSize: 56, lineHeight: 1 } }, weatherEmoji(cur.weather_code))
      )
    ),
    R.createElement(
      'div',
      { style: { display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 } },
      detailCard(tt(props, 'feels_like'), round(cur.apparent_temperature) + '°'),
      detailCard(tt(props, 'humidity'), (cur.humidity != null ? cur.humidity : '--') + '%'),
      detailCard(tt(props, 'wind'), round(cur.wind_speed) + ' ' + (cur.wind_speed_unit || 'km/h')),
      today && today.precipitation != null
        ? detailCard(tt(props, 'precip'), today.precipitation + ' ' + (today.precipitation_unit || 'mm'))
        : R.createElement('div', null)
    ),
    daily.length
      ? R.createElement(
          'div',
          { style: { borderRadius: 16, border: '1px solid ' + C.border, background: C.card, overflow: 'hidden' } },
          R.createElement(
            'div',
            { style: { padding: '10px 14px', borderBottom: '1px solid ' + C.border, fontSize: 11, color: C.muted, fontWeight: 600 } },
            '📅 ' + daily.length + ' ' + tt(props, 'forecast_days')
          ),
          daily.map(function (day, idx) {
            var lo = day.temp_min != null ? day.temp_min : gMin;
            var hi = day.temp_max != null ? day.temp_max : gMax;
            var left = tempPct(lo);
            var right = 100 - tempPct(hi);
            return R.createElement(
              'div',
              {
                key: day.date || idx,
                style: {
                  display: 'grid',
                  gridTemplateColumns: '4.5rem 2rem 2rem 1fr 2rem',
                  alignItems: 'center',
                  gap: 8,
                  padding: '10px 14px',
                  borderBottom: idx < daily.length - 1 ? '1px solid ' + C.border : 'none',
                  fontSize: 13,
                  color: dark ? '#e2e8f0' : '#334155'
                }
              },
              R.createElement('div', null, R.createElement('div', { style: { fontWeight: idx === 0 ? 700 : 400 } }, day.date), R.createElement('div', { style: { fontSize: 10, color: C.muted } }, day.weather_description || '')),
              R.createElement('div', { style: { textAlign: 'center' } }, weatherEmoji(day.weather_code)),
              R.createElement('div', { style: { textAlign: 'right', color: C.muted } }, round(lo) + '°'),
              R.createElement(
                'div',
                { style: { height: 6, borderRadius: 999, background: dark ? 'rgba(255,255,255,0.1)' : '#e2e8f0', position: 'relative' } },
                R.createElement('div', {
                  style: {
                    position: 'absolute',
                    top: 0,
                    bottom: 0,
                    left: left + '%',
                    right: right + '%',
                    borderRadius: 999,
                    background: 'linear-gradient(90deg,#60a5fa,#fbbf24,#fb923c)'
                  }
                })
              ),
              R.createElement('div', { style: { fontWeight: 600 } }, round(hi) + '°')
            );
          })
        )
      : null,
    d.timezone
      ? R.createElement('div', { style: { fontSize: 10, color: C.muted, paddingLeft: 4 } }, d.timezone)
      : null
  );
};
