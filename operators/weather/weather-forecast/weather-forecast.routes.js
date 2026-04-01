const express = require('express');
const axios = require('axios');
const { sendSuccessResponse } = require('../../../src/utils/response');

const router = express.Router();

const GEO = 'https://geocoding-api.open-meteo.com/v1/search';
const FORECAST = 'https://api.open-meteo.com/v1/forecast';

// Open-Meteo WMO Weather interpretation codes (WW) — 须与 API 一致，否则插件列表会显示 Unknown
// https://open-meteo.com/en/docs
const WMO = {
  0: 'Clear sky',
  1: 'Mainly clear',
  2: 'Partly cloudy',
  3: 'Overcast',
  45: 'Fog',
  48: 'Depositing rime fog',
  51: 'Light drizzle',
  53: 'Moderate drizzle',
  55: 'Dense drizzle',
  56: 'Light freezing drizzle',
  57: 'Dense freezing drizzle',
  61: 'Slight rain',
  63: 'Moderate rain',
  65: 'Heavy rain',
  66: 'Light freezing rain',
  67: 'Heavy freezing rain',
  71: 'Slight snow fall',
  73: 'Moderate snow fall',
  75: 'Heavy snow fall',
  77: 'Snow grains',
  80: 'Slight rain showers',
  81: 'Moderate rain showers',
  82: 'Violent rain showers',
  85: 'Slight snow showers',
  86: 'Heavy snow showers',
  95: 'Thunderstorm',
  96: 'Thunderstorm with slight hail',
  99: 'Thunderstorm with heavy hail'
};

function wmoLabel(code) {
  if (code == null) return 'Unknown';
  const n = Number(code);
  if (Number.isNaN(n)) return 'Unknown';
  return WMO[n] || 'Unknown';
}

/** 业务失败也走 HTTP 200 + success:true，payload 在 data 内且 ok:false，便于平台把结构化错误交给模型与插件（见 outputSchema）。 */
function sendBusinessOutcome(res, body) {
  return sendSuccessResponse(res, body);
}

router.post('/forecast', async (req, res, next) => {
  try {
    const location = String((req.body && req.body.location) || '').trim();
    if (!location) {
      return sendBusinessOutcome(res, {
        ok: false,
        error_code: 'INVALID_INPUT',
        error_message: 'Location cannot be empty. Provide a non-empty city or place name.',
        error_details: { field: 'location' }
      });
    }
    let days = parseInt((req.body && req.body.days) || 3, 10);
    if (Number.isNaN(days)) days = 3;
    days = Math.min(Math.max(days, 1), 7);

    let place = null;
    for (const lang of [null, 'zh', 'en']) {
      const params = { name: location, count: 1, format: 'json' };
      if (lang) params.language = lang;
      const { data } = await axios.get(GEO, { params, timeout: 10000 });
      if (data.results && data.results[0]) {
        place = data.results[0];
        break;
      }
    }
    if (!place) {
      return sendBusinessOutcome(res, {
        ok: false,
        error_code: 'NOT_FOUND',
        error_message:
          'Could not find a matching place for the given location string. Try a shorter name, admin-level name (e.g. county/city without province prefix), or a well-known English name.',
        error_details: { location_query: location }
      });
    }

    const lat = place.latitude;
    const lon = place.longitude;
    const city_name = place.name || location;
    const country = place.country || '';
    const admin = place.admin1 || '';

    const { data: forecast } = await axios.get(FORECAST, {
      timeout: 15000,
      params: {
        latitude: lat,
        longitude: lon,
        current: 'temperature_2m,relative_humidity_2m,apparent_temperature,weather_code,wind_speed_10m',
        daily: 'weather_code,temperature_2m_max,temperature_2m_min,precipitation_sum,wind_speed_10m_max',
        timezone: 'auto',
        forecast_days: days
      }
    });

    const current = forecast.current || {};
    const daily = forecast.daily || {};
    const du = forecast.daily_units || {};
    const cu = forecast.current_units || {};

    const current_weather = {
      temperature: current.temperature_2m,
      temperature_unit: cu.temperature_2m || '°C',
      apparent_temperature: current.apparent_temperature,
      humidity: current.relative_humidity_2m,
      wind_speed: current.wind_speed_10m,
      wind_speed_unit: cu.wind_speed_10m || 'km/h',
      weather_code: current.weather_code,
      weather_description: wmoLabel(current.weather_code)
    };

    const dates = daily.time || [];
    const daily_forecast = dates.map(function (date, i) {
      const wc = (daily.weather_code || [])[i];
      return {
        date: date,
        temp_max: (daily.temperature_2m_max || [])[i],
        temp_min: (daily.temperature_2m_min || [])[i],
        temp_unit: du.temperature_2m_max || '°C',
        precipitation: (daily.precipitation_sum || [])[i],
        precipitation_unit: du.precipitation_sum || 'mm',
        wind_speed_max: (daily.wind_speed_10m_max || [])[i],
        wind_speed_unit: du.wind_speed_10m_max || 'km/h',
        weather_code: wc,
        weather_description: wmoLabel(wc)
      };
    });

    const weather_data = {
      ok: true,
      location: {
        name: city_name,
        country: country,
        admin: admin,
        latitude: lat,
        longitude: lon
      },
      current: current_weather,
      daily: daily_forecast,
      timezone: forecast.timezone || ''
    };

    // data 即归一化天气 JSON；Chat 插件由算子 chatPluginByMethod 绑定，不依赖 widget metadata
    sendSuccessResponse(res, weather_data);
  } catch (err) {
    if (err.response && err.config && typeof err.config.url === 'string') {
      return sendBusinessOutcome(res, {
        ok: false,
        error_code: 'UPSTREAM_ERROR',
        error_message:
          'A downstream weather or geocoding HTTP request failed. You may retry later or try a different location.',
        error_details: {
          phase: String(err.config.url).indexOf('forecast') >= 0 ? 'forecast' : 'geocoding',
          status: err.response.status
        }
      });
    }
    next(err);
  }
});

module.exports = router;
