/**
 * weather-forecast：依赖 Open-Meteo 公网 API
 */

const test = require('node:test');
const assert = require('node:assert');
const { createRouterServer } = require('../../helpers/http-mini-app');
const router = require('../../../operators/weather/weather-forecast/weather-forecast.routes');

test('POST /forecast empty location → business ok:false in data', async () => {
  const { post, close } = await createRouterServer(router);
  try {
    const { status, json } = await post('/forecast', { location: '' });
    assert.strictEqual(status, 200);
    assert.strictEqual(json.success, true);
    assert.strictEqual(json.data.ok, false);
    assert.strictEqual(json.data.error_code, 'INVALID_INPUT');
  } finally {
    await close();
  }
});

test('POST /forecast known city → ok true (Open-Meteo, opt-in)', async (t) => {
  if (process.env.WEATHER_TEST_SKIP === '1') {
    t.skip('WEATHER_TEST_SKIP=1');
    return;
  }
  if (process.env.WEATHER_TEST_LIVE !== '1') {
    t.skip('设置 WEATHER_TEST_LIVE=1 以运行 Open-Meteo 联网集成测试');
    return;
  }
  const { post, close } = await createRouterServer(router);
  try {
    const { status, json } = await post('/forecast', { location: 'Paris', days: 1 });
    assert.strictEqual(status, 200);
    assert.strictEqual(json.success, true);
    if (json.data.ok === false) {
      assert.ok(json.data.error_code);
      return;
    }
    assert.strictEqual(json.data.ok, true);
    assert.ok(json.data.location && json.data.location.latitude != null);
    assert.ok(Array.isArray(json.data.daily));
  } finally {
    await close();
  }
});
