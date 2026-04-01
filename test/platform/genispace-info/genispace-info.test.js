/**
 * genispace-info：未注入 SDK 时应返回 401
 */

const test = require('node:test');
const assert = require('node:assert');
const { createRouterServer } = require('../../helpers/http-mini-app');
const router = require('../../../operators/platform/genispace-info/genispace-info.routes');

test('POST /user-profile without genispace → 401', async () => {
  const { post, close } = await createRouterServer(router);
  try {
    const { status, json } = await post('/user-profile', {});
    assert.strictEqual(status, 401);
    assert.strictEqual(json.success, false);
  } finally {
    await close();
  }
});

test('POST /agents without genispace → 401', async () => {
  const { post, close } = await createRouterServer(router);
  try {
    const { status, json } = await post('/agents', { page: 1, limit: 5 });
    assert.strictEqual(status, 401);
    assert.strictEqual(json.success, false);
  } finally {
    await close();
  }
});
