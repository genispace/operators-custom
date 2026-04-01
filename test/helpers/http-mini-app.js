/**
 * 将算子 express.Router 挂到最小 app 上，用 fetch 做集成探测（无需 supertest）
 */

const express = require('express');
const http = require('http');

/**
 * @param {import('express').Router} router
 * @param {{ jsonLimit?: string }} [opts]
 */
async function createRouterServer(router, opts = {}) {
  const app = express();
  app.use(express.json({ limit: opts.jsonLimit || '4mb' }));
  app.use(router);
  const server = http.createServer(app);
  await new Promise((resolve, reject) => {
    server.listen(0, '127.0.0.1', () => resolve());
    server.on('error', reject);
  });
  const addr = server.address();
  const baseUrl = `http://${addr.address}:${addr.port}`;

  async function post(routePath, body) {
    const res = await fetch(baseUrl + routePath, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body ?? {}),
    });
    const text = await res.text();
    let json;
    try {
      json = text ? JSON.parse(text) : {};
    } catch {
      json = { _parseError: true, _raw: text };
    }
    return { status: res.status, json };
  }

  async function close() {
    await new Promise((resolve, reject) => {
      server.close((err) => (err ? reject(err) : resolve()));
    });
  }

  return { baseUrl, post, close };
}

module.exports = { createRouterServer };
