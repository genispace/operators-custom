#!/usr/bin/env node
/**
 * 递归收集 test 目录下所有 .test.js 并交给 node --test（跨平台）
 */
const { spawnSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const root = path.join(__dirname, '..');

function collect(dir) {
  const out = [];
  if (!fs.existsSync(dir)) return out;
  for (const name of fs.readdirSync(dir)) {
    if (name === 'node_modules') continue;
    const p = path.join(dir, name);
    const st = fs.statSync(p);
    if (st.isDirectory()) {
      out.push(...collect(p));
    } else if (name.endsWith('.test.js')) {
      out.push(p);
    }
  }
  return out;
}

const files = collect(path.join(root, 'test')).sort();
if (files.length === 0) {
  console.error('No test files under test/');
  process.exit(1);
}

const r = spawnSync(process.execPath, ['--test', ...files], {
  stdio: 'inherit',
  cwd: root,
  env: process.env,
});
process.exit(r.status === null ? 1 : r.status);
