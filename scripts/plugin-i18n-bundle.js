/**
 * Build-time: merge plugin/locales/*.json and produce injectable prelude for remote Chat plugins.
 */

const fs = require('fs');
const path = require('path');

/**
 * @param {string} localesDir absolute path to plugin/locales
 * @returns {Record<string, Record<string, string>>}
 */
function loadLocaleBundle(localesDir) {
  if (!fs.existsSync(localesDir)) {
    throw new Error(`loadLocaleBundle: missing ${localesDir}`);
  }
  const bundle = {};
  for (const name of fs.readdirSync(localesDir)) {
    if (!name.endsWith('.json')) continue;
    const key = path.basename(name, '.json').toLowerCase();
    const full = path.join(localesDir, name);
    if (!fs.statSync(full).isFile()) continue;
    const raw = fs.readFileSync(full, 'utf8');
    bundle[key] = JSON.parse(raw);
  }
  if (!Object.prototype.hasOwnProperty.call(bundle, 'en')) {
    throw new Error(`loadLocaleBundle: en.json required in ${localesDir}`);
  }
  return bundle;
}

/** Runtime prepended before plugin script; uses props.config.locale then navigator. */
const RUNTIME_SOURCE = `'use strict';
function __gsPluginLocaleIndex(props, msgs) {
  var keys = msgs && typeof msgs === 'object' ? Object.keys(msgs) : [];
  if (keys.length === 0) return 'en';
  function pick(code) {
    if (code == null || code === '') return null;
    var n = String(code).toLowerCase().replace(/_/g, '-');
    if (msgs[n]) return n;
    var base = n.split('-')[0];
    if (msgs[base]) return base;
    return null;
  }
  var fromConfig = props && props.config && props.config.locale;
  var x = pick(fromConfig);
  if (x) return x;
  try {
    if (typeof navigator !== 'undefined' && navigator.language) {
      x = pick(navigator.language);
      if (x) return x;
    }
  } catch (_e) {}
  return msgs.en ? 'en' : keys[0];
}
function __gsPluginT(msgs, props, key) {
  if (!msgs || typeof msgs !== 'object') return key;
  var ix = __gsPluginLocaleIndex(props, msgs);
  var row = msgs[ix];
  if (row && row[key] != null && row[key] !== '') return row[key];
  var en = msgs.en;
  if (en && en[key] != null && en[key] !== '') return en[key];
  return key;
}
`;

/**
 * @param {Record<string, Record<string, string>>} bundle
 * @returns {string}
 */
function buildInjectedScriptBody(bundle) {
  return RUNTIME_SOURCE + 'var __PLUGIN_I18N = ' + JSON.stringify(bundle) + ';\n';
}

module.exports = {
  loadLocaleBundle,
  buildInjectedScriptBody,
  RUNTIME_SOURCE,
};
