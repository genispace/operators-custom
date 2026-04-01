#!/usr/bin/env node
/**
 * Copy each operator's plugins/<slot>/ (manifest.json, main entry, manifest.widget scripts, locales)
 * to public/plugins/<category>/<operator>/plugins/<slot>/.
 * <slot> is usually methods[].identifier; use shared when multiple methods share assets.
 */

const fs = require('fs');
const path = require('path');
const { loadLocaleBundle, buildInjectedScriptBody } = require('./plugin-i18n-bundle');

const root = path.join(__dirname, '..');
const operatorsDir = path.join(root, 'operators');
const outRoot = path.join(root, 'public', 'plugins');

function readJson(p) {
  return JSON.parse(fs.readFileSync(p, 'utf8'));
}

function copyFile(src, dest) {
  fs.mkdirSync(path.dirname(dest), { recursive: true });
  fs.copyFileSync(src, dest);
}

function copyDirRecursive(src, dest) {
  if (!fs.existsSync(src)) return;
  fs.mkdirSync(dest, { recursive: true });
  for (const name of fs.readdirSync(src)) {
    const from = path.join(src, name);
    const to = path.join(dest, name);
    if (fs.statSync(from).isDirectory()) {
      copyDirRecursive(from, to);
    } else {
      fs.copyFileSync(from, to);
    }
  }
}

/**
 * @returns {Array<{ pluginDir: string, category: string, operator: string, slot: string }>}
 */
function findSlotPluginBundles(base) {
  const bundles = [];
  if (!fs.existsSync(base)) return bundles;
  for (const category of fs.readdirSync(base)) {
    const catPath = path.join(base, category);
    if (!fs.statSync(catPath).isDirectory()) continue;
    for (const operator of fs.readdirSync(catPath)) {
      const opPath = path.join(catPath, operator);
      if (!fs.statSync(opPath).isDirectory()) continue;

      const legacyPlugin = path.join(opPath, 'plugin');
      if (fs.existsSync(legacyPlugin) && fs.existsSync(path.join(legacyPlugin, 'manifest.json'))) {
        console.warn(
          `build-plugins: deprecated ${path.relative(root, legacyPlugin)}/ — use plugins/<methodOrShared>/ instead`
        );
      }

      const pluginsRoot = path.join(opPath, 'plugins');
      if (!fs.existsSync(pluginsRoot) || !fs.statSync(pluginsRoot).isDirectory()) continue;
      for (const slot of fs.readdirSync(pluginsRoot)) {
        const slotPath = path.join(pluginsRoot, slot);
        if (!fs.statSync(slotPath).isDirectory()) continue;
        if (fs.existsSync(path.join(slotPath, 'manifest.json'))) {
          bundles.push({ pluginDir: slotPath, category, operator, slot });
        }
      }
    }
  }
  return bundles;
}

function main() {
  const bundles = findSlotPluginBundles(operatorsDir);
  if (bundles.length === 0) {
    console.log('build-plugins: no operators/**/plugins/*/manifest.json found, skip');
    return;
  }

  for (const { pluginDir, category, operator, slot } of bundles) {
    const manifestPath = path.join(pluginDir, 'manifest.json');
    const manifest = readJson(manifestPath);
    const mainFile =
      typeof manifest.main === 'string' && manifest.main.trim() !== ''
        ? manifest.main.trim()
        : null;
    const destDir = path.join(outRoot, category, operator, 'plugins', slot);

    copyFile(manifestPath, path.join(destDir, 'manifest.json'));

    const localesSrc = path.join(pluginDir, 'locales');
    let i18nPrelude = '';
    if (fs.existsSync(localesSrc) && fs.existsSync(path.join(localesSrc, 'en.json'))) {
      try {
        const bundle = loadLocaleBundle(localesSrc);
        i18nPrelude = buildInjectedScriptBody(bundle);
      } catch (e) {
        console.error(`build-plugins: locale bundle failed for ${pluginDir}:`, e.message);
        process.exitCode = 1;
        throw e;
      }
    }

    function writeScriptWithI18n(srcPath, destPath) {
      const body = fs.readFileSync(srcPath, 'utf8');
      fs.mkdirSync(path.dirname(destPath), { recursive: true });
      fs.writeFileSync(destPath, i18nPrelude + body, 'utf8');
    }

    if (mainFile) {
      const mainSrc = path.join(pluginDir, mainFile);
      if (fs.existsSync(mainSrc)) {
        const mainDest = path.join(destDir, mainFile);
        if (i18nPrelude) {
          writeScriptWithI18n(mainSrc, mainDest);
        } else {
          copyFile(mainSrc, mainDest);
        }
      } else {
        console.warn(`build-plugins: missing ${mainFile} in ${pluginDir}, skip main`);
      }
    }

    const widgetFile =
      typeof manifest.widget === 'string' && manifest.widget.trim()
        ? manifest.widget.trim()
        : manifest.widget === true
          ? 'widget.js'
          : null;
    if (widgetFile) {
      const widgetSrc = path.join(pluginDir, widgetFile);
      if (fs.existsSync(widgetSrc)) {
        const widgetDest = path.join(destDir, widgetFile);
        if (i18nPrelude) {
          writeScriptWithI18n(widgetSrc, widgetDest);
        } else {
          copyFile(widgetSrc, widgetDest);
        }
      } else {
        console.warn(
          `build-plugins: manifest.widget "${widgetFile}" not found under ${pluginDir}`
        );
      }
    }

    if (fs.existsSync(localesSrc)) {
      copyDirRecursive(localesSrc, path.join(destDir, 'locales'));
    }
    console.log(
      `build-plugins: ${category}/${operator}/plugins/${slot} -> public/plugins/${category}/${operator}/plugins/${slot}/`
    );
  }
}

main();
