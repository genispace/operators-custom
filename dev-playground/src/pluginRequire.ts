/**
 * 与 GeniSpace Chat 远程插件宿主一致的 require 白名单（见 frontend/apps/chat/src/plugins/index.ts）。
 */
import * as React from 'react';
import * as ReactDOM from 'react-dom';
import * as LucideReact from 'lucide-react';

export function createChatLikeRequire(ReactMod: typeof React) {
  const builtins: Record<string, unknown> = {
    react: ReactMod,
    React: ReactMod,
    'react-dom': ReactDOM,
    ReactDOM,
    'lucide-react': LucideReact,
    LucideReact
  };
  return (id: string): unknown => {
    if (builtins[id] !== undefined) return builtins[id];
    const lower = id.toLowerCase();
    for (const key of Object.keys(builtins)) {
      if (key.toLowerCase() === lower) return builtins[key];
    }
    return {};
  };
}

/** 执行远程 CommonJS 插件脚本（fetch 文本 + Function），返回 module.exports */
export function runRemotePluginScript(script: string, ReactMod: typeof React): Record<string, unknown> {
  const mod: { exports: Record<string, unknown> } = { exports: {} };
  const require = createChatLikeRequire(ReactMod);
  const run = new Function('exports', 'module', 'require', script) as (
    e: Record<string, unknown>,
    m: { exports: Record<string, unknown> },
    r: typeof require
  ) => void;
  run(mod.exports, mod, require);
  return mod.exports;
}
