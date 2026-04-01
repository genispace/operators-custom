import type { MethodRow, OperatorRow } from './types';

function normalizeLang(lang: string): 'zh' | 'en' {
  const base = (lang || 'en').split('-')[0].toLowerCase();
  return base === 'zh' ? 'zh' : 'en';
}

function mergeMethodLocales(methods: MethodRow[], localeMethods?: Array<{ identifier: string; name?: string; description?: string }>) {
  if (!localeMethods?.length) return methods;
  const byId = new Map(localeMethods.map((m) => [m.identifier, m]));
  return methods.map((m) => {
    const loc = byId.get(m.identifier);
    if (!loc) return m;
    return {
      ...m,
      name: loc.name || m.name,
      description: loc.description != null ? loc.description : m.description
    };
  });
}

export function applyLocalesToOperatorRow(row: OperatorRow, lang: string): OperatorRow {
  const lng = normalizeLang(lang);
  const zh = row.metadata?.locales?.zh;
  if (lng !== 'zh' || !zh) {
    return { ...row, methods: [...row.methods] };
  }
  return {
    ...row,
    name: zh.name || row.name,
    description: zh.description != null ? zh.description : row.description,
    methods: mergeMethodLocales(row.methods, zh.methods)
  };
}
