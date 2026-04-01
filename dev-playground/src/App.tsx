import React, { useCallback, useEffect, useMemo, useState } from 'react';
import Form from '@rjsf/core';
import validator from '@rjsf/validator-ajv8';
import type { UiSchema } from '@rjsf/utils';
import { useTranslation } from 'react-i18next';
import { TopNav } from './components/TopNav';
import { usePlaygroundTheme, type PlaygroundTheme } from './hooks/usePlaygroundTheme';
import type { OperatorRow } from './types';
import i18n from './i18n/config';
import { applyLocalesToOperatorRow } from './operatorDisplayLocale';
import { runRemotePluginScript } from './pluginRequire';

/** 调试台在 Vite(18080) 下通过代理访问算子服务(8080)；同源 fetch 应用相对路径，避免 localhost 与 127.0.0.1 跨域。 */
function normalizeDevPluginBase(pluginUrl: string): string {
  if (!pluginUrl) return pluginUrl;
  try {
    const u = new URL(pluginUrl, typeof window !== 'undefined' ? window.location.href : 'http://localhost');
    const loopback = u.hostname === 'localhost' || u.hostname === '127.0.0.1';
    const port = u.port || (u.protocol === 'https:' ? '443' : '80');
    if (loopback && port === '8080' && u.pathname.startsWith('/static/')) {
      return `${u.pathname}${u.search}`;
    }
  } catch {
    /* keep */
  }
  return pluginUrl;
}

const PLUGIN_ERR_NO_EXPORT = 'NO_DEFAULT_EXPORT';

function resolveWidgetFile(manifest: { widget?: string | boolean }): string | null {
  const w = manifest.widget;
  if (w === true) return 'widget.js';
  if (typeof w === 'string' && w.trim()) return w.trim();
  return null;
}

type RemotePluginArtifacts = {
  MainPanel: React.ComponentType<Record<string, unknown>> | null;
  WidgetArtifact: React.ComponentType<Record<string, unknown>> | null;
  mainError: string | null;
  widgetError: string | null;
  loadingMain: boolean;
  loadingWidget: boolean;
};

function useRemotePluginArtifacts({
  pluginBase,
  enabled
}: {
  pluginBase: string;
  enabled: boolean;
}) {
  const [state, setState] = useState<RemotePluginArtifacts>({
    MainPanel: null,
    WidgetArtifact: null,
    mainError: null,
    widgetError: null,
    loadingMain: false,
    loadingWidget: false
  });

  useEffect(() => {
    if (!enabled) {
      setState({
        MainPanel: null,
        WidgetArtifact: null,
        mainError: null,
        widgetError: null,
        loadingMain: false,
        loadingWidget: false
      });
      return;
    }
    let cancelled = false;
    setState({
      MainPanel: null,
      WidgetArtifact: null,
      mainError: null,
      widgetError: null,
      loadingMain: true,
      loadingWidget: true
    });
    (async () => {
      try {
        const base = pluginBase.endsWith('/') ? pluginBase : `${pluginBase}/`;
        const manRes = await fetch(`${base}manifest.json`);
        if (!manRes.ok) throw new Error(`manifest ${manRes.status}`);
        const manifest = (await manRes.json()) as { main?: string; widget?: string | boolean };
        const main = manifest.main || 'index.js';
        const mainRes = await fetch(`${base}${main}`);
        if (!mainRes.ok) throw new Error(`script ${mainRes.status}`);
        const mainScript = await mainRes.text();
        const mainExports = runRemotePluginScript(mainScript, React);
        const mainDef = mainExports.default ?? mainExports;
        const MainC =
          typeof mainDef === 'function' ? (mainDef as React.ComponentType<Record<string, unknown>>) : null;
        if (!cancelled) {
          setState((prev) => ({
            ...prev,
            MainPanel: MainC,
            mainError: MainC ? null : PLUGIN_ERR_NO_EXPORT,
            loadingMain: false
          }));
        }

        const widgetFile = resolveWidgetFile(manifest);
        if (!widgetFile) {
          if (!cancelled) {
            setState((prev) => ({
              ...prev,
              WidgetArtifact: null,
              widgetError: null,
              loadingWidget: false
            }));
          }
          return;
        }
        try {
          const wRes = await fetch(`${base}${widgetFile}`);
          if (!wRes.ok) {
            if (!cancelled) {
              setState((prev) => ({
                ...prev,
                widgetError: `widget ${wRes.status}`,
                loadingWidget: false
              }));
            }
            return;
          }
          const wScript = await wRes.text();
          const wExports = runRemotePluginScript(wScript, React);
          const wDef = wExports.default ?? wExports;
          const WidgetC =
            typeof wDef === 'function' ? (wDef as React.ComponentType<Record<string, unknown>>) : null;
          if (!cancelled) {
            setState((prev) => ({
              ...prev,
              WidgetArtifact: WidgetC,
              widgetError: WidgetC ? null : PLUGIN_ERR_NO_EXPORT,
              loadingWidget: false
            }));
          }
        } catch (we) {
          if (!cancelled) {
            setState((prev) => ({
              ...prev,
              widgetError: we instanceof Error ? we.message : String(we),
              loadingWidget: false
            }));
          }
        }
      } catch (e) {
        if (!cancelled) {
          setState((prev) => ({
            ...prev,
            mainError: e instanceof Error ? e.message : String(e),
            loadingMain: false,
            loadingWidget: false
          }));
        }
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [enabled, pluginBase]);

  return state;
}

function RemotePluginPreview({
  title,
  kind,
  contentText,
  pluginMetadata,
  theme,
  compact,
  artifacts
}: {
  title: string;
  kind: 'main' | 'widget';
  contentText: string;
  pluginMetadata: Record<string, unknown>;
  theme: PlaygroundTheme;
  compact: boolean;
  artifacts: RemotePluginArtifacts;
}) {
  const { t, i18n } = useTranslation('playground');
  const { MainPanel, WidgetArtifact, mainError, widgetError, loadingMain, loadingWidget } = artifacts;

  const loadError = kind === 'main' ? mainError : widgetError;
  const loading = kind === 'main' ? loadingMain : loadingWidget;
  const hasRenderer = kind === 'main' ? Boolean(MainPanel) : Boolean(WidgetArtifact);
  const MainComp = MainPanel as React.ComponentType<Record<string, unknown>>;
  const WidgetComp = WidgetArtifact as React.ComponentType<Record<string, unknown>>;

  if (loadError) {
    const msg =
      loadError === PLUGIN_ERR_NO_EXPORT
        ? t('plugin.noDefaultExport', 'Plugin has no renderable default export')
        : loadError;
    return (
      <div>
        <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-g-muted">{title}</h3>
        <pre className="whitespace-pre-wrap text-sm text-g-red">{msg}</pre>
      </div>
    );
  }
  if (loading) {
    return (
      <div>
        <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-g-muted">{title}</h3>
        <p className="text-sm text-g-muted">{t('plugin.loading', 'Loading remote plugin…')}</p>
      </div>
    );
  }
  if (!hasRenderer) {
    return (
      <div>
        <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-g-muted">{title}</h3>
        <p className="text-xs text-g-muted">{t('panel.noChatPluginHint', 'No chatPluginConfig for this method.')}</p>
      </div>
    );
  }

  const mockToolEvent = {
    metadata: {
      result: {
        success: true,
        result: {
          content: [{ text: contentText, type: 'text' }]
        }
      }
    }
  };

  return (
    <div className="playground-plugin-host">
      <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-g-muted">{title}</h3>
      {kind === 'main' ? (
        <MainComp
          key={`main-${theme}-${i18n.language}`}
          data={contentText}
          metadata={pluginMetadata}
          success
          compact={compact}
          config={{ theme, locale: i18n.language }}
        />
      ) : (
        <WidgetComp
          key={`widget-${theme}-${i18n.language}`}
          event={mockToolEvent}
          compact={compact}
          config={{ theme, locale: i18n.language }}
        />
      )}
    </div>
  );
}

const uiSchema: UiSchema = {
  'ui:submitButtonOptions': {
    norender: true
  }
};

const GENISPACE_KEY_STORAGE = 'operators-playground-genispace-key';

export default function App() {
  const { t, i18n: i18nInstance } = useTranslation('playground');
  const { theme, toggleTheme } = usePlaygroundTheme();
  const [operators, setOperators] = useState<OperatorRow[]>([]);
  const [loadErr, setLoadErr] = useState<string | null>(null);
  const [opKey, setOpKey] = useState<string>('');
  const [methodId, setMethodId] = useState<string>('');
  const [formData, setFormData] = useState<Record<string, unknown>>({});
  const [execLoading, setExecLoading] = useState(false);
  const [rawResult, setRawResult] = useState<unknown>(null);
  const [execErr, setExecErr] = useState<string | null>(null);
  const [geniSpaceApiKey, setGeniSpaceApiKey] = useState('');
  const [layoutMode, setLayoutMode] = useState<'compact' | 'balanced' | 'detailed'>('balanced');

  useEffect(() => {
    try {
      const stored = localStorage.getItem(GENISPACE_KEY_STORAGE);
      if (stored != null) setGeniSpaceApiKey(stored);
    } catch {
      /* ignore */
    }
  }, []);

  useEffect(() => {
    fetch('/api/dev/playground-registry')
      .then((r) => r.json())
      .then((body) => {
        if (!body.success) throw new Error(body.error || 'registry failed');
        setOperators(body.data.operators || []);
      })
      .catch((e) => {
        const base = i18n.t('errors.registryFailed', 'Failed to load operator registry');
        const detail = e instanceof Error && e.message ? `: ${e.message}` : '';
        setLoadErr(`${base}${detail}`);
      });
  }, []);

  const displayOperators = useMemo(
    () => operators.map((o) => applyLocalesToOperatorRow(o, i18nInstance.language)),
    [operators, i18nInstance.language]
  );

  const selectedOp = useMemo(
    () => displayOperators.find((o) => `${o.category}/${o.identifier}` === opKey) || null,
    [displayOperators, opKey]
  );

  const selectedMethod = useMemo(
    () => selectedOp?.methods.find((m) => m.identifier === methodId) || null,
    [selectedOp, methodId]
  );

  useEffect(() => {
    if (!selectedMethod) return;
    setFormData({});
  }, [selectedMethod?.identifier, selectedOp?.id]);

  /** 远程插件入参：与线上面向插件的负载一致，序列化为 JSON 字符串（插件内 parse） */
  const { textForPlugin, pluginMetadata } = useMemo(() => {
    const empty = { textForPlugin: '', pluginMetadata: {} as Record<string, unknown> };
    if (!rawResult || typeof rawResult !== 'object') return empty;
    const data = (rawResult as { data?: unknown }).data;
    if (data != null && typeof data === 'object' && !Array.isArray(data)) {
      const o = data as { current?: unknown; result?: { content?: unknown[] }; content?: unknown[] };
      if (o.current != null && typeof o.current === 'object') {
        return { textForPlugin: JSON.stringify(data), pluginMetadata: {} };
      }
      const c0 = o.result?.content?.[0] ?? o.content?.[0];
      if (c0 && typeof c0 === 'object' && 'text' in c0) {
        const slice = c0 as { text?: string; metadata?: Record<string, unknown> };
        return {
          textForPlugin: typeof slice.text === 'string' ? slice.text : '',
          pluginMetadata: slice.metadata ?? {}
        };
      }
      return { textForPlugin: JSON.stringify(data), pluginMetadata: {} };
    }
    if (Array.isArray(data) && data[0] != null && typeof data[0] === 'object') {
      const slice = data[0] as { text?: string; metadata?: Record<string, unknown> };
      if (typeof slice.text === 'string') {
        return { textForPlugin: slice.text, pluginMetadata: slice.metadata ?? {} };
      }
    }
    return empty;
  }, [rawResult]);

  const persistGeniSpaceKey = useCallback((value: string) => {
    try {
      localStorage.setItem(GENISPACE_KEY_STORAGE, value);
    } catch {
      /* ignore */
    }
  }, []);

  const runExecute = useCallback(async () => {
    if (!selectedMethod?.endpoint || !selectedMethod.httpMethod) {
      setExecErr(t('execute.missingEndpoint', 'Missing endpoint or HTTP method'));
      return;
    }
    if (selectedMethod.needsGeniSpaceKey && !geniSpaceApiKey.trim()) {
      setExecErr(t('execute.genispaceKeyRequired', 'This method requires a GeniSpace API key. Enter it below.'));
      return;
    }
    setExecLoading(true);
    setExecErr(null);
    setRawResult(null);
    try {
      const headers: Record<string, string> = { 'Content-Type': 'application/json' };
      if (selectedMethod.needsGeniSpaceKey && geniSpaceApiKey.trim()) {
        headers.GeniSpace = geniSpaceApiKey.trim();
      }
      const res = await fetch(selectedMethod.endpoint, {
        method: selectedMethod.httpMethod,
        headers,
        body: JSON.stringify(formData)
      });
      const json = await res.json();
      setRawResult(json);
      if (!res.ok || json.success === false) {
        setExecErr(json.error || json.message || `HTTP ${res.status}`);
      }
    } catch (e) {
      setExecErr(e instanceof Error ? e.message : String(e));
    } finally {
      setExecLoading(false);
    }
  }, [formData, geniSpaceApiKey, selectedMethod, t]);

  const pluginBase = selectedMethod?.chatPluginConfig?.pluginUrl
    ? normalizeDevPluginBase(selectedMethod.chatPluginConfig.pluginUrl)
    : '';
  const useRemote =
    selectedMethod?.chatPluginConfig?.enabled === true && Boolean(pluginBase) && Boolean(textForPlugin);
  const remoteArtifacts = useRemotePluginArtifacts({ pluginBase, enabled: useRemote });

  const rightSpanByLayout: Record<'compact' | 'balanced' | 'detailed', string> = {
    compact: 'lg:col-span-4',
    balanced: 'lg:col-span-6',
    detailed: 'lg:col-span-8'
  };
  const leftSpanByLayout: Record<'compact' | 'balanced' | 'detailed', string> = {
    compact: 'lg:col-span-8',
    balanced: 'lg:col-span-6',
    detailed: 'lg:col-span-4'
  };
  const mainCompact = layoutMode === 'compact';
  const widgetCompact = true;

  return (
    <div className="flex min-h-screen flex-col bg-g-bg text-g-text">
      <TopNav
        operators={displayOperators}
        opKey={opKey}
        setOpKey={setOpKey}
        methodId={methodId}
        setMethodId={setMethodId}
        selectedOp={selectedOp}
        loadErr={loadErr}
        theme={theme}
        onToggleTheme={toggleTheme}
      />

      <main className="mx-auto grid min-h-0 w-full max-w-[1920px] flex-1 grid-cols-1 gap-4 p-4 lg:grid-cols-12">
        <section className={`flex min-h-0 flex-col gap-4 ${leftSpanByLayout[layoutMode]}`}>
          <div className="g-card flex min-h-[360px] flex-col overflow-hidden">
            <div className="border-b border-g-border px-5 py-4">
              <h2 className="font-display text-sm font-semibold tracking-tight text-g-text">
                {t('panel.requestTitle', 'Request body')}
              </h2>
              <p className="mt-1 text-xs text-g-muted">{t('panel.requestDesc', 'Form from inputSchema; calls operator API')}</p>
              {selectedOp?.description ? (
                <p className="mt-2 text-xs text-g-secondary">{selectedOp.description}</p>
              ) : null}
            </div>
            <div className="min-h-0 flex-1 overflow-y-auto p-5">
              {selectedMethod ? (
                <>
                  {selectedMethod.needsGeniSpaceKey ? (
                    <div className="mb-4 rounded-lg border border-g-border bg-g-bg-muted/30 p-3">
                      <label className="block text-xs font-medium text-g-text" htmlFor="playground-genispace-key">
                        {t('genispace.keyLabel', 'GeniSpace API key')}
                      </label>
                      <p className="mt-1 text-xs text-g-muted">
                        {t(
                          'genispace.keyHint',
                          'Stored only in this browser (localStorage). Do not commit keys to the repo.'
                        )}
                      </p>
                      <input
                        id="playground-genispace-key"
                        type="password"
                        autoComplete="off"
                        className="mt-2 w-full rounded-md border border-g-border bg-g-bg px-3 py-2 text-sm text-g-text"
                        value={geniSpaceApiKey}
                        onChange={(e) => setGeniSpaceApiKey(e.target.value)}
                        onBlur={() => persistGeniSpaceKey(geniSpaceApiKey)}
                        placeholder={t('genispace.keyPlaceholder', 'Paste system API key')}
                      />
                    </div>
                  ) : null}
                  <div className="playground-rjsf">
                    <Form
                      schema={selectedMethod.inputSchema}
                      formData={formData}
                      onChange={(e) => setFormData(e.formData as Record<string, unknown>)}
                      validator={validator}
                      uiSchema={uiSchema}
                      liveValidate={false}
                    />
                  </div>
                  <button
                    type="button"
                    className="g-btn-primary mt-4 w-full"
                    disabled={execLoading}
                    onClick={() => void runExecute()}
                  >
                    {execLoading ? t('form.executing', 'Running…') : t('form.execute', 'Run')}
                  </button>
                  {execErr ? <p className="mt-3 text-sm text-g-red">{execErr}</p> : null}
                </>
              ) : (
                <p className="text-sm text-g-muted">{t('form.selectOperatorMethod', 'Select an operator and method above')}</p>
              )}
            </div>
          </div>

          <div className="g-card flex min-h-[260px] flex-col overflow-hidden">
            <div className="border-b border-g-border px-5 py-4">
              <h2 className="font-display text-sm font-semibold tracking-tight text-g-text">
                {t('plugin.widgetPreview', 'Widget (message artifact)')}
              </h2>
              <p className="mt-1 text-xs text-g-muted">
                {t('panel.outputDesc', 'JSON or remote chat plugin')}
              </p>
            </div>
            <div className="min-h-0 flex-1 overflow-y-auto p-5">
              {!rawResult && !execErr && (
                <p className="text-sm text-g-muted">{t('panel.outputEmpty', 'Run to see results.')}</p>
              )}
              {rawResult != null &&
                (useRemote ? (
                  <RemotePluginPreview
                    title={t('plugin.widgetPreview', 'Widget (message artifact)')}
                    kind="widget"
                    contentText={textForPlugin}
                    pluginMetadata={pluginMetadata}
                    theme={theme}
                    compact={widgetCompact}
                    artifacts={remoteArtifacts}
                  />
                ) : (
                  <pre className="g-pre">{JSON.stringify(rawResult, null, 2)}</pre>
                ))}
            </div>
          </div>
        </section>

        <section className={`g-card flex min-h-0 flex-col overflow-hidden ${rightSpanByLayout[layoutMode]}`}>
          <div className="border-b border-g-border px-5 py-4">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <h2 className="font-display text-sm font-semibold tracking-tight text-g-text">
                {t('plugin.mainPreview', 'Main (activity panel)')}
              </h2>
              <div className="inline-flex rounded-md border border-g-border p-1">
                {(['compact', 'balanced', 'detailed'] as const).map((mode) => (
                  <button
                    key={mode}
                    type="button"
                    onClick={() => setLayoutMode(mode)}
                    className={`rounded px-2 py-1 text-xs ${
                      layoutMode === mode ? 'bg-g-bg-muted text-g-text' : 'text-g-muted'
                    }`}
                  >
                    {mode}
                  </button>
                ))}
              </div>
            </div>
            <p className="mt-1 text-xs text-g-muted">{t('panel.outputDesc', 'JSON or remote chat plugin')}</p>
          </div>
          <div className="min-h-0 flex-1 overflow-y-auto p-5">
            {!rawResult && !execErr && (
              <p className="text-sm text-g-muted">{t('panel.outputEmpty', 'Run to see results.')}</p>
            )}
            {rawResult != null &&
              (useRemote ? (
                <RemotePluginPreview
                  title={t('plugin.mainPreview', 'Main (activity panel)')}
                  kind="main"
                  contentText={textForPlugin}
                  pluginMetadata={pluginMetadata}
                  theme={theme}
                  compact={mainCompact}
                  artifacts={remoteArtifacts}
                />
              ) : (
                <pre className="g-pre">{JSON.stringify(rawResult, null, 2)}</pre>
              ))}
          </div>
        </section>
      </main>
    </div>
  );
}
