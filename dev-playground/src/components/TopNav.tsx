import { useTranslation } from 'react-i18next';
import type { OperatorRow } from '../types';
import type { PlaygroundTheme } from '../hooks/usePlaygroundTheme';
import { ThemeToggle } from './ThemeToggle';
import { LanguageToggle } from './LanguageToggle';

type TopNavProps = {
  operators: OperatorRow[];
  opKey: string;
  setOpKey: (v: string) => void;
  methodId: string;
  setMethodId: (v: string) => void;
  selectedOp: OperatorRow | null;
  loadErr: string | null;
  theme: PlaygroundTheme;
  onToggleTheme: () => void;
};

function NavActions({ theme, onToggleTheme }: { theme: PlaygroundTheme; onToggleTheme: () => void }) {
  return (
    <div className="flex items-center gap-0.5 sm:gap-1">
      <div className="nav-divider hidden sm:block" aria-hidden />
      <ThemeToggle theme={theme} onToggle={onToggleTheme} />
      <LanguageToggle />
    </div>
  );
}

export function TopNav({
  operators,
  opKey,
  setOpKey,
  methodId,
  setMethodId,
  selectedOp,
  loadErr,
  theme,
  onToggleTheme
}: TopNavProps) {
  const { t } = useTranslation('playground');

  return (
    <header className="g-nav shrink-0">
      <div className="mx-auto flex max-w-[1920px] flex-col gap-3 px-4 py-3 lg:flex-row lg:items-end lg:justify-between lg:gap-4">
        {/* 左：品牌（移动端与同排右侧为主题+语言） */}
        <div className="flex w-full items-center justify-between gap-3 lg:w-auto lg:shrink-0 lg:justify-start">
          <div className="flex min-w-0 items-center gap-2">
            <img src="/logo.svg" alt="GeniSpace Logo" className="h-5 w-auto shrink-0" />
            <div className="min-w-0">
              <div className="font-display text-base font-semibold tracking-tight text-g-text">
                {t('nav.brand', 'GeniSpace')}
              </div>
              <div className="truncate text-xs text-g-muted">{t('nav.subtitle', 'operators dev playground')}</div>
            </div>
          </div>
          <div className="shrink-0 lg:hidden">
            <NavActions theme={theme} onToggleTheme={onToggleTheme} />
          </div>
        </div>

        {/* 中：算子 + 方法（桌面端在剩余空间内居中） */}
        <div className="flex min-w-0 flex-1 flex-col gap-3 sm:flex-row sm:items-center sm:justify-center lg:px-4">
          <div className="min-w-0 sm:max-w-[min(100%,500px)] sm:flex-1">
            <select
              className="g-select w-full"
              value={opKey}
              onChange={(e) => {
                setOpKey(e.target.value);
                setMethodId('');
              }}
              aria-label={t('nav.selectOperator', 'Select Operator ...')}
            >
              <option value="">{t('nav.selectOperator', 'Select Operator ...')}</option>
              {operators.map((o) => (
                <option key={o.id} value={`${o.category}/${o.identifier}`}>
                  {o.category}/{o.identifier}
                  {o.name ? ` — ${o.name}` : ''}
                </option>
              ))}
            </select>
          </div>
          <div className="min-w-0 sm:max-w-[min(100%,500px)] sm:flex-1">
            <select
              className="g-select w-full"
              value={methodId}
              disabled={!selectedOp}
              onChange={(e) => setMethodId(e.target.value)}
              aria-label={t('nav.selectMethod', 'Select Method ...')}
            >
              <option value="">{t('nav.selectMethod', 'Select Method ...')}</option>
              {selectedOp?.methods.map((m) => (
                <option key={m.identifier} value={m.identifier}>
                  {m.identifier} — {m.name}
                </option>
              ))}
            </select>
          </div>
        </div>

        {/* 右：主题 + 语言（仅桌面端） */}
        <div className="hidden shrink-0 lg:block">
          <NavActions theme={theme} onToggleTheme={onToggleTheme} />
        </div>
      </div>
      {loadErr ? (
        <div className="border-t border-g-border px-4 py-2 text-sm text-g-red">
          {loadErr}
        </div>
      ) : null}
    </header>
  );
}
